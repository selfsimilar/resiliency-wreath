// Copyright 2026 The Resiliency Ring Authors
// SPDX-License-Identifier: Apache-2.0

// Package store is the on-disk bundle cache with anti-rollback. Layout:
//
//	<dir>/members/<id>/v<version>/manifest.json   signed envelope
//	<dir>/members/<id>/v<version>/blobs/<sha256>  file bodies
//	<dir>/members/<id>/current                    pointer file: "v<version>"
//	<dir>/members/<id>/seen                       highest version ever observed
//
// Updates are atomic: a new version directory is fully written, then the
// pointer file is swapped via rename. The store never verifies
// signatures — callers (fetch) verify BEFORE Put; on reopen the contents
// are trusted as previously-verified local state (structural checks
// only). Anti-rollback is enforced here: Put rejects any version lower
// than the currently stored one with ErrRollback.
//
// "Seen" tracks the highest version observed anywhere (e.g. a peer
// announced v5 before we could fetch it) and survives restarts; it feeds
// the freshness half of the health check. A wiped data directory
// legitimately resets both (cold-cache restart, KICKOFF scenario 6).
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/selfsimilar/resiliency-ring/internal/wire"
)

// ErrRollback is returned by Put when the offered version is lower than
// the stored one. Deliberately distinct from signature errors: rollback
// depends on local state, not on the document being forged.
var ErrRollback = errors.New("store: version rollback rejected")

type memberState struct {
	version       uint64
	manifestBytes []byte
	manifest      *wire.Manifest
	seen          uint64
}

// Store is safe for concurrent use.
type Store struct {
	dir string
	log *slog.Logger

	mu      sync.RWMutex
	members map[string]*memberState
}

// Open scans dir (created if missing) and loads every member's current
// bundle. Corrupt member state is logged and skipped — the fetch loop
// will re-converge it; disk corruption must never brick the agent.
func Open(dir string, log *slog.Logger) (*Store, error) {
	if log == nil {
		log = slog.Default()
	}
	s := &Store{dir: dir, log: log, members: make(map[string]*memberState)}
	membersDir := filepath.Join(dir, "members")
	if err := os.MkdirAll(membersDir, 0o755); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(membersDir)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if !e.IsDir() || !wire.ValidMemberID(e.Name()) {
			continue
		}
		id := e.Name()
		st, err := s.loadMember(id)
		if err != nil {
			log.Warn("store: skipping corrupt member state", "member", id, "err", err)
			continue
		}
		if st != nil {
			s.members[id] = st
		}
	}
	return s, nil
}

func (s *Store) memberDir(id string) string { return filepath.Join(s.dir, "members", id) }

func (s *Store) loadMember(id string) (*memberState, error) {
	mdir := s.memberDir(id)
	st := &memberState{}
	if seenRaw, err := os.ReadFile(filepath.Join(mdir, "seen")); err == nil {
		if n, err := strconv.ParseUint(strings.TrimSpace(string(seenRaw)), 10, 64); err == nil {
			st.seen = n
		}
	}
	cur, err := os.ReadFile(filepath.Join(mdir, "current"))
	if err != nil {
		if os.IsNotExist(err) {
			if st.seen > 0 {
				return st, nil // seen-only state (nothing held yet) is valid
			}
			return nil, nil
		}
		return nil, err
	}
	vdir := strings.TrimSpace(string(cur))
	version, err := parseVersionDir(vdir)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(filepath.Join(mdir, vdir, "manifest.json"))
	if err != nil {
		return nil, err
	}
	m, err := decodeStoredManifest(data)
	if err != nil {
		return nil, err
	}
	if m.Version != version || m.MemberID != id {
		return nil, fmt.Errorf("manifest (%s v%d) does not match location (%s %s)", m.MemberID, m.Version, id, vdir)
	}
	st.version = version
	st.manifestBytes = data
	st.manifest = m
	if st.seen < version {
		st.seen = version
	}
	return st, nil
}

func parseVersionDir(name string) (uint64, error) {
	if !strings.HasPrefix(name, "v") {
		return 0, fmt.Errorf("bad version dir %q", name)
	}
	return strconv.ParseUint(name[1:], 10, 64)
}

// decodeStoredManifest structurally parses a stored envelope (no
// signature check; see package comment).
func decodeStoredManifest(data []byte) (*wire.Manifest, error) {
	var sm wire.SignedManifest
	if err := json.Unmarshal(data, &sm); err != nil {
		return nil, err
	}
	if err := sm.Manifest.Validate(); err != nil {
		return nil, err
	}
	return &sm.Manifest, nil
}

// Put atomically stores a VERIFIED bundle. manifestBytes is the exact
// envelope as received (it re-serves byte-for-byte on relay); m is its
// verified decoding; blobs maps sha256 -> content for every file in m.
// Same-version Put is an idempotent no-op; a lower version returns
// ErrRollback.
func (s *Store) Put(id string, manifestBytes []byte, m *wire.Manifest, blobs map[string][]byte) error {
	if id != m.MemberID {
		return fmt.Errorf("store: manifest is for %q, not %q", m.MemberID, id)
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	st := s.members[id]
	if st != nil && st.manifest != nil {
		if m.Version < st.version {
			return fmt.Errorf("%w: have v%d, offered v%d (member %s)", ErrRollback, st.version, m.Version, id)
		}
		if m.Version == st.version {
			return nil
		}
	}
	for _, f := range m.Files {
		if _, ok := blobs[f.SHA256]; !ok {
			return fmt.Errorf("store: blob %s for %q missing from Put", f.SHA256, f.Path)
		}
	}

	mdir := s.memberDir(id)
	vdirName := fmt.Sprintf("v%d", m.Version)
	tmp := filepath.Join(mdir, ".tmp-"+vdirName)
	if err := os.RemoveAll(tmp); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(tmp, "blobs"), 0o755); err != nil {
		return err
	}
	for hash, data := range blobs {
		if err := os.WriteFile(filepath.Join(tmp, "blobs", hash), data, 0o644); err != nil {
			return err
		}
	}
	if err := os.WriteFile(filepath.Join(tmp, "manifest.json"), manifestBytes, 0o644); err != nil {
		return err
	}
	final := filepath.Join(mdir, vdirName)
	if err := os.RemoveAll(final); err != nil {
		return err
	}
	if err := os.Rename(tmp, final); err != nil {
		return err
	}
	// Commit point: swap the pointer.
	ptmp := filepath.Join(mdir, ".current.tmp")
	if err := os.WriteFile(ptmp, []byte(vdirName+"\n"), 0o644); err != nil {
		return err
	}
	if err := os.Rename(ptmp, filepath.Join(mdir, "current")); err != nil {
		return err
	}

	// Prune superseded version dirs (best-effort).
	if entries, err := os.ReadDir(mdir); err == nil {
		for _, e := range entries {
			if e.IsDir() && strings.HasPrefix(e.Name(), "v") && e.Name() != vdirName {
				os.RemoveAll(filepath.Join(mdir, e.Name()))
			}
		}
	}

	if st == nil {
		st = &memberState{}
		s.members[id] = st
	}
	st.version = m.Version
	st.manifestBytes = append([]byte(nil), manifestBytes...)
	mCopy := *m
	st.manifest = &mCopy
	if st.seen < m.Version {
		st.seen = m.Version
		s.persistSeenLocked(id, st.seen)
	}
	s.log.Info("store: bundle updated", "member", id, "version", m.Version, "files", len(m.Files))
	return nil
}

// NoteSeen records that some source presented a validly-signed manifest
// at version v for member id. Feeds freshness; persists across restarts.
func (s *Store) NoteSeen(id string, v uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.members[id]
	if st == nil {
		st = &memberState{}
		s.members[id] = st
	}
	if v > st.seen {
		st.seen = v
		s.persistSeenLocked(id, v)
	}
}

func (s *Store) persistSeenLocked(id string, v uint64) {
	mdir := s.memberDir(id)
	if err := os.MkdirAll(mdir, 0o755); err != nil {
		s.log.Warn("store: persist seen", "member", id, "err", err)
		return
	}
	tmp := filepath.Join(mdir, ".seen.tmp")
	if err := os.WriteFile(tmp, []byte(strconv.FormatUint(v, 10)+"\n"), 0o644); err != nil {
		s.log.Warn("store: persist seen", "member", id, "err", err)
		return
	}
	if err := os.Rename(tmp, filepath.Join(mdir, "seen")); err != nil {
		s.log.Warn("store: persist seen", "member", id, "err", err)
	}
}

// Manifest returns the stored envelope bytes and decoded manifest.
func (s *Store) Manifest(id string) ([]byte, *wire.Manifest, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	st := s.members[id]
	if st == nil || st.manifest == nil {
		return nil, nil, false
	}
	return st.manifestBytes, st.manifest, true
}

// Version returns the stored bundle version (0 = none held).
func (s *Store) Version(id string) uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if st := s.members[id]; st != nil {
		return st.version
	}
	return 0
}

// SeenVersion returns the highest version ever observed for id.
func (s *Store) SeenVersion(id string) uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if st := s.members[id]; st != nil {
		return st.seen
	}
	return 0
}

// BlobPath returns the on-disk path of a held blob, after checking that
// the hash belongs to the member's current manifest.
func (s *Store) BlobPath(id, hash string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	st := s.members[id]
	if st == nil || st.manifest == nil {
		return "", false
	}
	for _, f := range st.manifest.Files {
		if f.SHA256 == hash {
			return filepath.Join(s.memberDir(id), fmt.Sprintf("v%d", st.version), "blobs", hash), true
		}
	}
	return "", false
}

// Held returns the IDs of members whose bundles this store holds.
func (s *Store) Held() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.members))
	for id, st := range s.members {
		if st.manifest != nil {
			out = append(out, id)
		}
	}
	return out
}
