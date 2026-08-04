// Copyright 2026 The Resiliency Wreath Authors
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/selfsimilar/resiliency-wreath/internal/wire"
)

func testBundle(t *testing.T, member string, version uint64, content string) ([]byte, *wire.Manifest, map[string][]byte) {
	t.Helper()
	seed := sha256.Sum256([]byte("store test key: " + member))
	priv := ed25519.NewKeyFromSeed(seed[:])
	sum := sha256.Sum256([]byte(content))
	hash := hex.EncodeToString(sum[:])
	m := &wire.Manifest{
		MemberID:  member,
		Version:   version,
		Timestamp: "2026-07-23T00:00:00Z",
		Files:     []wire.FileEntry{{Path: "index.html", SHA256: hash, Size: int64(len(content))}},
	}
	sm, err := wire.SignManifest(m, priv)
	if err != nil {
		t.Fatal(err)
	}
	env, err := wire.EncodeSignedManifest(sm)
	if err != nil {
		t.Fatal(err)
	}
	return env, m, map[string][]byte{hash: []byte(content)}
}

func openTest(t *testing.T, dir string) *Store {
	t.Helper()
	s, err := Open(dir, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestPutGetAndRollback(t *testing.T) {
	dir := t.TempDir()
	s := openTest(t, dir)

	env1, m1, blobs1 := testBundle(t, "member-a", 1, "v1 content")
	if err := s.Put("member-a", env1, m1, blobs1); err != nil {
		t.Fatal(err)
	}
	env2, m2, blobs2 := testBundle(t, "member-a", 2, "v2 content")
	if err := s.Put("member-a", env2, m2, blobs2); err != nil {
		t.Fatal(err)
	}
	if got := s.Version("member-a"); got != 2 {
		t.Fatalf("version = %d, want 2", got)
	}

	// Rollback: re-offering v1 must fail with ErrRollback specifically.
	if err := s.Put("member-a", env1, m1, blobs1); !errors.Is(err, ErrRollback) {
		t.Fatalf("want ErrRollback, got %v", err)
	}
	// Same version: idempotent no-op.
	if err := s.Put("member-a", env2, m2, blobs2); err != nil {
		t.Fatalf("idempotent Put failed: %v", err)
	}

	// Blob is retrievable and hash-gated.
	hash := m2.Files[0].SHA256
	p, ok := s.BlobPath("member-a", hash)
	if !ok {
		t.Fatal("BlobPath: not found")
	}
	data, err := os.ReadFile(p)
	if err != nil || string(data) != "v2 content" {
		t.Fatalf("blob content %q err %v", data, err)
	}
	if _, ok := s.BlobPath("member-a", m1.Files[0].SHA256); ok {
		t.Error("v1 blob still addressable after v2 swap")
	}
}

func TestReopenPersistsStateAndSeen(t *testing.T) {
	dir := t.TempDir()
	s := openTest(t, dir)
	env2, m2, blobs2 := testBundle(t, "member-a", 2, "v2 content")
	if err := s.Put("member-a", env2, m2, blobs2); err != nil {
		t.Fatal(err)
	}
	s.NoteSeen("member-a", 5) // a peer showed us a signed v5 we couldn't fetch

	s2 := openTest(t, dir)
	if got := s2.Version("member-a"); got != 2 {
		t.Errorf("reopened version = %d, want 2", got)
	}
	if got := s2.SeenVersion("member-a"); got != 5 {
		t.Errorf("reopened seen = %d, want 5", got)
	}
	// Anti-rollback survives restart.
	env1, m1, blobs1 := testBundle(t, "member-a", 1, "v1 content")
	if err := s2.Put("member-a", env1, m1, blobs1); !errors.Is(err, ErrRollback) {
		t.Errorf("want ErrRollback after reopen, got %v", err)
	}
}

func TestOldVersionsPruned(t *testing.T) {
	dir := t.TempDir()
	s := openTest(t, dir)
	env1, m1, blobs1 := testBundle(t, "member-a", 1, "v1")
	env2, m2, blobs2 := testBundle(t, "member-a", 2, "v2")
	if err := s.Put("member-a", env1, m1, blobs1); err != nil {
		t.Fatal(err)
	}
	if err := s.Put("member-a", env2, m2, blobs2); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "members", "member-a", "v1")); !os.IsNotExist(err) {
		t.Errorf("v1 dir survived swap: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "members", "member-a", "v2", "manifest.json")); err != nil {
		t.Errorf("v2 manifest missing: %v", err)
	}
}

func TestCorruptMemberSkippedOnOpen(t *testing.T) {
	dir := t.TempDir()
	s := openTest(t, dir)
	env1, m1, blobs1 := testBundle(t, "member-a", 1, "v1")
	if err := s.Put("member-a", env1, m1, blobs1); err != nil {
		t.Fatal(err)
	}
	// Corrupt the pointer.
	if err := os.WriteFile(filepath.Join(dir, "members", "member-a", "current"), []byte("garbage\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	s2 := openTest(t, dir)
	if got := s2.Version("member-a"); got != 0 {
		t.Errorf("corrupt member loaded anyway: v%d", got)
	}
	// Recovery: a fresh Put works.
	if err := s2.Put("member-a", env1, m1, blobs1); err != nil {
		t.Errorf("recovery Put failed: %v", err)
	}
}
