// Copyright 2026 The Resiliency Wreath Authors
// SPDX-License-Identifier: Apache-2.0

// Package fetch is the poll loop: keep every registry member's bundle
// current in the local store. Distribution is pull-based (KICKOFF
// decision 3): each cycle, for each member, the fetcher gathers signed
// manifests from the member's origin AND from every peer agent, picks
// the highest validly-signed version, and — if it beats what's stored —
// downloads the blobs (content-addressed, so any source that offered the
// manifest can serve them; per-blob fallback covers an origin that dies
// mid-rollout). Push-notify ("re-poll now") only accelerates this;
// correctness never depends on it.
package fetch

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/selfsimilar/resiliency-wreath/internal/store"
	"github.com/selfsimilar/resiliency-wreath/internal/wire"
)

// Config wires a Fetcher. Client is injectable so the simulation can
// impose partitions; Registry is a func so reloads take effect without
// coordination.
type Config struct {
	Client   *http.Client
	Store    *store.Store
	Registry func() *wire.Registry
	SelfID   string
	Interval time.Duration
	Logger   *slog.Logger
}

// Fetcher runs the poll loop. Kick(member) forces an immediate re-poll
// of one member (the notify path).
type Fetcher struct {
	cfg  Config
	kick chan string
}

func New(cfg Config) *Fetcher {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 30 * time.Second
	}
	if cfg.Client == nil {
		cfg.Client = &http.Client{Timeout: 10 * time.Second}
	}
	return &Fetcher{cfg: cfg, kick: make(chan string, 64)}
}

// Kick requests an immediate poll of one member. Non-blocking; a full
// queue drops the hint (the regular poll will catch up — by design).
func (f *Fetcher) Kick(memberID string) {
	select {
	case f.kick <- memberID:
	default:
	}
}

// Run polls until ctx is done. The first sweep happens immediately.
func (f *Fetcher) Run(ctx context.Context) {
	t := time.NewTicker(f.cfg.Interval)
	defer t.Stop()
	f.SyncAll(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			f.SyncAll(ctx)
		case id := <-f.kick:
			if err := f.SyncMember(ctx, id); err != nil {
				f.cfg.Logger.Debug("fetch: kicked sync failed", "member", id, "err", err)
			}
		}
	}
}

// SyncAll polls every member in the current registry.
func (f *Fetcher) SyncAll(ctx context.Context) {
	reg := f.cfg.Registry()
	if reg == nil {
		return
	}
	for _, m := range reg.Members {
		if ctx.Err() != nil {
			return
		}
		if err := f.SyncMember(ctx, m.ID); err != nil {
			f.cfg.Logger.Debug("fetch: sync failed", "member", m.ID, "err", err)
		}
	}
}

// source is one place a member's bundle can be fetched from.
type source struct {
	name        string
	manifestURL string
	blobURL     func(hash string) string
}

// sourcesFor lists candidate sources for a member's bundle: its origin
// first, then every peer agent (including the member's own agent — a
// co-tenant agent can outlive the origin process, and after OUR restart
// it may be the only holder of the latest version).
func (f *Fetcher) sourcesFor(reg *wire.Registry, member *wire.Member) []source {
	srcs := []source{{
		name:        "origin:" + member.ID,
		manifestURL: member.Origin + wire.OriginManifestPath,
		blobURL:     func(h string) string { return member.Origin + wire.OriginBlobPath(h) },
	}}
	for _, peer := range reg.Members {
		if peer.ID == f.cfg.SelfID || peer.Agent == "" {
			continue
		}
		agent := peer.Agent
		srcs = append(srcs, source{
			name:        "agent:" + peer.ID,
			manifestURL: agent + wire.MemberManifestPath(member.ID),
			blobURL: func(h string) string {
				return agent + wire.MemberBlobPath(member.ID, h)
			},
		})
	}
	return srcs
}

// SyncMember brings one member's bundle up to the newest validly-signed
// version reachable this cycle.
func (f *Fetcher) SyncMember(ctx context.Context, id string) error {
	reg := f.cfg.Registry()
	if reg == nil {
		return fmt.Errorf("fetch: no registry")
	}
	member := reg.Member(id)
	if member == nil {
		return fmt.Errorf("fetch: unknown member %q", id)
	}
	pub, err := reg.MemberKey(id)
	if err != nil {
		return err
	}

	current := f.cfg.Store.Version(id)
	srcs := f.sourcesFor(reg, member)

	var (
		bestVersion  = current
		bestIdx      = -1
		bestManifest *wire.Manifest
		bestBytes    []byte
		errs         []error
	)
	for i, src := range srcs {
		data, err := f.get(ctx, src.manifestURL, wire.MaxManifestBytes)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", src.name, err))
			continue
		}
		m, err := wire.VerifyManifestBytes(data, pub)
		if err != nil {
			// Tampered or forged — worth more than a debug line.
			f.cfg.Logger.Warn("fetch: rejected manifest", "member", id, "source", src.name, "err", err)
			errs = append(errs, fmt.Errorf("%s: %w", src.name, err))
			continue
		}
		if m.MemberID != id {
			errs = append(errs, fmt.Errorf("%s: manifest is for %q", src.name, m.MemberID))
			continue
		}
		f.cfg.Store.NoteSeen(id, m.Version)
		if m.Version > bestVersion {
			bestVersion, bestIdx, bestManifest, bestBytes = m.Version, i, m, data
		}
	}
	if bestIdx < 0 {
		// Nothing newer than what we hold. Only an error if we hold
		// nothing and nobody answered validly.
		if current == 0 && f.cfg.Store.SeenVersion(id) == 0 && len(errs) > 0 {
			return fmt.Errorf("fetch: no source for %s: %v", id, errs)
		}
		return nil
	}

	blobs := make(map[string][]byte, len(bestManifest.Files))
	for _, file := range bestManifest.Files {
		blob, err := f.getBlob(ctx, srcs, bestIdx, file)
		if err != nil {
			return fmt.Errorf("fetch: %s v%d blob %s: %w", id, bestVersion, file.Path, err)
		}
		blobs[file.SHA256] = blob
	}
	if err := f.cfg.Store.Put(id, bestBytes, bestManifest, blobs); err != nil {
		return err
	}
	f.cfg.Logger.Info("fetch: updated", "member", id, "version", bestVersion, "source", srcs[bestIdx].name)
	return nil
}

// getBlob fetches one content-addressed blob, preferring the source that
// supplied the winning manifest, then falling back to every other
// source. Any holder can serve any blob (relay safety comes from the
// hash check, not the source).
func (f *Fetcher) getBlob(ctx context.Context, srcs []source, preferred int, file wire.FileEntry) ([]byte, error) {
	order := append([]int{preferred}, otherIndices(len(srcs), preferred)...)
	var lastErr error
	for _, i := range order {
		data, err := f.get(ctx, srcs[i].blobURL(file.SHA256), wire.MaxBlobBytes)
		if err != nil {
			lastErr = err
			continue
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != file.SHA256 || int64(len(data)) != file.Size {
			lastErr = fmt.Errorf("%s: %w", srcs[i].name, wire.ErrHashMismatch)
			f.cfg.Logger.Warn("fetch: blob hash mismatch", "source", srcs[i].name, "path", file.Path)
			continue
		}
		return data, nil
	}
	return nil, lastErr
}

func otherIndices(n, skip int) []int {
	out := make([]int, 0, n-1)
	for i := 0; i < n; i++ {
		if i != skip {
			out = append(out, i)
		}
	}
	return out
}

func (f *Fetcher) get(ctx context.Context, url string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := f.cfg.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("GET %s: body exceeds %d bytes", url, limit)
	}
	return data, nil
}
