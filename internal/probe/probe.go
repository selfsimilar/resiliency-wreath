// Copyright 2026 The Resiliency Ring Authors
// SPDX-License-Identifier: Apache-2.0

// Package probe implements data-plane liveness (DESIGN §9, KICKOFF M3):
// each agent periodically fetches every holder's copy of every member's
// bundle manifest and classifies it. The three-part check is
//
//	reachable ∧ valid-signature ∧ version ≥ highest-known
//
// with a grace window: when the prober first learns of version V, other
// holders may lag behind V for up to the staleness tolerance before
// they flip from "fresh" to "stale". A stale-but-signed bundle is up
// and useless — freshness is part of health, not an afterthought.
//
// Reports are the prober's OWN view; agents on opposite sides of a
// partition legitimately disagree.
package probe

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/selfsimilar/resiliency-ring/internal/store"
	"github.com/selfsimilar/resiliency-ring/internal/wire"
)

// Config wires a Prober; fields mirror fetch.Config.
type Config struct {
	Client    *http.Client
	Store     *store.Store
	Registry  func() *wire.Registry
	SelfID    string
	Interval  time.Duration
	Staleness time.Duration
	Logger    *slog.Logger
}

type cell struct {
	entry    wire.HealthEntry
	lastSeen time.Time
}

// Prober runs the probe loop and answers health queries.
type Prober struct {
	cfg Config

	mu sync.Mutex
	// matrix[member][holder] = latest observation.
	matrix map[string]map[string]*cell
	// firstKnown[member][version] = when this prober first learned of
	// that version (grace-window anchor).
	firstKnown map[string]map[uint64]time.Time
}

func New(cfg Config) *Prober {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 60 * time.Second
	}
	if cfg.Staleness <= 0 {
		cfg.Staleness = 5 * time.Minute
	}
	if cfg.Client == nil {
		cfg.Client = &http.Client{Timeout: 10 * time.Second}
	}
	return &Prober{
		cfg:        cfg,
		matrix:     make(map[string]map[string]*cell),
		firstKnown: make(map[string]map[uint64]time.Time),
	}
}

// Run probes until ctx is done. First sweep is immediate.
func (p *Prober) Run(ctx context.Context) {
	t := time.NewTicker(p.cfg.Interval)
	defer t.Stop()
	p.Sweep(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.Sweep(ctx)
		}
	}
}

// Sweep probes every (member, holder) pair once.
func (p *Prober) Sweep(ctx context.Context) {
	reg := p.cfg.Registry()
	if reg == nil {
		return
	}
	now := time.Now()
	for _, member := range reg.Members {
		// Track our own store's knowledge first so freshness has a
		// baseline even before any peer answers.
		p.noteVersion(member.ID, p.cfg.Store.SeenVersion(member.ID), now)
	}
	for _, holder := range reg.Members {
		if holder.Agent == "" {
			continue
		}
		for _, member := range reg.Members {
			if ctx.Err() != nil {
				return
			}
			var e wire.HealthEntry
			if holder.ID == p.cfg.SelfID {
				e = p.observeSelf(member.ID)
			} else {
				e = p.observeRemote(ctx, reg, holder, member.ID)
			}
			p.record(member.ID, holder.ID, e, now)
		}
	}
}

func (p *Prober) observeSelf(memberID string) wire.HealthEntry {
	v := p.cfg.Store.Version(memberID)
	if v == 0 {
		return wire.HealthEntry{Status: wire.StatusMissing}
	}
	return wire.HealthEntry{Status: wire.StatusHealthy, Version: v}
}

// observeRemote fetches holder's copy of memberID's manifest and
// classifies the result. Full bundle verification (every blob) happens
// implicitly through relay fetches; probing checks the signed manifest,
// which pins every blob hash.
func (p *Prober) observeRemote(ctx context.Context, reg *wire.Registry, holder wire.Member, memberID string) wire.HealthEntry {
	pub, err := reg.MemberKey(memberID)
	if err != nil {
		return wire.HealthEntry{Status: wire.StatusInvalid, Detail: err.Error()}
	}
	url := holder.Agent + wire.MemberManifestPath(memberID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return wire.HealthEntry{Status: wire.StatusUnreachable, Detail: err.Error()}
	}
	resp, err := p.cfg.Client.Do(req)
	if err != nil {
		return wire.HealthEntry{Status: wire.StatusUnreachable}
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return wire.HealthEntry{Status: wire.StatusMissing}
	}
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return wire.HealthEntry{Status: wire.StatusUnreachable, Detail: resp.Status}
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, wire.MaxManifestBytes+1))
	if err != nil || int64(len(data)) > wire.MaxManifestBytes {
		return wire.HealthEntry{Status: wire.StatusInvalid, Detail: "oversized or truncated manifest"}
	}
	m, err := wire.VerifyManifestBytes(data, pub)
	if err != nil {
		// Reachable but serving garbage/forgery — the "tampered"
		// classification KICKOFF M3 requires.
		return wire.HealthEntry{Status: wire.StatusInvalid, Detail: err.Error()}
	}
	if m.MemberID != memberID {
		return wire.HealthEntry{Status: wire.StatusInvalid, Detail: "manifest for wrong member"}
	}
	p.cfg.Store.NoteSeen(memberID, m.Version)
	return wire.HealthEntry{Status: wire.StatusHealthy, Version: m.Version}
}

// noteVersion anchors the grace window for a newly-learned version.
func (p *Prober) noteVersion(memberID string, v uint64, now time.Time) {
	if v == 0 {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	fk := p.firstKnown[memberID]
	if fk == nil {
		fk = make(map[uint64]time.Time)
		p.firstKnown[memberID] = fk
	}
	if _, ok := fk[v]; !ok {
		fk[v] = now
	}
}

// record finalizes freshness for one observation and stores it.
func (p *Prober) record(memberID, holderID string, e wire.HealthEntry, now time.Time) {
	e.Member = memberID
	e.Holder = holderID
	if e.Version > 0 {
		p.noteVersion(memberID, e.Version, now)
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	highest := p.cfg.Store.SeenVersion(memberID)
	for v := range p.firstKnown[memberID] {
		if v > highest {
			highest = v
		}
	}
	switch e.Status {
	case wire.StatusHealthy:
		e.Fresh = e.Version >= highest
		if !e.Fresh {
			// Lagging: allowed inside the grace window measured from
			// when WE first learned of the highest version.
			if first, ok := p.firstKnown[memberID][highest]; ok && now.Sub(first) <= p.cfg.Staleness {
				e.Fresh = true
			} else {
				e.Status = wire.StatusStale
			}
		}
	default:
		e.Fresh = false
	}

	row := p.matrix[memberID]
	if row == nil {
		row = make(map[string]*cell)
		p.matrix[memberID] = row
	}
	c := row[holderID]
	if c == nil {
		c = &cell{}
		row[holderID] = c
	}
	if e.Status == wire.StatusHealthy || e.Status == wire.StatusStale {
		c.lastSeen = now
	}
	if !c.lastSeen.IsZero() {
		e.LastSeen = c.lastSeen.UTC().Format(time.RFC3339)
	}
	c.entry = e
}

// Report renders the current matrix, sorted for stable output.
func (p *Prober) Report() *wire.HealthReport {
	p.mu.Lock()
	defer p.mu.Unlock()
	rep := &wire.HealthReport{
		AgentID:            p.cfg.SelfID,
		GeneratedAt:        time.Now().UTC().Format(time.RFC3339),
		StalenessTolerance: p.cfg.Staleness.String(),
	}
	for member, row := range p.matrix {
		for _, c := range row {
			rep.Entries = append(rep.Entries, c.entry)
		}
		_ = member
	}
	sort.Slice(rep.Entries, func(i, j int) bool {
		a, b := rep.Entries[i], rep.Entries[j]
		if a.Member != b.Member {
			return a.Member < b.Member
		}
		return a.Holder < b.Holder
	})
	return rep
}

// String renders a compact matrix for logs and the sim's event stream.
func (p *Prober) String() string {
	rep := p.Report()
	out := fmt.Sprintf("health@%s:", rep.AgentID)
	for _, e := range rep.Entries {
		out += fmt.Sprintf(" %s@%s=%s/v%d", e.Member, e.Holder, e.Status, e.Version)
	}
	return out
}
