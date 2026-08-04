// Copyright 2026 The Resiliency Wreath Authors
// SPDX-License-Identifier: Apache-2.0

// Package agent composes store + registry + fetch + serve (+ probe from
// M3) into the peer-agent daemon. Deployment concerns — which listener,
// which HTTP client, which logger — are all injectable, so the co-tenant
// daemon, the simulation harness, and a future appliance build are the
// same core with different wiring (KICKOFF decision 6).
package agent

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/selfsimilar/resiliency-wreath/internal/fetch"
	"github.com/selfsimilar/resiliency-wreath/internal/probe"
	"github.com/selfsimilar/resiliency-wreath/internal/registry"
	"github.com/selfsimilar/resiliency-wreath/internal/serve"
	"github.com/selfsimilar/resiliency-wreath/internal/store"
)

// Config for one agent. MemberID must appear in the registry.
type Config struct {
	MemberID     string
	RegistryPath string
	RegistryPub  ed25519.PublicKey
	DataDir      string

	// Listen is the TCP address to serve on; ignored when Listener is
	// set (the simulation pre-binds listeners to learn ports).
	Listen   string
	Listener net.Listener

	// Client, if set, replaces the default HTTP client (simulation
	// injects partition-aware transports here).
	Client *http.Client

	// TLS, if set, wraps the listener (e.g. certmagic in wreath-agent).
	// Kept behind an interface so core packages stay stdlib-only and
	// the sim never touches ACME.
	TLS TLSProvider

	PollInterval  time.Duration
	ProbeInterval time.Duration
	Staleness     time.Duration

	Logger *slog.Logger
}

// Agent is one running peer agent.
type Agent struct {
	cfg      Config
	log      *slog.Logger
	Store    *store.Store
	Registry *registry.Watcher
	Fetcher  *fetch.Fetcher
	Prober   *probe.Prober
	handler  http.Handler
	ln       net.Listener
}

// New validates config, opens local state, and prepares (but does not
// start) the agent.
func New(cfg Config) (*Agent, error) {
	if cfg.MemberID == "" || cfg.RegistryPath == "" || cfg.DataDir == "" {
		return nil, errors.New("agent: MemberID, RegistryPath, and DataDir are required")
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 30 * time.Second
	}
	if cfg.ProbeInterval <= 0 {
		cfg.ProbeInterval = 60 * time.Second
	}
	if cfg.Staleness <= 0 {
		cfg.Staleness = 5 * time.Minute
	}
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	log = log.With("agent", cfg.MemberID)

	st, err := store.Open(cfg.DataDir, log)
	if err != nil {
		return nil, fmt.Errorf("agent: open store: %w", err)
	}
	reg, err := registry.Open(cfg.RegistryPath, cfg.RegistryPub, log)
	if err != nil {
		return nil, fmt.Errorf("agent: open registry: %w", err)
	}
	if reg.Current().Member(cfg.MemberID) == nil {
		return nil, fmt.Errorf("agent: member %q is not in registry %s", cfg.MemberID, cfg.RegistryPath)
	}

	f := fetch.New(fetch.Config{
		Client:   cfg.Client,
		Store:    st,
		Registry: reg.Current,
		SelfID:   cfg.MemberID,
		Interval: cfg.PollInterval,
		Logger:   log,
	})
	p := probe.New(probe.Config{
		Client:    cfg.Client,
		Store:     st,
		Registry:  reg.Current,
		SelfID:    cfg.MemberID,
		Interval:  cfg.ProbeInterval,
		Staleness: cfg.Staleness,
		Logger:    log,
	})
	h := serve.Handler(serve.Config{
		SelfID:   cfg.MemberID,
		Store:    st,
		Registry: reg.Current,
		Health:   p.Report,
		Notify:   f.Kick,
		Logger:   log,
	})
	return &Agent{cfg: cfg, log: log, Store: st, Registry: reg, Fetcher: f, Prober: p, handler: h}, nil
}

// Run serves until ctx is canceled, then shuts down gracefully.
func (a *Agent) Run(ctx context.Context) error {
	ln := a.cfg.Listener
	if ln == nil {
		var err error
		ln, err = net.Listen("tcp", a.cfg.Listen)
		if err != nil {
			return err
		}
	}
	if a.cfg.TLS != nil {
		var err error
		ln, err = a.cfg.TLS.Listener(ln)
		if err != nil {
			return fmt.Errorf("agent: enable TLS: %w", err)
		}
		a.log.Info("agent: TLS enabled")
	}
	a.ln = ln
	srv := &http.Server{Handler: a.handler}

	go a.Fetcher.Run(ctx)
	go a.Prober.Run(ctx)
	go a.registryReloadLoop(ctx)

	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(ln) }()
	a.log.Info("agent: serving", "addr", ln.Addr().String())

	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutCtx); err != nil {
			return err
		}
		<-errCh // Serve has returned ErrServerClosed
		return nil
	case err := <-errCh:
		return err
	}
}

// registryReloadLoop re-checks the registry file on the poll cadence. A
// failed reload keeps the last good registry (see registry.Reload).
func (a *Agent) registryReloadLoop(ctx context.Context) {
	t := time.NewTicker(a.cfg.PollInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := a.Registry.Reload(); err != nil {
				a.log.Warn("agent: registry reload failed; keeping previous", "err", err)
			}
		}
	}
}

// Addr returns the bound address once Run has started listening.
func (a *Agent) Addr() string {
	if a.ln == nil {
		return ""
	}
	return a.ln.Addr().String()
}

// URL returns the agent's base URL once listening.
func (a *Agent) URL() string { return "http://" + a.Addr() }
