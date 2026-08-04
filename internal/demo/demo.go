// Copyright 2026 The Resiliency Wreath Authors
// SPDX-License-Identifier: Apache-2.0

// Package demo wraps the simulated wreath in a long-running, human-paced
// mode with a web dashboard: per-member iframes loaded through a
// client-walk proxy, the gossiped health matrix, manual failure
// controls, and a chaos loop that swings members dark and back.
//
// Everything below the dashboard is the real reference implementation —
// real agents, real signing and verification, real HTTP on loopback —
// with timing compressed to demo scale. The one simulated component is
// the DNS control plane: the walk proxy stands in for a browser
// resolving HTTPS/SVCB records (RFC 9460, DESIGN §5) — try the origin
// at priority 1, then each peer's fallback surface in order — which is
// exactly the boundary DESIGN §13 draws for the MVP.
package demo

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/selfsimilar/resiliency-wreath/internal/sim"
	"github.com/selfsimilar/resiliency-wreath/internal/wire"
)

//go:embed dashboard.html
var dashboardHTML []byte

// Config tunes the demo. Zero values get demo-scale defaults.
type Config struct {
	Members     []string // 2..8 member IDs, in dashboard order
	Listen      string   // dashboard listen address
	Poll        time.Duration
	Probe       time.Duration
	Staleness   time.Duration
	Chaos       bool          // start with the chaos loop enabled
	ChaosGap    time.Duration // quiet time between automatic outages
	ChaosOutage time.Duration // how long an automatic outage lasts
	Verbose     bool
	Log         io.Writer
}

type walkRecord struct {
	ServedBy string `json:"served_by"`
	At       string `json:"at"`
}

type event struct {
	At   string `json:"at"`
	Text string `json:"text"`
}

// Server is one running demo: a simulated wreath plus its dashboard.
type Server struct {
	cfg    Config
	wreath *sim.Wreath

	mu         sync.Mutex
	version    map[string]uint64
	originDown map[string]bool
	lastWalk   map[string]walkRecord
	chaos      bool
	events     []event
}

// Run builds the wreath, publishes v1 for every member, and serves the
// dashboard until ctx is canceled.
func Run(ctx context.Context, cfg Config) error {
	if len(cfg.Members) < 2 || len(cfg.Members) > 8 {
		return fmt.Errorf("demo: want 2..8 members, got %d", len(cfg.Members))
	}
	for _, id := range cfg.Members {
		if !wire.ValidMemberID(id) {
			return fmt.Errorf("demo: invalid member id %q", id)
		}
	}
	if cfg.Poll <= 0 {
		cfg.Poll = 2 * time.Second
	}
	if cfg.Probe <= 0 {
		cfg.Probe = 3 * time.Second
	}
	if cfg.Staleness <= 0 {
		cfg.Staleness = 20 * time.Second
	}
	if cfg.ChaosGap <= 0 {
		cfg.ChaosGap = 30 * time.Second
	}
	if cfg.ChaosOutage <= 0 {
		cfg.ChaosOutage = 20 * time.Second
	}
	if cfg.Listen == "" {
		cfg.Listen = "127.0.0.1:8100"
	}
	if cfg.Log == nil {
		cfg.Log = os.Stdout
	}

	var specs []sim.MemberSpec
	for _, id := range cfg.Members {
		specs = append(specs, sim.MemberSpec{ID: id})
	}
	wreath, err := sim.NewWreath(sim.Config{
		Members:   specs,
		Poll:      cfg.Poll,
		Probe:     cfg.Probe,
		Staleness: cfg.Staleness,
		Log:       cfg.Log,
		Verbose:   cfg.Verbose,
	})
	if err != nil {
		return err
	}
	defer wreath.Close()

	s := &Server{
		cfg:        cfg,
		wreath:     wreath,
		chaos:      cfg.Chaos,
		version:    make(map[string]uint64),
		originDown: make(map[string]bool),
		lastWalk:   make(map[string]walkRecord),
	}
	for i, id := range cfg.Members {
		s.version[id] = 1
		if err := wreath.Publish(id, 1, siteFiles(id, 1, i, time.Now()), true); err != nil {
			return fmt.Errorf("demo: publish %s v1: %w", id, err)
		}
	}
	s.eventf("wreath up: %d members, each published bundle v1", len(cfg.Members))
	go func() {
		for _, id := range cfg.Members {
			if err := wreath.WaitVersion(30*time.Second, id, 1, cfg.Members...); err == nil {
				s.eventf("converged: every agent holds %s v1", id)
			}
		}
	}()
	go s.chaosLoop(ctx)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(dashboardHTML)
	})
	mux.HandleFunc("GET /api/state", s.handleState)
	mux.HandleFunc("POST /api/origin/{id}/toggle", s.handleToggleOrigin)
	mux.HandleFunc("POST /api/agent/{id}/toggle", s.handleToggleAgent)
	mux.HandleFunc("POST /api/publish/{id}", s.handlePublish)
	mux.HandleFunc("POST /api/chaos/toggle", s.handleToggleChaos)
	mux.HandleFunc("GET /walk/{member}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/walk/"+r.PathValue("member")+"/", http.StatusMovedPermanently)
	})
	mux.HandleFunc("GET /walk/{member}/{path...}", s.handleWalk)

	srv := &http.Server{Addr: cfg.Listen, Handler: mux}
	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()
	fmt.Fprintf(cfg.Log, "demo: dashboard at http://%s  (chaos=%v, poll=%s, staleness=%s)\n",
		cfg.Listen, cfg.Chaos, cfg.Poll, cfg.Staleness)

	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		srv.Shutdown(shutCtx)
		<-errCh
		return nil
	case err := <-errCh:
		return err
	}
}

// chaosLoop periodically picks the next member round-robin and takes it
// fully dark — origin and co-tenant agent together, the DESIGN §7
// co-tenancy failure mode — then restores it after ChaosOutage.
func (s *Server) chaosLoop(ctx context.Context) {
	wait := 12 * time.Second // first outage arrives quickly
	idx := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		wait = s.cfg.ChaosGap
		s.mu.Lock()
		on := s.chaos
		s.mu.Unlock()
		if !on {
			continue
		}
		members := s.wreath.RealMembers()
		id := members[idx%len(members)]
		idx++
		if !s.setDark(id, true, "chaos") {
			continue // already dark by hand; skip this round
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(s.cfg.ChaosOutage):
		}
		s.setDark(id, false, "chaos")
	}
}

// setDark flips a member's origin AND agent together. Reports false if
// the member was already in the requested state (e.g. manually toggled
// mid-chaos), in which case nothing happens.
func (s *Server) setDark(id string, dark bool, cause string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.originDown[id] == dark {
		return false
	}
	s.originDown[id] = dark
	n := s.wreath.Nodes[id]
	n.Origin.SetDown(dark)
	if dark {
		s.wreath.StopAgent(id)
		s.eventfLocked("%s: %s goes dark (origin + co-tenant agent)", cause, id)
	} else {
		if err := s.wreath.StartAgent(id); err != nil {
			s.eventfLocked("%s: %s origin restored (agent: %v)", cause, id, err)
		} else {
			s.eventfLocked("%s: %s restored (origin + agent)", cause, id)
		}
	}
	return true
}

// handleWalk is the client-walk proxy: the endpoint list is the
// member's simulated HTTPS-record set — origin at priority 1, then
// every peer's fallback surface in registry order — and the first 200
// wins, exactly sim.Walk / DESIGN §5.
func (s *Server) handleWalk(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("member")
	n := s.wreath.Nodes[id]
	if n == nil {
		http.NotFound(w, r)
		return
	}
	path := r.PathValue("path")
	type endpoint struct{ name, url string }
	eps := []endpoint{{"origin:" + id, n.Origin.URL + "/" + path}}
	for _, hid := range s.wreath.Order {
		if hid == id || s.wreath.Nodes[hid].Fake {
			continue
		}
		eps = append(eps, endpoint{"agent:" + hid, s.wreath.Nodes[hid].AgentURL() + "/fallback/" + id + "/" + path})
	}
	client := &http.Client{Timeout: 1500 * time.Millisecond}
	for _, ep := range eps {
		resp, err := client.Get(ep.url)
		if err != nil {
			continue
		}
		if resp.StatusCode != http.StatusOK {
			io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			continue
		}
		s.recordWalk(id, ep.name)
		for _, hk := range []string{"Content-Type", "Wreath-Member", "Wreath-Version", "Wreath-Holder"} {
			if v := resp.Header.Get(hk); v != "" {
				w.Header().Set(hk, v)
			}
		}
		w.Header().Set("X-Served-By", ep.name)
		w.Header().Set("Cache-Control", "no-store")
		io.Copy(w, io.LimitReader(resp.Body, 8<<20))
		resp.Body.Close()
		return
	}
	s.recordWalk(id, "none")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusServiceUnavailable)
	fmt.Fprintf(w, darkPage, id)
}

const darkPage = `<!doctype html><meta charset="utf-8"><body style="margin:0;font:15px/1.5 system-ui,sans-serif;background:#1a1a19;color:#c3c2b7;display:grid;place-items:center;min-height:97vh"><div style="text-align:center"><div style="font-size:1.6rem">✕</div><b>%s is dark</b><br>no endpoint answered the walk —<br>origin down and every peer holder unreachable</div>`

func (s *Server) recordWalk(id, servedBy string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	prev := s.lastWalk[id].ServedBy
	s.lastWalk[id] = walkRecord{ServedBy: servedBy, At: time.Now().Format("15:04:05")}
	if prev == servedBy {
		return
	}
	switch {
	case servedBy == "none":
		s.eventfLocked("walk: %s is DARK — no endpoint answered", id)
	case prev == "":
		s.eventfLocked("walk: %s served by %s", id, servedBy)
	default:
		s.eventfLocked("walk: %s now served by %s (was %s)", id, servedBy, prev)
	}
}

type memberState struct {
	ID         string      `json:"id"`
	Org        string      `json:"org"`
	Server     string      `json:"server"` // origin web-server software (label)
	OriginAddr string      `json:"origin_addr"`
	AgentAddr  string      `json:"agent_addr"`
	OriginUp   bool        `json:"origin_up"`
	AgentUp    bool        `json:"agent_up"`
	Version    uint64      `json:"published_version"`
	LastWalk   *walkRecord `json:"last_walk,omitempty"`
}

type observerHealth struct {
	Observer string             `json:"observer"`
	Error    string             `json:"error,omitempty"`
	Report   *wire.HealthReport `json:"report,omitempty"`
}

type stateDoc struct {
	WreathID  string           `json:"wreath_id"`
	Now       string           `json:"now"`
	Chaos     bool             `json:"chaos"`
	Poll      string           `json:"poll"`
	Staleness string           `json:"staleness"`
	Members   []memberState    `json:"members"`
	Health    []observerHealth `json:"health"`
	Events    []event          `json:"events"`
}

func (s *Server) handleState(w http.ResponseWriter, r *http.Request) {
	health := s.fetchHealth()
	s.mu.Lock()
	doc := stateDoc{
		WreathID:  "sim-wreath",
		Now:       time.Now().Format("15:04:05"),
		Chaos:     s.chaos,
		Poll:      s.cfg.Poll.String(),
		Staleness: s.cfg.Staleness.String(),
		Health:    health,
	}
	for i, id := range s.cfg.Members {
		n := s.wreath.Nodes[id]
		ms := memberState{
			ID:         id,
			Org:        orgName(id, i),
			Server:     serverName(i),
			OriginAddr: strings.TrimPrefix(n.Origin.URL, "http://"),
			AgentAddr:  strings.TrimPrefix(n.AgentURL(), "http://"),
			OriginUp:   !s.originDown[id],
			AgentUp:    n.Agent() != nil,
			Version:    s.version[id],
		}
		if wr, ok := s.lastWalk[id]; ok {
			c := wr
			ms.LastWalk = &c
		}
		doc.Members = append(doc.Members, ms)
	}
	if len(s.events) > 30 {
		doc.Events = append(doc.Events, s.events[len(s.events)-30:]...)
	} else {
		doc.Events = append(doc.Events, s.events...)
	}
	s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(doc)
}

// fetchHealth asks every running agent for its own health matrix; the
// dashboard aggregates the (legitimately differing) views client-side.
func (s *Server) fetchHealth() []observerHealth {
	members := s.wreath.RealMembers()
	out := make([]observerHealth, len(members))
	client := &http.Client{Timeout: 800 * time.Millisecond}
	var wg sync.WaitGroup
	for i, id := range members {
		wg.Add(1)
		go func() {
			defer wg.Done()
			oh := observerHealth{Observer: id}
			defer func() { out[i] = oh }()
			if s.wreath.Nodes[id].Agent() == nil {
				oh.Error = "agent stopped"
				return
			}
			resp, err := client.Get(s.wreath.Nodes[id].AgentURL() + wire.HealthPath)
			if err != nil {
				oh.Error = "unreachable"
				return
			}
			defer resp.Body.Close()
			var rep wire.HealthReport
			if err := json.NewDecoder(resp.Body).Decode(&rep); err != nil {
				oh.Error = err.Error()
				return
			}
			oh.Report = &rep
		}()
	}
	wg.Wait()
	return out
}

func (s *Server) member(w http.ResponseWriter, r *http.Request) *sim.Node {
	n := s.wreath.Nodes[r.PathValue("id")]
	if n == nil || n.Fake {
		http.NotFound(w, r)
		return nil
	}
	return n
}

func (s *Server) handleToggleOrigin(w http.ResponseWriter, r *http.Request) {
	n := s.member(w, r)
	if n == nil {
		return
	}
	s.mu.Lock()
	down := !s.originDown[n.ID]
	s.originDown[n.ID] = down
	n.Origin.SetDown(down)
	if down {
		s.eventfLocked("manual: %s origin killed", n.ID)
	} else {
		s.eventfLocked("manual: %s origin revived", n.ID)
	}
	s.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleToggleAgent(w http.ResponseWriter, r *http.Request) {
	n := s.member(w, r)
	if n == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if n.Agent() != nil {
		s.wreath.StopAgent(n.ID)
		s.eventfLocked("manual: %s agent stopped", n.ID)
	} else {
		if err := s.wreath.StartAgent(n.ID); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		s.eventfLocked("manual: %s agent restarted", n.ID)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handlePublish(w http.ResponseWriter, r *http.Request) {
	n := s.member(w, r)
	if n == nil {
		return
	}
	s.mu.Lock()
	s.version[n.ID]++
	v := s.version[n.ID]
	slot := 0
	for i, id := range s.cfg.Members {
		if id == n.ID {
			slot = i
		}
	}
	s.mu.Unlock()
	if err := s.wreath.Publish(n.ID, v, siteFiles(n.ID, v, slot, time.Now()), true); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.eventf("published %s v%d — watch it propagate", n.ID, v)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleToggleChaos(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.chaos = !s.chaos
	if s.chaos {
		s.eventfLocked("chaos enabled")
	} else {
		s.eventfLocked("chaos disabled")
	}
	s.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) eventf(format string, args ...any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.eventfLocked(format, args...)
}

func (s *Server) eventfLocked(format string, args ...any) {
	e := event{At: time.Now().Format("15:04:05"), Text: fmt.Sprintf(format, args...)}
	s.events = append(s.events, e)
	if len(s.events) > 60 {
		s.events = s.events[len(s.events)-60:]
	}
	fmt.Fprintf(s.cfg.Log, "%s  %s\n", e.At, e.Text)
}
