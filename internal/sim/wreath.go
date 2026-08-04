// Copyright 2026 The Resiliency Wreath Authors
// SPDX-License-Identifier: Apache-2.0

// Package sim spins up a whole wreath — N member origins + N peer agents,
// real HTTP on loopback ports — inside one process, with scriptable
// failures: dead origins, stopped agents, wiped caches, network
// partitions, and malicious peers. It is simultaneously the demo and
// the protocol test bed (KICKOFF M4).
package sim

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/selfsimilar/resiliency-wreath/internal/agent"
	"github.com/selfsimilar/resiliency-wreath/internal/bundle"
	"github.com/selfsimilar/resiliency-wreath/internal/wire"
)

// ToggleServer is an origin that can play dead (503 on every request)
// without losing its port.
type ToggleServer struct {
	srv  *httptest.Server
	down atomic.Bool
	URL  string
}

func newToggleServer(inner http.Handler) *ToggleServer {
	ts := &ToggleServer{}
	ts.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ts.down.Load() {
			http.Error(w, "origin dead", http.StatusServiceUnavailable)
			return
		}
		inner.ServeHTTP(w, r)
	}))
	ts.URL = ts.srv.URL
	return ts
}

// SetDown toggles the "origin is dead" switch.
func (ts *ToggleServer) SetDown(down bool) { ts.down.Store(down) }

// MemberSpec describes one wreath participant. A Fake member gets a real
// key, origin, and registry entry, but its "agent" is a hostile shell:
// it serves whatever handler the scenario installs (default 404)
// instead of running the real protocol.
type MemberSpec struct {
	ID   string
	Fake bool
}

// Node is one member's runtime state inside the sim.
type Node struct {
	ID   string
	Fake bool
	Pub  ed25519.PublicKey
	Priv ed25519.PrivateKey

	OriginDir string
	Origin    *ToggleServer
	siteDir   atomic.Value // string: the member's "real website" tree

	DataDir  string
	agentURL string

	fakeSrv     *httptest.Server
	fakeHandler atomic.Value // handlerBox (atomic.Value needs one concrete type)

	ln     net.Listener
	agent  *agent.Agent
	cancel context.CancelFunc
	done   chan struct{}
}

// Agent exposes the running agent (nil for fakes / stopped agents).
func (n *Node) Agent() *agent.Agent { return n.agent }

// AgentURL is the node's agent base URL (real or fake), stable for the
// life of the wreath even across agent restarts.
func (n *Node) AgentURL() string { return n.agentURL }

// Config tunes a simulated wreath.
type Config struct {
	Members   []MemberSpec
	Poll      time.Duration // default 60ms
	Probe     time.Duration // default 80ms
	Staleness time.Duration // default 250ms
	Log       io.Writer     // event log; default os.Stdout
	Verbose   bool          // also stream agent logs
}

// Wreath is a running simulated wreath.
type Wreath struct {
	cfg     Config
	dir     string
	Nodes   map[string]*Node
	Order   []string
	Net     *PartitionTable
	RegPath string
	RootPub ed25519.PublicKey

	start time.Time
	log   io.Writer
}

// NewWreath builds keys, origins, registry, and agents, and starts every
// real member's agent.
func NewWreath(cfg Config) (*Wreath, error) {
	if cfg.Poll <= 0 {
		cfg.Poll = 60 * time.Millisecond
	}
	if cfg.Probe <= 0 {
		cfg.Probe = 80 * time.Millisecond
	}
	if cfg.Staleness <= 0 {
		cfg.Staleness = 250 * time.Millisecond
	}
	if cfg.Log == nil {
		cfg.Log = os.Stdout
	}
	dir, err := os.MkdirTemp("", "wreath-sim-*")
	if err != nil {
		return nil, err
	}
	r := &Wreath{
		cfg:   cfg,
		dir:   dir,
		Nodes: make(map[string]*Node),
		Net:   NewPartitionTable(),
		start: time.Now(),
		log:   cfg.Log,
	}

	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	r.RootPub = rootPub

	var members []wire.Member
	for _, spec := range cfg.Members {
		n := &Node{ID: spec.ID, Fake: spec.Fake}
		n.Pub, n.Priv, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		n.OriginDir = filepath.Join(dir, spec.ID, "origin")
		if err := os.MkdirAll(n.OriginDir, 0o755); err != nil {
			return nil, err
		}
		// A member origin is its real website PLUS the two static wreath
		// endpoints (that's the whole onboarding story for a member).
		node := n
		n.Origin = newToggleServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if strings.HasPrefix(req.URL.Path, "/.well-known/wreath/") {
				originHandler(node.OriginDir).ServeHTTP(w, req)
				return
			}
			site, _ := node.siteDir.Load().(string)
			if site == "" {
				http.NotFound(w, req)
				return
			}
			http.FileServer(http.Dir(site)).ServeHTTP(w, req)
		}))
		r.registerURL(n.Origin.URL, spec.ID)

		if spec.Fake {
			n.fakeHandler.Store(handlerBox{http.NotFoundHandler()})
			n.fakeSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				n.fakeHandler.Load().(handlerBox).h.ServeHTTP(w, req)
			}))
			n.agentURL = n.fakeSrv.URL
		} else {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				return nil, err
			}
			n.ln = ln
			n.agentURL = "http://" + ln.Addr().String()
			n.DataDir = filepath.Join(dir, spec.ID, "data")
		}
		r.registerURL(n.agentURL, spec.ID)

		r.Nodes[spec.ID] = n
		r.Order = append(r.Order, spec.ID)
		members = append(members, wire.Member{
			ID:        spec.ID,
			PublicKey: wire.EncodePublicKey(n.Pub),
			Origin:    n.Origin.URL,
			Agent:     n.agentURL,
		})
	}

	reg := &wire.Registry{
		WreathID:  "sim-wreath",
		Version:   1,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Members:   members,
	}
	sr, err := wire.SignRegistry(reg, rootPriv)
	if err != nil {
		return nil, err
	}
	regBytes, err := wire.EncodeSignedRegistry(sr)
	if err != nil {
		return nil, err
	}
	r.RegPath = filepath.Join(dir, "registry.json")
	if err := os.WriteFile(r.RegPath, regBytes, 0o644); err != nil {
		return nil, err
	}

	for _, id := range r.Order {
		n := r.Nodes[id]
		if !n.Fake {
			if err := r.StartAgent(id); err != nil {
				return nil, err
			}
		}
	}
	return r, nil
}

func (r *Wreath) registerURL(rawURL, node string) {
	if host := hostOf(rawURL); host != "" {
		r.Net.RegisterHost(host, node)
	}
}

func hostOf(rawURL string) string {
	if len(rawURL) > 7 && rawURL[:7] == "http://" {
		return rawURL[7:]
	}
	return ""
}

// Eventf appends a timestamped line to the scenario event log.
func (r *Wreath) Eventf(format string, args ...any) {
	fmt.Fprintf(r.log, "%8.3fs  %s\n", time.Since(r.start).Seconds(), fmt.Sprintf(format, args...))
}

func (r *Wreath) agentLogger(id string) *slog.Logger {
	level := slog.LevelWarn
	if r.cfg.Verbose {
		level = slog.LevelDebug
	}
	return slog.New(slog.NewTextHandler(r.log, &slog.HandlerOptions{Level: level})).With("agent", id)
}

// StartAgent starts (or restarts) a real member's agent on its original
// port, reusing whatever is in its data directory.
func (r *Wreath) StartAgent(id string) error {
	n := r.Nodes[id]
	if n == nil || n.Fake {
		return fmt.Errorf("sim: %q is not a real member", id)
	}
	if n.agent != nil {
		return fmt.Errorf("sim: agent %q already running", id)
	}
	ln := n.ln
	n.ln = nil
	if ln == nil {
		var err error
		ln, err = net.Listen("tcp", hostOf(n.agentURL))
		if err != nil {
			return fmt.Errorf("sim: rebind %s: %w", id, err)
		}
	}
	a, err := agent.New(agent.Config{
		MemberID:      id,
		RegistryPath:  r.RegPath,
		RegistryPub:   r.RootPub,
		DataDir:       n.DataDir,
		Listener:      ln,
		Client:        &http.Client{Timeout: 500 * time.Millisecond, Transport: r.Net.Transport(id)},
		PollInterval:  r.cfg.Poll,
		ProbeInterval: r.cfg.Probe,
		Staleness:     r.cfg.Staleness,
		Logger:        r.agentLogger(id),
	})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	n.agent = a
	n.cancel = cancel
	n.done = make(chan struct{})
	go func() {
		defer close(n.done)
		if err := a.Run(ctx); err != nil {
			fmt.Fprintf(r.log, "agent %s exited: %v\n", id, err)
		}
	}()
	return nil
}

// StopAgent gracefully stops a member's agent and frees its port.
func (r *Wreath) StopAgent(id string) {
	n := r.Nodes[id]
	if n == nil || n.agent == nil {
		return
	}
	n.cancel()
	<-n.done
	n.agent = nil
	n.cancel = nil
}

// WipeData deletes a member's bundle cache (cold-cache restart).
func (r *Wreath) WipeData(id string) error {
	n := r.Nodes[id]
	if n.agent != nil {
		return fmt.Errorf("sim: stop agent %q before wiping", id)
	}
	return os.RemoveAll(n.DataDir)
}

// handlerBox gives atomic.Value the single concrete type it requires.
type handlerBox struct{ h http.Handler }

// SetFakeHandler installs the hostile behavior of a fake member's agent.
func (r *Wreath) SetFakeHandler(id string, h http.Handler) {
	r.Nodes[id].fakeHandler.Store(handlerBox{h})
}

// Publish builds, signs, and pushes a bundle to a member's origin, then
// (optionally) notifies every running agent.
func (r *Wreath) Publish(id string, version uint64, files map[string]string, notify bool) error {
	n := r.Nodes[id]
	site := filepath.Join(r.dir, id, fmt.Sprintf("site-v%d", version))
	for p, content := range files {
		full := filepath.Join(site, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			return err
		}
	}
	m, blobs, err := bundle.Build(site, id, version, time.Now(), nil)
	if err != nil {
		return err
	}
	sm, err := wire.SignManifest(m, n.Priv)
	if err != nil {
		return err
	}
	env, err := wire.EncodeSignedManifest(sm)
	if err != nil {
		return err
	}
	if err := bundle.WriteDir(n.OriginDir, env, blobs); err != nil {
		return err
	}
	n.siteDir.Store(site)
	r.Eventf("publish: %s v%d (%d files)", id, version, len(files))
	if notify {
		r.NotifyAll(id)
	}
	return nil
}

// NotifyAll sends the best-effort "re-poll now" hint for member id to
// every running agent.
func (r *Wreath) NotifyAll(memberID string) {
	body := fmt.Sprintf("{%q: %q}", "member_id", memberID)
	client := &http.Client{Timeout: 300 * time.Millisecond}
	for _, hid := range r.Order {
		h := r.Nodes[hid]
		if h.Fake || h.agent == nil {
			continue
		}
		resp, err := client.Post(h.agentURL+wire.NotifyPath, "application/json", strings.NewReader(body))
		if err == nil {
			resp.Body.Close()
		}
	}
}

// WaitVersion blocks until every listed holder's store has member at
// exactly version (or times out).
func (r *Wreath) WaitVersion(timeout time.Duration, memberID string, version uint64, holders ...string) error {
	deadline := time.Now().Add(timeout)
	for {
		ok := true
		for _, hid := range holders {
			n := r.Nodes[hid]
			if n.Fake || n.agent == nil || n.agent.Store.Version(memberID) != version {
				ok = false
				break
			}
		}
		if ok {
			r.Eventf("converged: %s at v%d on %v", memberID, version, holders)
			return nil
		}
		if time.Now().After(deadline) {
			state := ""
			for _, hid := range holders {
				n := r.Nodes[hid]
				v := uint64(0)
				if n.agent != nil {
					v = n.agent.Store.Version(memberID)
				}
				state += fmt.Sprintf(" %s=v%d", hid, v)
			}
			return fmt.Errorf("sim: timeout waiting for %s@v%d:%s", memberID, version, state)
		}
		time.Sleep(15 * time.Millisecond)
	}
}

// RealMembers returns the IDs of non-fake members.
func (r *Wreath) RealMembers() []string {
	var out []string
	for _, id := range r.Order {
		if !r.Nodes[id].Fake {
			out = append(out, id)
		}
	}
	return out
}

// WalkResult reports which endpoint of the client walk answered.
type WalkResult struct {
	ServedBy string // "origin:<id>" or "agent:<id>"
	Status   int
	Body     string
}

// Walk simulates the control plane of DESIGN §5: a client holding the
// full endpoint list (origin first, then every peer agent's fallback
// surface for the member) tries each in order and settles on the first
// success. No external brain — exactly the multi-A/HTTPS-record walk.
func (r *Wreath) Walk(memberID, path string) (*WalkResult, error) {
	n := r.Nodes[memberID]
	type endpoint struct{ name, url string }
	eps := []endpoint{{"origin:" + memberID, n.Origin.URL + "/" + path}}
	for _, hid := range r.Order {
		h := r.Nodes[hid]
		if h.Fake {
			continue
		}
		eps = append(eps, endpoint{"agent:" + hid, h.agentURL + "/fallback/" + memberID + "/" + path})
	}
	client := &http.Client{Timeout: 300 * time.Millisecond}
	var lastErr error
	for _, ep := range eps {
		resp, err := client.Get(ep.url)
		if err != nil {
			lastErr = err
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("%s: %s", ep.name, resp.Status)
			continue
		}
		r.Eventf("client walk for %s/%s -> served by %s", memberID, path, ep.name)
		return &WalkResult{ServedBy: ep.name, Status: resp.StatusCode, Body: string(body)}, nil
	}
	return nil, fmt.Errorf("sim: client walk exhausted all endpoints for %s: %v", memberID, lastErr)
}

// HealthFrom fetches an agent's health report (out-of-band observer,
// unaffected by partitions).
func (r *Wreath) HealthFrom(id string) (*wire.HealthReport, error) {
	resp, err := http.Get(r.Nodes[id].agentURL + wire.HealthPath)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var rep wire.HealthReport
	if err := jsonDecode(resp.Body, &rep); err != nil {
		return nil, err
	}
	return &rep, nil
}

// Entry finds one cell of a health report.
func Entry(rep *wire.HealthReport, member, holder string) *wire.HealthEntry {
	for i := range rep.Entries {
		if rep.Entries[i].Member == member && rep.Entries[i].Holder == holder {
			return &rep.Entries[i]
		}
	}
	return nil
}

// Close stops everything and removes the wreath's scratch directory.
func (r *Wreath) Close() {
	for _, id := range r.Order {
		n := r.Nodes[id]
		if n.agent != nil {
			r.StopAgent(id)
		}
		if n.fakeSrv != nil {
			n.fakeSrv.Close()
		}
		n.Origin.srv.Close()
	}
	os.RemoveAll(r.dir)
}
