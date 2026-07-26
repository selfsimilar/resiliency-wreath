package agent_test

// M2 acceptance (KICKOFF): two agents on localhost; publish v1 to a fake
// origin -> both agents pick it up and serve it; kill the origin ->
// agents keep serving v1; an agent that missed v2 backfills it from the
// other agent with the origin down.

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/selfsimilar/resiliency-ring/internal/agent"
	"github.com/selfsimilar/resiliency-ring/internal/bundle"
	"github.com/selfsimilar/resiliency-ring/internal/serve"
	"github.com/selfsimilar/resiliency-ring/internal/wire"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func derivedKey(name string) (ed25519.PublicKey, ed25519.PrivateKey) {
	seed := sha256.Sum256([]byte("agent test key: " + name))
	priv := ed25519.NewKeyFromSeed(seed[:])
	return priv.Public().(ed25519.PublicKey), priv
}

// toggleOrigin is a fake member origin whose "down" switch simulates a
// dead origin (503 on every path).
type toggleOrigin struct {
	srv  *httptest.Server
	down atomic.Bool
}

func newToggleOrigin(dir string) *toggleOrigin {
	o := &toggleOrigin{}
	inner := serve.OriginHandler(dir)
	o.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if o.down.Load() {
			http.Error(w, "origin dead", http.StatusServiceUnavailable)
			return
		}
		inner.ServeHTTP(w, r)
	}))
	return o
}

func publish(t *testing.T, priv ed25519.PrivateKey, member, originDir string, version uint64, content string) {
	t.Helper()
	site := t.TempDir()
	if err := os.WriteFile(filepath.Join(site, "index.html"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	m, blobs, err := bundle.Build(site, member, version, time.Now(), nil)
	if err != nil {
		t.Fatal(err)
	}
	sm, err := wire.SignManifest(m, priv)
	if err != nil {
		t.Fatal(err)
	}
	env, err := wire.EncodeSignedManifest(sm)
	if err != nil {
		t.Fatal(err)
	}
	if err := bundle.WriteDir(originDir, env, blobs); err != nil {
		t.Fatal(err)
	}
}

func waitFor(t *testing.T, what string, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func httpGet(t *testing.T, url string) (int, string) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		return 0, ""
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestM2Acceptance(t *testing.T) {
	rootPub, rootPriv := derivedKey("registry-root")
	pubA, privA := derivedKey("member-a")
	pubB, privB := derivedKey("member-b")

	originDirA, originDirB := t.TempDir(), t.TempDir()
	originA := newToggleOrigin(originDirA)
	defer originA.srv.Close()
	originB := newToggleOrigin(originDirB)
	defer originB.srv.Close()

	// Pre-bind agent listeners so the registry can carry real URLs.
	lnA, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	lnB, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	agentURL := func(ln net.Listener) string { return "http://" + ln.Addr().String() }

	reg := &wire.Registry{
		RingID:    "test-ring",
		Version:   1,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Members: []wire.Member{
			{ID: "member-a", PublicKey: wire.EncodePublicKey(pubA), Origin: originA.srv.URL, Agent: agentURL(lnA)},
			{ID: "member-b", PublicKey: wire.EncodePublicKey(pubB), Origin: originB.srv.URL, Agent: agentURL(lnB)},
		},
	}
	sr, err := wire.SignRegistry(reg, rootPriv)
	if err != nil {
		t.Fatal(err)
	}
	regBytes, err := wire.EncodeSignedRegistry(sr)
	if err != nil {
		t.Fatal(err)
	}
	regPath := filepath.Join(t.TempDir(), "registry.json")
	if err := os.WriteFile(regPath, regBytes, 0o644); err != nil {
		t.Fatal(err)
	}

	publish(t, privA, "member-a", originDirA, 1, "A v1: member A is fine")
	publish(t, privB, "member-b", originDirB, 1, "B v1: member B is fine")

	mkAgent := func(id string, ln net.Listener, dataDir string) *agent.Agent {
		a, err := agent.New(agent.Config{
			MemberID:      id,
			RegistryPath:  regPath,
			RegistryPub:   rootPub,
			DataDir:       dataDir,
			Listener:      ln,
			PollInterval:  50 * time.Millisecond,
			ProbeInterval: 50 * time.Millisecond,
			Staleness:     300 * time.Millisecond,
			Logger:        testLogger(),
		})
		if err != nil {
			t.Fatal(err)
		}
		return a
	}

	dataA, dataB := t.TempDir(), t.TempDir()
	agentA := mkAgent("member-a", lnA, dataA)
	ctxA, cancelA := context.WithCancel(context.Background())
	defer cancelA()
	go agentA.Run(ctxA)

	agentB := mkAgent("member-b", lnB, dataB)
	ctxB, cancelB := context.WithCancel(context.Background())
	go agentB.Run(ctxB)

	// Phase 1: both agents converge on v1 of both members.
	waitFor(t, "both agents hold both bundles at v1", 5*time.Second, func() bool {
		return agentA.Store.Version("member-a") == 1 && agentA.Store.Version("member-b") == 1 &&
			agentB.Store.Version("member-a") == 1 && agentB.Store.Version("member-b") == 1
	})
	code, body := httpGet(t, agentURL(lnB)+"/fallback/member-a/")
	if code != 200 || body != "A v1: member A is fine" {
		t.Fatalf("agent B fallback for A: %d %q", code, body)
	}

	// Phase 2: origin A dies; agents keep serving v1.
	originA.down.Store(true)
	time.Sleep(200 * time.Millisecond) // several poll cycles
	code, body = httpGet(t, agentURL(lnB)+"/fallback/member-a/")
	if code != 200 || body != "A v1: member A is fine" {
		t.Fatalf("after origin death, agent B: %d %q", code, body)
	}

	// Phase 3: agent B goes down and misses v2.
	cancelB()
	waitFor(t, "agent B released its port", 5*time.Second, func() bool {
		conn, err := net.DialTimeout("tcp", lnB.Addr().String(), 20*time.Millisecond)
		if err != nil {
			return true
		}
		conn.Close()
		return false
	})

	originA.down.Store(false)
	publish(t, privA, "member-a", originDirA, 2, "A v2: updated home page")
	waitFor(t, "agent A picks up v2", 5*time.Second, func() bool {
		return agentA.Store.Version("member-a") == 2
	})
	originA.down.Store(true) // origin dies again — v2 now lives only on agent A

	// Phase 4: agent B restarts (same port, same data dir) and must
	// backfill v2 from agent A, with the origin down.
	lnB2, err := net.Listen("tcp", lnB.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	agentB2 := mkAgent("member-b", lnB2, dataB)
	ctxB2, cancelB2 := context.WithCancel(context.Background())
	defer cancelB2()
	go agentB2.Run(ctxB2)

	waitFor(t, "agent B backfills v2 from peer with origin down", 5*time.Second, func() bool {
		return agentB2.Store.Version("member-a") == 2
	})
	code, body = httpGet(t, agentURL(lnB2)+"/fallback/member-a/")
	if code != 200 || body != "A v2: updated home page" {
		t.Fatalf("agent B after backfill: %d %q", code, body)
	}

	// Relay surface sanity: manifest re-served byte-identical.
	stored, _, ok := agentB2.Store.Manifest("member-a")
	if !ok {
		t.Fatal("no stored manifest")
	}
	code, relayed := httpGet(t, agentURL(lnB2)+wire.MemberManifestPath("member-a"))
	if code != 200 || relayed != string(stored) {
		t.Fatalf("relay bytes differ from stored (code %d)", code)
	}
}
