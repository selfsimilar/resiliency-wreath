package probe_test

// M3 acceptance (KICKOFF): the health matrix correctly distinguishes a
// healthy peer, an unreachable peer, a peer serving a stale version,
// and a peer serving garbage/tampered data — plus "missing" (reachable,
// no copy) and the grace window that separates "lagging" from "stale".

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/selfsimilar/resiliency-ring/internal/probe"
	"github.com/selfsimilar/resiliency-ring/internal/serve"
	"github.com/selfsimilar/resiliency-ring/internal/store"
	"github.com/selfsimilar/resiliency-ring/internal/wire"
)

func derivedKey(name string) (ed25519.PublicKey, ed25519.PrivateKey) {
	seed := sha256.Sum256([]byte("probe test key: " + name))
	priv := ed25519.NewKeyFromSeed(seed[:])
	return priv.Public().(ed25519.PublicKey), priv
}

func signedManifest(t *testing.T, priv ed25519.PrivateKey, member string, version uint64, content string) ([]byte, *wire.Manifest, map[string][]byte) {
	t.Helper()
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

// manifestHolder fakes a peer agent that serves exactly one document
// for member alpha (or nothing).
func manifestHolder(body []byte) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if body != nil && r.URL.Path == wire.MemberManifestPath("alpha") {
			w.Header().Set("Content-Type", "application/json")
			w.Write(body)
			return
		}
		http.NotFound(w, r)
	}))
}

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError + 4}))
}

func TestM3HealthMatrix(t *testing.T) {
	pubAlpha, privAlpha := derivedKey("alpha")
	_, privEvil := derivedKey("evil")

	envV2, mV2, blobsV2 := signedManifest(t, privAlpha, "alpha", 2, "alpha v2")
	envV1, _, _ := signedManifest(t, privAlpha, "alpha", 1, "alpha v1")
	// "Tampered": signed by the wrong key entirely (a forgery attempt).
	envForged, _, _ := signedManifest(t, privEvil, "alpha", 9, "evil content")

	hGood := manifestHolder(envV2)
	defer hGood.Close()
	hStale := manifestHolder(envV1)
	defer hStale.Close()
	hEvil := manifestHolder(envForged)
	defer hEvil.Close()
	hMissing := manifestHolder(nil)
	defer hMissing.Close()
	// Unreachable: a listener with nothing accepting connections.
	deadLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadURL := "http://" + deadLn.Addr().String()
	deadLn.Close()

	dummyOrigin := "http://127.0.0.1:1" // never contacted by the prober
	members := []wire.Member{
		{ID: "alpha", PublicKey: wire.EncodePublicKey(pubAlpha), Origin: dummyOrigin, Agent: hGood.URL},
		{ID: "bravo", PublicKey: wire.EncodePublicKey(mustPub(t, "bravo")), Origin: dummyOrigin, Agent: hStale.URL},
		{ID: "charlie", PublicKey: wire.EncodePublicKey(mustPub(t, "charlie")), Origin: dummyOrigin, Agent: hEvil.URL},
		{ID: "delta", PublicKey: wire.EncodePublicKey(mustPub(t, "delta")), Origin: dummyOrigin, Agent: deadURL},
		{ID: "foxtrot", PublicKey: wire.EncodePublicKey(mustPub(t, "foxtrot")), Origin: dummyOrigin, Agent: hMissing.URL},
		{ID: "echo", PublicKey: wire.EncodePublicKey(mustPub(t, "echo")), Origin: dummyOrigin, Agent: "http://127.0.0.1:2"},
	}
	reg := &wire.Registry{RingID: "probe-ring", Version: 1, Timestamp: "2026-07-23T00:00:00Z", Members: members}

	st, err := store.Open(t.TempDir(), quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	// Self (echo) holds alpha v2 — the freshness baseline.
	if err := st.Put("alpha", envV2, mV2, blobsV2); err != nil {
		t.Fatal(err)
	}

	tolerance := 150 * time.Millisecond
	p := probe.New(probe.Config{
		Client:    &http.Client{Timeout: 500 * time.Millisecond},
		Store:     st,
		Registry:  func() *wire.Registry { return reg },
		SelfID:    "echo",
		Interval:  time.Hour, // manual sweeps only
		Staleness: tolerance,
		Logger:    quietLogger(),
	})

	ctx := context.Background()
	p.Sweep(ctx)

	// Within the grace window a lagging holder still counts as fresh.
	if e := entry(t, p, "alpha", "bravo"); e.Status != wire.StatusHealthy || !e.Fresh {
		t.Errorf("inside grace window: bravo = %+v, want healthy+fresh", e)
	}

	time.Sleep(tolerance + 50*time.Millisecond)
	p.Sweep(ctx)

	cases := []struct {
		holder string
		status wire.HealthStatus
		vers   uint64
		fresh  bool
	}{
		{"echo", wire.StatusHealthy, 2, true},     // self, current
		{"alpha", wire.StatusHealthy, 2, true},    // healthy peer
		{"bravo", wire.StatusStale, 1, false},     // validly signed but old
		{"charlie", wire.StatusInvalid, 0, false}, // forged signature
		{"delta", wire.StatusUnreachable, 0, false},
		{"foxtrot", wire.StatusMissing, 0, false}, // reachable, holds nothing
	}
	for _, c := range cases {
		e := entry(t, p, "alpha", c.holder)
		if e.Status != c.status || e.Version != c.vers || e.Fresh != c.fresh {
			t.Errorf("alpha@%s = {status:%s version:%d fresh:%v}, want {%s %d %v}",
				c.holder, e.Status, e.Version, e.Fresh, c.status, c.vers, c.fresh)
		}
	}

	// Stale and healthy holders have LastSeen; unreachable never does.
	if e := entry(t, p, "alpha", "bravo"); e.LastSeen == "" {
		t.Error("stale holder should still have last_seen")
	}
	if e := entry(t, p, "alpha", "delta"); e.LastSeen != "" {
		t.Error("never-reached holder should have empty last_seen")
	}

	// The health endpoint serves the same matrix as JSON.
	h := serve.Handler(serve.Config{
		SelfID:   "echo",
		Store:    st,
		Registry: func() *wire.Registry { return reg },
		Health:   p.Report,
		Logger:   quietLogger(),
	})
	srv := httptest.NewServer(h)
	defer srv.Close()
	resp, err := http.Get(srv.URL + wire.HealthPath)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var rep wire.HealthReport
	if err := json.NewDecoder(resp.Body).Decode(&rep); err != nil {
		t.Fatal(err)
	}
	if rep.AgentID != "echo" || len(rep.Entries) == 0 || rep.StalenessTolerance != tolerance.String() {
		t.Errorf("health endpoint report malformed: %+v", rep)
	}
}

func mustPub(t *testing.T, name string) ed25519.PublicKey {
	t.Helper()
	pub, _ := derivedKey(name)
	return pub
}

func entry(t *testing.T, p *probe.Prober, member, holder string) wire.HealthEntry {
	t.Helper()
	for _, e := range p.Report().Entries {
		if e.Member == member && e.Holder == holder {
			return e
		}
	}
	t.Fatalf("no entry for %s@%s", member, holder)
	return wire.HealthEntry{}
}
