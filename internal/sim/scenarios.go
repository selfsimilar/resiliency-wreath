package sim

// The seven KICKOFF M4 scenarios. Each builds its own ring, drives a
// scripted failure, and asserts on outcomes — go test runs them all;
// ring-sim runs them interactively with the event log streaming.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/selfsimilar/resiliency-ring/internal/wire"
)

// Scenario is one scripted run.
type Scenario struct {
	Name string
	Desc string
	Run  func(log io.Writer, verbose bool) error
}

// All scenarios, in KICKOFF order.
var All = []Scenario{
	{"steady-state", "all origins healthy; every agent holds every bundle fresh", runSteadyState},
	{"origin-down", "origin dies; client walk lands on a peer; everyone keeps serving", runOriginDown},
	{"mid-rollout", "origin dies mid-rollout; laggards backfill the new version from peers", runMidRollout},
	{"tampered-peer", "malicious peer serves a forged bundle; detected, refused, flagged", runTamperedPeer},
	{"rollback-peer", "malicious peer replays an old signed version; anti-rollback holds", runRollbackPeer},
	{"cold-cache", "agent restarts with a wiped cache and converges from peers", runColdCache},
	{"partition", "network splits; both sides keep serving; converge after heal", runPartition},
}

// Find returns the named scenario, or nil.
func Find(name string) *Scenario {
	for i := range All {
		if All[i].Name == name {
			return &All[i]
		}
	}
	return nil
}

const walkWait = 8 * time.Second

func page(member, version string) map[string]string {
	return map[string]string{"index.html": fmt.Sprintf("%s %s lights-on page", member, version)}
}

func newStandardRing(log io.Writer, verbose bool, specs ...MemberSpec) (*Ring, error) {
	if len(specs) == 0 {
		specs = []MemberSpec{{ID: "alpha"}, {ID: "bravo"}, {ID: "charlie"}}
	}
	return NewRing(Config{Members: specs, Log: log, Verbose: verbose})
}

func publishAllV1(r *Ring) error {
	for _, id := range r.RealMembers() {
		if err := r.Publish(id, 1, page(id, "v1"), false); err != nil {
			return err
		}
	}
	for _, id := range r.RealMembers() {
		if err := r.WaitVersion(walkWait, id, 1, r.RealMembers()...); err != nil {
			return err
		}
	}
	return nil
}

// --- 1. steady state ------------------------------------------------

func runSteadyState(log io.Writer, verbose bool) error {
	r, err := newStandardRing(log, verbose)
	if err != nil {
		return err
	}
	defer r.Close()
	if err := publishAllV1(r); err != nil {
		return err
	}
	// Give the probers one full sweep, then demand an all-healthy matrix.
	time.Sleep(3 * r.cfg.Probe)
	rep, err := r.HealthFrom("alpha")
	if err != nil {
		return err
	}
	for _, member := range r.RealMembers() {
		for _, holder := range r.RealMembers() {
			e := Entry(rep, member, holder)
			if e == nil || e.Status != wire.StatusHealthy || !e.Fresh || e.Version != 1 {
				return fmt.Errorf("steady state: %s@%s = %+v, want healthy v1 fresh", member, holder, e)
			}
		}
	}
	r.Eventf("health matrix all green (%d cells)", len(r.RealMembers())*len(r.RealMembers()))
	// With everything up, the client walk never leaves the origin.
	res, err := r.Walk("alpha", "")
	if err != nil {
		return err
	}
	if res.ServedBy != "origin:alpha" {
		return fmt.Errorf("steady state: walk served by %s, want origin", res.ServedBy)
	}
	return nil
}

// --- 2. origin dies -> fallback everywhere ---------------------------

func runOriginDown(log io.Writer, verbose bool) error {
	r, err := newStandardRing(log, verbose)
	if err != nil {
		return err
	}
	defer r.Close()
	if err := publishAllV1(r); err != nil {
		return err
	}

	r.Eventf("killing alpha's origin AND alpha's agent (co-tenant dies with the host)")
	r.Nodes["alpha"].Origin.SetDown(true)
	r.StopAgent("alpha")

	res, err := r.Walk("alpha", "")
	if err != nil {
		return err
	}
	if res.ServedBy == "origin:alpha" || res.ServedBy == "agent:alpha" {
		return fmt.Errorf("origin-down: walk served by %s, want a surviving peer", res.ServedBy)
	}
	if !strings.Contains(res.Body, "alpha v1") {
		return fmt.Errorf("origin-down: wrong content %q", res.Body)
	}
	// Every surviving agent serves alpha's page.
	for _, hid := range []string{"bravo", "charlie"} {
		if v := r.Nodes[hid].Agent().Store.Version("alpha"); v != 1 {
			return fmt.Errorf("origin-down: %s dropped alpha's bundle (v%d)", hid, v)
		}
	}
	return nil
}

// --- 3. origin dies mid-rollout -> peers backfill ---------------------

func runMidRollout(log io.Writer, verbose bool) error {
	r, err := newStandardRing(log, verbose)
	if err != nil {
		return err
	}
	defer r.Close()
	if err := publishAllV1(r); err != nil {
		return err
	}

	// charlie is cut off from everyone while v2 rolls out.
	r.Eventf("partition: {alpha,bravo} | {charlie}")
	r.Net.SetGroups([]string{"alpha", "bravo"}, []string{"charlie"})
	if err := r.Publish("alpha", 2, page("alpha", "v2"), false); err != nil {
		return err
	}
	if err := r.WaitVersion(walkWait, "alpha", 2, "alpha", "bravo"); err != nil {
		return err
	}
	if v := r.Nodes["charlie"].Agent().Store.Version("alpha"); v != 1 {
		return fmt.Errorf("mid-rollout: charlie should still be at v1, is at v%d", v)
	}

	r.Eventf("origin alpha dies; partition heals — v2 now only exists on peers")
	r.Nodes["alpha"].Origin.SetDown(true)
	r.Net.Heal()

	if err := r.WaitVersion(walkWait, "alpha", 2, "charlie"); err != nil {
		return fmt.Errorf("mid-rollout: laggard never backfilled from peers: %w", err)
	}
	return nil
}

// --- 4. tampered peer -------------------------------------------------

func runTamperedPeer(log io.Writer, verbose bool) error {
	r, err := newStandardRing(log, verbose,
		MemberSpec{ID: "alpha"}, MemberSpec{ID: "bravo"}, MemberSpec{ID: "charlie"},
		MemberSpec{ID: "mallory", Fake: true})
	if err != nil {
		return err
	}
	defer r.Close()
	if err := publishAllV1(r); err != nil {
		return err
	}

	// Mallory forges a "v9" bundle for alpha, signed with her own key,
	// blobs included — a complete attack except for the one thing she
	// cannot fake: alpha's signature.
	evil := "EVIL: go to the wrong shelter"
	sum := sha256.Sum256([]byte(evil))
	forged := &wire.Manifest{
		MemberID:  "alpha",
		Version:   9,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Files:     []wire.FileEntry{{Path: "index.html", SHA256: hex.EncodeToString(sum[:]), Size: int64(len(evil))}},
	}
	sm, err := wire.SignManifest(forged, r.Nodes["mallory"].Priv)
	if err != nil {
		return err
	}
	env, err := wire.EncodeSignedManifest(sm)
	if err != nil {
		return err
	}
	r.SetFakeHandler("mallory", RelayHandler("alpha", env, map[string][]byte{hex.EncodeToString(sum[:]): []byte(evil)}))
	r.Eventf("mallory now serves a forged alpha v9 at her relay")

	// Several poll cycles: nobody may ingest it.
	time.Sleep(6 * r.cfg.Poll)
	for _, hid := range []string{"alpha", "bravo", "charlie"} {
		if v := r.Nodes[hid].Agent().Store.Version("alpha"); v != 1 {
			return fmt.Errorf("tampered-peer: %s ingested forged bundle (v%d)", hid, v)
		}
	}
	// And the mesh flags her.
	time.Sleep(3 * r.cfg.Probe)
	rep, err := r.HealthFrom("bravo")
	if err != nil {
		return err
	}
	e := Entry(rep, "alpha", "mallory")
	if e == nil || e.Status != wire.StatusInvalid {
		return fmt.Errorf("tampered-peer: health should flag mallory invalid for alpha, got %+v", e)
	}
	r.Eventf("forgery refused everywhere; health flags mallory as invalid")
	return nil
}

// --- 5. rollback peer --------------------------------------------------

func runRollbackPeer(log io.Writer, verbose bool) error {
	r, err := newStandardRing(log, verbose,
		MemberSpec{ID: "alpha"}, MemberSpec{ID: "bravo"}, MemberSpec{ID: "charlie"},
		MemberSpec{ID: "mallory", Fake: true})
	if err != nil {
		return err
	}
	defer r.Close()
	if err := publishAllV1(r); err != nil {
		return err
	}

	// Capture the GENUINE v1 envelope before alpha moves on — a replay
	// attack uses real signatures.
	v1env, _, ok := r.Nodes["bravo"].Agent().Store.Manifest("alpha")
	if !ok {
		return fmt.Errorf("rollback-peer: no v1 envelope to replay")
	}
	v1blob := make(map[string][]byte)
	_, v1m, _ := r.Nodes["bravo"].Agent().Store.Manifest("alpha")
	for _, f := range v1m.Files {
		p, _ := r.Nodes["bravo"].Agent().Store.BlobPath("alpha", f.SHA256)
		if data, err := readFile(p); err == nil {
			v1blob[f.SHA256] = data
		}
	}

	if err := r.Publish("alpha", 2, page("alpha", "v2"), false); err != nil {
		return err
	}
	if err := r.WaitVersion(walkWait, "alpha", 2, r.RealMembers()...); err != nil {
		return err
	}

	r.SetFakeHandler("mallory", RelayHandler("alpha", append([]byte(nil), v1env...), v1blob))
	r.Eventf("mallory replays alpha's genuine v1 (valid signature, old version)")

	time.Sleep(6 * r.cfg.Poll)
	for _, hid := range []string{"alpha", "bravo", "charlie"} {
		if v := r.Nodes[hid].Agent().Store.Version("alpha"); v != 2 {
			return fmt.Errorf("rollback-peer: %s rolled back to v%d", hid, v)
		}
	}
	// A cold-cache newcomer is the juicy target: it must still land on
	// v2 because fetch takes the HIGHEST valid version across sources.
	r.StopAgent("charlie")
	if err := r.WipeData("charlie"); err != nil {
		return err
	}
	if err := r.StartAgent("charlie"); err != nil {
		return err
	}
	if err := r.WaitVersion(walkWait, "alpha", 2, "charlie"); err != nil {
		return fmt.Errorf("rollback-peer: cold-cache agent seduced by replay: %w", err)
	}
	// Health: replayed copy shows as stale once the grace window passes.
	time.Sleep(r.cfg.Staleness + 3*r.cfg.Probe)
	rep, err := r.HealthFrom("bravo")
	if err != nil {
		return err
	}
	e := Entry(rep, "alpha", "mallory")
	if e == nil || e.Status != wire.StatusStale || e.Version != 1 {
		return fmt.Errorf("rollback-peer: health should flag mallory stale@v1, got %+v", e)
	}
	r.Eventf("anti-rollback held everywhere; mallory flagged stale")
	return nil
}

// --- 6. cold cache -----------------------------------------------------

func runColdCache(log io.Writer, verbose bool) error {
	r, err := newStandardRing(log, verbose)
	if err != nil {
		return err
	}
	defer r.Close()
	if err := publishAllV1(r); err != nil {
		return err
	}
	if err := r.Publish("alpha", 2, page("alpha", "v2"), false); err != nil {
		return err
	}
	if err := r.WaitVersion(walkWait, "alpha", 2, r.RealMembers()...); err != nil {
		return err
	}

	r.Eventf("charlie restarts with a wiped cache; alpha's origin is dead")
	r.StopAgent("charlie")
	if err := r.WipeData("charlie"); err != nil {
		return err
	}
	r.Nodes["alpha"].Origin.SetDown(true)
	if err := r.StartAgent("charlie"); err != nil {
		return err
	}

	for _, member := range []string{"alpha", "bravo", "charlie"} {
		want := uint64(1)
		if member == "alpha" {
			want = 2
		}
		if err := r.WaitVersion(walkWait, member, want, "charlie"); err != nil {
			return fmt.Errorf("cold-cache: %w", err)
		}
	}
	r.Eventf("cold cache fully reconverged (alpha via peers only)")
	return nil
}

// --- 7. partition + heal ------------------------------------------------

func runPartition(log io.Writer, verbose bool) error {
	r, err := newStandardRing(log, verbose,
		MemberSpec{ID: "alpha"}, MemberSpec{ID: "bravo"},
		MemberSpec{ID: "charlie"}, MemberSpec{ID: "delta"})
	if err != nil {
		return err
	}
	defer r.Close()
	if err := publishAllV1(r); err != nil {
		return err
	}

	r.Eventf("partition: {alpha,bravo} | {charlie,delta}")
	r.Net.SetGroups([]string{"alpha", "bravo"}, []string{"charlie", "delta"})

	if err := r.Publish("alpha", 2, page("alpha", "v2"), false); err != nil {
		return err
	}
	if err := r.WaitVersion(walkWait, "alpha", 2, "alpha", "bravo"); err != nil {
		return err
	}
	// The far side still serves v1 — degraded, not dark.
	time.Sleep(4 * r.cfg.Poll)
	for _, hid := range []string{"charlie", "delta"} {
		if v := r.Nodes[hid].Agent().Store.Version("alpha"); v != 1 {
			return fmt.Errorf("partition: %s at v%d, want to keep serving v1", hid, v)
		}
	}
	// The two sides legitimately disagree about the world.
	time.Sleep(3 * r.cfg.Probe)
	if rep, err := r.HealthFrom("charlie"); err == nil {
		if e := Entry(rep, "alpha", "alpha"); e == nil || e.Status != wire.StatusUnreachable {
			return fmt.Errorf("partition: charlie should see alpha unreachable, got %+v", e)
		}
	} else {
		return err
	}

	r.Eventf("partition heals")
	r.Net.Heal()
	for _, hid := range []string{"charlie", "delta"} {
		if err := r.WaitVersion(walkWait, "alpha", 2, hid); err != nil {
			return fmt.Errorf("partition: %s never converged after heal: %w", hid, err)
		}
	}
	r.Eventf("both sides converged on v2 after heal")
	return nil
}
