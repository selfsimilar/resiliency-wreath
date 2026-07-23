# KICKOFF — Civic Resilience Ring: Go reference implementation

*This is the working brief for Claude Code. Read `DESIGN.md` first — it is the
decision record. This file tells you what to build now, in what order, and what
NOT to build. Where this file and DESIGN.md conflict, this file wins for scope;
DESIGN.md wins for rationale.*

---

## Mission

Build the **Go reference implementation** of the ring protocol: peer agent +
publisher CLI + file-based registry. Then run a **simulated multi-member ring**
end-to-end to iron out protocol kinks. The RFC will be **distilled from this
working code afterward** — so keep wire formats isolated and documented as you
go, but do NOT write the spec first.

## Decisions already made — do not re-litigate

1. **Language: Go**, single static binary, stdlib-first. Third-party deps
   allowed: `certmagic` (later milestone), a JCS/RFC-8785 canonicalization
   library (or implement minimally), test libs. Anything else: justify in a
   comment.
2. **Crypto: Ed25519** (stdlib `crypto/ed25519`). Signatures cover
   **canonicalized bytes** (RFC 8785 JCS) or raw content hashes — never
   ad-hoc-serialized JSON. This matters from commit one: a second
   implementation (Elixir/Nerves) must be able to verify our signatures.
3. **Distribution: pull-based polling** of well-known HTTPS endpoints +
   optional push-notify ("re-poll now") that correctness never depends on.
   **Peer-to-peer backfill**: any agent can relay any member's bundle; signing
   makes relay safe.
4. **Topology: full mesh.** Every agent holds every member's bundle. No
   sharding.
5. **Versioning: monotonic** version number in the signed manifest;
   anti-rollback enforced at verify time (never accept version < highest seen).
6. **Deployment unit: co-tenant daemon** for now, but isolate "how am I
   deployed / how do I serve" behind interfaces so an appliance build later is
   a swap, not a rewrite.
7. **Registry: a signed JSON file** (synced out-of-band, e.g., git). No
   registry server, no database.
8. **Liveness check is three-part:** `reachable ∧ valid-signature ∧
   version ≥ last-published within staleness tolerance`. Freshness is part of
   health, not an afterthought.

## Repo shape (suggested, adjust with reason)

```
ring/
├── DESIGN.md               # provided
├── KICKOFF.md              # this file
├── cmd/
│   ├── ring-agent/         # the peer agent daemon
│   ├── ring-publish/       # publisher CLI: build, sign, push
│   └── ring-sim/           # simulation harness (see Milestone 4)
├── internal/
│   ├── wire/               # ALL wire-format types + canonicalization + sign/verify.
│   │                       #   This package is the future RFC. Keep it dependency-light,
│   │                       #   heavily commented, with golden-file tests.
│   ├── registry/           # load/verify the signed registry file
│   ├── store/              # bundle cache w/ anti-rollback
│   ├── fetch/              # poll loop, origin + peer backfill
│   ├── serve/              # HTTP serving of held bundles (failover + always-on fallback)
│   └── probe/              # liveness probing + health reporting
└── testdata/               # golden files: canonical bytes, signatures, bundles
```

**`internal/wire` is sacred:** every type that crosses the network lives there,
with doc comments describing byte-level semantics (what exactly is signed, in
what canonical form). Golden-file tests pin canonical bytes + signatures so any
refactor that changes wire bytes fails loudly. This is what makes RFC
extraction cheap later.

## Milestones (in order; each ends runnable + tested)

### M1 — Bundle format, signing, verification
- `wire`: `Manifest` (member ID, monotonic version, timestamp, file list with
  SHA-256 hashes, optional metadata), canonicalization, Ed25519 sign/verify.
- `ring-publish`: `init` (keygen), `build <dir>` (bundle = manifest + files as
  a tar or content-addressed dir), `sign`, and `verify` subcommands.
- Golden-file tests incl. cross-checks: a manifest signed once must verify from
  its serialized form byte-for-byte; mutate any field → fail; replay older
  version → fail at store level (M2).
- **Acceptance:** `ring-publish build && ring-publish verify` round-trips; a
  tampered bundle and a rolled-back version are both rejected with distinct
  errors.

### M2 — Agent: store, poll, serve
- `store`: cache bundles on disk, enforce anti-rollback, atomic swap on update.
- `fetch`: poll each registry member's
  `/.well-known/ring/v0/bundle` (+ detached sig / manifest endpoint) on an
  interval; verify before store.
- `serve`: HTTP server exposing (a) each held bundle at a per-member vhost/path
  — this is the failover + always-on fallback surface; (b) the agent's own
  relay endpoints (same well-known paths) so peers can backfill from it.
- Plain HTTP is fine at this milestone; TLS/certmagic is M5.
- **Acceptance:** two agents on localhost; publish v1 to a fake origin → both
  agents pick it up and serve it; kill the origin, publish nothing → agents
  keep serving v1; one agent that "missed" v2 backfills it from the other agent
  (origin down).

### M3 — Probe + health
- `probe`: each agent periodically checks each peer's copy of each bundle
  (reachable / signature / freshness vs. the highest version it knows) and
  exposes a health report at `/.well-known/ring/v0/health` (JSON matrix:
  member × holder → {version, fresh, last_seen}).
- Staleness tolerance + poll interval configurable, sane defaults, documented.
- **Acceptance:** the health matrix correctly distinguishes: healthy peer,
  unreachable peer, peer serving stale version, peer serving garbage/tampered
  data.

### M4 — Simulation harness (the "iron out kinks" deliverable)
- `ring-sim`: spins up N agents + M fake member origins **in one process**
  (goroutines, real HTTP on loopback ports), drives scripted scenarios, and
  asserts on outcomes. Scenarios to include at minimum:
  1. steady state — all fresh;
  2. origin dies → fallback serves everywhere;
  3. origin dies mid-rollout → laggard agent backfills from peers;
  4. malicious peer serves tampered bundle → detected, refused, flagged in
     health;
  5. malicious/stale peer serves old version → anti-rollback holds;
  6. agent restarts with cold cache → converges;
  7. network partition (drop rules between subsets) → both sides converge
     after heal.
- **DNS swing is simulated, not real:** model the control plane as "which
  endpoint does the simulated client try, in order" (the multi-A/HTTPS-record
  client walk from DESIGN §5). No real DNS provider integration in MVP.
- **Acceptance:** `go test ./...` runs all scenarios green; `ring-sim run
  --scenario=...` runs them interactively with readable event logs. This
  harness is the demo AND the protocol test bed.

### M5 — Hardening pass (only after M4 findings are folded in)
- TLS via certmagic behind an interface (agents serve fallback names per
  DESIGN §5 cert-custody rules); config file for the agent; graceful
  shutdown; structured logs; `WIRE-NOTES.md` — a running log of every wire
  format decision + every kink M4 surfaced and how it changed the protocol.
  That file is the raw material for the RFC.

## Explicitly OUT of scope (see DESIGN §13)

Real DNS-provider integration; incident banner + out-of-band/phone signer;
shed/offload mode; Nerves/appliance build; Elixir coordination plane /
dashboard; sharding; accounting/quotas; any web UI. Resist all of these — the
health JSON + sim logs are the only observability MVP needs.

## Working style

- Wire-format changes are the expensive kind — flag them loudly in commits and
  record them in `WIRE-NOTES.md` from M1 on.
- Prefer boring code over clever code everywhere; this codebase's audience
  includes future auditors from small government IT shops.
- Version every endpoint path (`/ring/v0/...`) from the start.
- When a design question isn't answered by DESIGN.md or this file, make the
  simple choice, note it in `WIRE-NOTES.md`, and keep moving — the sim harness
  exists precisely to invalidate wrong guesses cheaply.
