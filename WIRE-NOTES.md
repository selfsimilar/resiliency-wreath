# WIRE-NOTES — running log of wire-format decisions

Every entry here is a protocol commitment or a change to one. The RFC will be
distilled from `internal/wire` plus this file. Newest entries at the bottom of
each section. Dates are UTC.

## M1 — bundle format, signing, verification (2026-07-23)

- **Signature scope.** Ed25519 over the RFC 8785 (JCS) canonical form of the
  *payload object alone* — the value of the `"manifest"` (or `"registry"`)
  field, without its envelope. Verifiers MUST canonicalize the payload as
  *generically parsed* JSON (preserving fields unknown to them), then verify.
  Consequence: on-wire whitespace/key order is irrelevant, and a future
  publisher may add fields without breaking verification by older readers.
- **JCS subset.** Number serialization implemented for integers with
  |n| ≤ 2^53−1 only; ring wire formats contain no non-integer numbers, and a
  float anywhere is a hard error, never an approximation. String escaping and
  UTF-16 property ordering are full RFC 8785.
- **Encodings.** Ed25519 keys and signatures: standard base64 (RFC 4648, with
  padding). Content hashes: lowercase-hex SHA-256. Timestamps: RFC 3339, UTC.
- **Envelope shape.** `{"manifest": {…}, "signature": "…"}`; the registry uses
  `{"registry": {…}, "signature": "…"}`. Serialized JSON may be
  pretty-printed; bytes on disk/wire are not signature-significant.
- **Ordering authority.** The monotonic `version` (1 … 2^53−1) inside the
  signed payload is the only ordering authority. `timestamp` is informational.
- **Limits** (spec constants, `internal/wire/limits.go`): manifest document
  ≤ 1 MiB; ≤ 1024 files per bundle; blob ≤ 32 MiB; bundle total ≤ 64 MiB;
  ≤ 512 registry members. Fetchers enforce these before storing.
- **Bundle layout** (chosen so an origin can serve it with any static file
  server): a directory containing `manifest.json` (signed envelope) and
  `blobs/<sha256>` (content-addressed file bodies). Origin endpoints map 1:1
  onto this layout:
  - `GET /.well-known/ring/v0/manifest` → `manifest.json`
  - `GET /.well-known/ring/v0/blob/<sha256>` → `blobs/<sha256>`
- **Member IDs** match `^[a-z0-9][a-z0-9-]{0,62}$` and appear in URL paths.
  Bundle file paths are clean, relative, slash-separated, no `..`, no `\`,
  no control characters.

## Format rationale — why JSON (2026-07-23)

Decided against protobuf / XML / CBOR for all signed wire documents:

- **Canonical form for signing is the deciding constraint.** JSON has
  RFC 8785 (JCS), small enough to implement auditable-y in stdlib Go.
  Protobuf serialization is documented as non-canonical across
  implementations (its docs warn against signing serialized protos);
  XML C14N/DSig is a historic source of signature-wrapping CVEs.
- **Conformance strategy needs a zero-toolchain format**: a second
  implementation (Elixir/Nerves) and county-built tooling must
  interoperate with no codegen, no schema distribution, no pinned
  runtime libs. `curl | less` is a conformance debugging tool.
- **Scale makes binary efficiency irrelevant**: manifests/registry are
  kilobytes at tens-of-seconds poll intervals; big payloads (blobs) are
  raw content-addressed octets outside the serialization format anyway.
- **Readability is operational**: signed registry lives in git —
  diffable, PR-reviewable; manifests are the audit artifact; TUF (whose
  threat model we reuse) also signs canonical JSON.
- **Honest runner-up for the RFC's alternatives section**: deterministic
  CBOR (RFC 8949 §4.2 / COSE) — solves canonicality in binary, loses on
  readability and implementer friction, saves bytes we don't need.

## M2 — store, poll, serve (2026-07-23)

- **Relay endpoints** (agent surface, per-member namespaced because one
  agent holds many bundles):
  `GET /.well-known/ring/v0/members/<id>/manifest` and
  `.../members/<id>/blob/<sha256>`. Relays re-serve manifest bytes
  **exactly as stored** — a relay never re-serializes, so envelopes stay
  byte-stable across hops (belt to the re-canonicalization suspenders).
- **Notify** (optional accelerator): `POST /.well-known/ring/v0/notify`
  with body `{"member_id": "<id>"}` → 202. Hint only; agents drop it
  when busy and correctness never depends on it.
- **Poll algorithm** (per member, per cycle): gather manifests from the
  member's origin AND every peer agent (including the member's own —
  a co-tenant agent can outlive its origin process); verify each; take
  the highest valid version; if it beats the stored version, fetch blobs
  with per-blob source fallback (content addressing makes any holder a
  valid source). This one rule yields both normal updates and
  origin-down backfill — there is no separate "backfill mode".
- **Anti-rollback is local state**: store rejects Put of version < held
  (`ErrRollback`, distinct from signature errors). Highest *seen* version
  (validly signed, from any source) is persisted separately and survives
  restarts; a wiped data dir legitimately resets both.
- **Failover surface**: `/fallback/<id>/<path>` on every agent, plus
  Host-header vhost: a request whose Host equals a member's registry
  `fallback_host` serves that member's bundle at the URL root. Responses
  carry `Ring-Member`, `Ring-Version`, `Ring-Holder` headers.
- **Registry reload semantics**: mtime-triggered, verify-then-swap,
  registry version anti-rollback; any failure keeps the previous
  registry in force (a broken out-of-band sync must not kill agents).

## M4 — kinks the simulation surfaced (2026-07-23)

- **Origin endpoints are additive, and the spec should say so.** The
  first client-walk test failed because the fake origin served ONLY the
  two well-known paths and 404'd `/`. Clarified model: a member origin
  is its existing website PLUS two static paths. That is the entire
  server-side onboarding footprint, worth stating verbatim in the RFC.
- **"Highest valid version across all sources" defeats replay even for
  cold caches.** A newcomer with no local anti-rollback state polls
  every source and takes the max valid version, so a replay peer
  serving genuine-but-old envelopes can never win — it can only tie
  with honest sources it fails to outbid. No first-seen-wins hazard
  exists in the pull rule; the RFC should keep highest-wins mandatory
  (a "first responder wins" optimization would reintroduce it).
- **Health reports are observer-local truth by design.** During a
  partition the two sides publish contradictory matrices and both are
  correct. The spec must define a health entry as "what this agent
  observed", never "ring consensus" — aggregation is a consumer
  concern (the future dashboard), not a protocol concern.
- **Forgery containment confirmed end-to-end**: a complete forged
  bundle (manifest + matching blobs) from a registry member is refused
  by every agent at manifest-verify time and surfaces as `invalid` in
  peers' health matrices; the blobs are never fetched.

## M5 — hardening (2026-07-23)

- **TLS is a deployment concern, not a wire concern.** Nothing in the
  formats changes when TLS is on; the agent takes a TLSProvider
  interface, and the certmagic/ACME implementation lives in
  cmd/ring-agent only. certmagic is the repository's sole third-party
  dependency and internal packages remain stdlib-only — keep it that
  way for auditability.
- **Cert custody (DESIGN §5) status:** the current provider covers the
  agent's OWN hostnames (TLS-ALPN-01 on its listener; HTTP-01 needs
  port 80). Serving *another member's* `fallback_host` over TLS
  requires the delegated DNS-01 flow (`_acme-challenge` CNAME) and is
  parked with the real-DNS milestone. Until then, cross-member vhost
  fallback is HTTP or fronted by the member's own proxy.
- **Agent config file** (JSON, flags override, unknown fields rejected
  loudly) is a local convention, not protocol. `ring-agent
  -example-config` prints the template.
- Graceful shutdown and structured logs (slog text/json) were in place
  since M2; M5 added the log-level/format switches.

## Golden fixture regeneration — domain-neutral naming (2026-07-26)

- Golden files under `testdata/` were regenerated (`go test ./internal/wire
  -run Golden -update`) after renaming fixture content to domain-neutral
  values (`county-x` → `member-x`, `county-a`/`county-b` → `member-a`/
  `member-b`, example contact/hostnames → `example.org`, and a new
  deterministic golden-key seed string). **No wire format changed** — no
  field names, encodings, envelope shapes, limits, or URL paths differ;
  only the fixture payloads (and therefore their canonical bytes,
  signatures, and derived test keys) are new.

## Proposed extensions — agreed direction, not yet commitments (2026-07-26)

Everything above this line is shipped and golden-pinned. Everything below
is design direction from post-MVP review, recorded together so the wire
implications stay coherent; each item becomes a commitment only when it
lands (with goldens and its own dated entry).

**Framing — four tiers of tunables**, distinguished by who decides and
where enforcement happens:

1. *Protocol constants* — compiled in: crypto suite, path grammar,
   envelope shapes, absolute ceilings.
2. *Ring policy* — signed into the registry, uniform per ring.
3. *Member declarations* — signed per-member registry fields.
4. *Node-local config* — unsigned, private behavior only.

Rule: anything one node enforces **against another** must live in a
signed tier; anything purely private must stay out of the registry so it
needs no ceremony to change.

### P1 — Origins are ring-agnostic; rings are overlays (invariant)

- A ring exists only as a registry. Manifests, bundles, and origin
  endpoints carry NO ring identity — never add a `ring_id` to the
  manifest. This is what makes multi-ring membership free: the same key
  and origin listed in several registries, one signed publish serving
  all of them. Version counters cannot conflict (one publisher).
- Daemon shape: a supervisor running one agent instance per ring (own
  registry, data dir, listener). Stores must never be shared across
  rings — member IDs are ring-scoped and collide. No wire change.

### P2 — Ring policy rides the registry

- Optional `limits` object in the registry payload (max blob/bundle
  bytes, file count, retention depth, replication factor, staleness
  tolerance). Absent = v0 constants, so old registries stay valid.
  Registry version monotonicity orders limit rollouts.
- Compiled absolute ceilings remain: a compromised governor set must not
  be able to declare resource-exhausting limits.
- Raising blob limits far past v0 requires the (non-wire) streaming
  work: stream-to-disk verify, Range/resume on immutable blobs, and
  cross-version blob reuse in fetch (currently re-downloads blobs it
  already holds — cheap fix, most of the delta-transfer win).

### P3 — Roles, capacity, selective holding

- Member entry gains `roles` (publisher, holder; both = v0 behavior).
  Publisher-only already exists (empty `agent`); holder-only makes
  `origin` optional — the "patron" case: a large host joining rings it
  is invited to, holding signed content it cannot alter.
- `capacity` pledge per member: storage bytes, egress, availability
  target. Probes already passively audit holding; the client walk
  reveals who answers; egress is unverifiable until the bad day.
- `holds`: explicit signed list of members held (absent = all). Ring
  policy sets `replication_factor` as the floor. Probe semantics must
  then split "missing" into not-obligated (fine) vs obligated-and-absent
  (reneging). The registry is the contract; the health matrix is the
  enforcement — there is deliberately no other.

### P4 — Governance: threshold-signed registry

- Envelope alternative: `{"registry": {…}, "signatures": [{"governor":
  …, "signature": …}, …]}`; verifiers require ≥ threshold from the
  governor set. The veto becomes arithmetic at signing time. There is
  still NO runtime consensus protocol — agents only ever verify a file.
- Governor set and threshold live in the registry itself; registry vN's
  set validates vN+1 (rotation is an ordinary signed update; the first
  threshold registry is validated by the last root-signed one).
- Admission (may this key publish into the ring) is ring-wide and
  threshold-gated. Obligation (must I hold them) is per-member via
  `holds` and unilaterally declinable — visible in the matrix, never
  punished by protocol.

### P5 — Steering documents (same-domain failover)

- New signed document at `/.well-known/ring/v0/steering/<id>`: desired
  DNS state, never imperative commands —
  `{"steering": {"member_id", "version" (monotonic), "timestamp",
  "state": "primary"|"failover", "records": […]}, "signature"}`.
  Desired-state + signature + monotonic version means connectors are
  dumb idempotent reconcilers, safely run in parallel, replay-proof.
- Pre-signed standing orders: the member signs BOTH record sets ahead of
  time plus a policy (watcher quorum, dwell, restore rules). At incident
  time, delegated watchers select which pre-signed set is current; the
  member's key stays offline during the emergency and no peer ever holds
  registrar credentials. Member entry gains `steering_key` and
  `watchers`.
- This makes watcher observations load-bearing and absorbs the "signed
  health gossip" open question: watcher attestations MUST be signed.
- Connectors: standalone pollers or exec plugins against the JSON;
  provider APIs stay out of the core. Registrar escape hatch: one manual
  CNAME into an API-capable zone (the acme-dns pattern). Cert custody:
  delegated DNS-01 (`_acme-challenge` CNAME) so designated holders keep
  live, auto-renewed certs for fallback names BEFORE the emergency; CAA
  (incl. RFC 8657 account binding) caps rogue issuance.
- Physics: TTL + probe interval + quorum dwell ≈ 2–5 min blackout floor.
  Standing multi-value A/HTTPS records are layer 0 and mask the window;
  split-brain guard = quorum across network-diverse watchers plus
  connector-side independent confirmation; restore slower than failover.

### P6 — Review gate and attestations

- Gate placement invariant: relay endpoints ALWAYS serve newest-verified
  (replication must never wait on humans); the fallback surface serves
  newest-APPROVED. Replicate eagerly, serve conservatively.
- Store: per member, `latest` (verified) and `serving` (approved)
  pointers; rejection writes a tombstone (version, manifest hash, blob
  hashes) and PURGES blobs — never re-served, never re-fetched, and
  because manifests arrive before blobs, an early flag suppresses the
  blob download entirely.
- The served promise becomes "last authentic version we vouched for."
  Health vocabulary gains `pending-review`; health entries gain
  serving_version / latest_version / review_status (preview link is
  derivable: holder agent + `/fallback/<id>/`). Holders legitimately
  serve different versions during review windows; `Ring-Version` already
  exposes this.
- Attestations: one signed document, two polarities — flag and vouch:
  `{"attestation": {"subject_member", "subject_version",
  "manifest_sha256", "blob_sha256"?, "polarity": "flag"|"vouch",
  "category", "note", "attester", "timestamp"}, "signature"}` (attester's
  member key). Gossiped pull-based over the relay like manifests.
- Flags are ADVISORY: they never mechanically reject anywhere — that
  would hand any member a censorship primitive. Each holder maps
  category→action locally (e.g. illegal-content flag from anyone →
  suppress fetch + quarantine pending review; dispute → annotate the
  queue). Attestations are attributable speech; false flagging is
  legible in the same matrix as everything else.
- Review transition policy is the tunable; the state machine is
  universal: strict (affirmative local review) / delegated (K trusted
  vouches, no flags) / dwell (auto-approve after T unless flagged) /
  open (v0 behavior). Ring policy may set a floor (`review_minimum`);
  the reviewer is a node-local interface (human, on-call rota, or
  automated) taking manifest + diff + flags → verdict. Category taxonomy
  is ring policy; category→action mapping is node-local.
- Review policy is per-SUBJECT, not global: each holder resolves
  (subject member → policy) from a node default plus overrides, so
  out-of-band knowledge ("personnel change at X") can tighten review
  for one member only. Rules: overrides may only tighten relative to
  the ring `review_minimum` floor, never loosen; overrides carry an
  expiry so temporary caution reverts by default instead of rotting
  into permanence. Escalations can also be automatic from in-band
  events — a key rotation for X in the registry IS a personnel-change
  signal (auto-strict for a window), a new member's first versions get
  probationary strict, a dispute flag puts its subject in temporary
  strict. Manual and automatic escalation are the same mechanism with
  different triggers. Entirely node-local; no wire change.

### P7 — Member directives: owner-initiated failover and freeze

- Completes the threat quadrant the rest of the design leaves open:
  origin ALIVE but hostile (defacement, hijacked hosting), where the
  legitimate owner wants to summon failover rather than wait for
  detection. Two sub-cases with different depths:
  - Attacker without the signing key: peers are already safe (the
    defacement cannot be signed; agents keep the last genuine version).
    The only gap is traffic steering — add a member-initiated trigger
    for the P5 failover state alongside the watcher-quorum trigger.
  - Attacker WITH the publishing key: they can publish validly-signed
    poison (P6 review gates are the existing brake). Requires a new
    primitive: an optional per-member `emergency_key` in the registry —
    held offline (management/board, or a mobile signer app) — that
    outranks the publishing key for exactly three verbs: FREEZE ("serve
    nothing newer than version N"), STEER (activate failover), REVOKE
    (fast-track publishing-key rotation to the governors). TUF-style
    role separation.
- Mechanism: a small signed "member directive" document — monotonic
  version, explicit TTL (a stale panic must expire, not stick), signed
  by the member key or the emergency key (emergency outranks). Injected
  via ANY reachable agent and gossiped like attestations: the injection
  point needs no trust, the signature carries it.
- Freeze composes with existing pieces: it is the P6 serving/latest
  pointer split operated by the SUBJECT rather than the holder, and P2
  retention depth is what guarantees a known-good version still exists
  to freeze onto.
- Bounded damage (state in the RFC): a stolen emergency key can only
  select among PREVIOUSLY SIGNED genuine versions and flip pre-signed
  steering states — worst case is mischievous rollback plus a DNS flip,
  never content forgery. Recovery is ordinary registry rotation.

## Open questions carried forward (for the RFC draft)

- Signed health gossip (v0 reports are unsigned observability).
- Registry rotation ceremony & threshold signing for the root key.
- Numeric defaults: poll 30s / probe 60s / staleness 5m are running
  defaults, not yet load-tested at N=100 members (probe traffic is
  O(N²) per cycle ring-wide; fine at civic scale, revisit if not).
- Notify authentication (currently unauthenticated hint; abuse = free
  extra polls, rate-limit if it matters).
