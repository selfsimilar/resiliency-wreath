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

## Open questions carried forward (for the RFC draft)

- Signed health gossip (v0 reports are unsigned observability).
- Registry rotation ceremony & threshold signing for the root key.
- Numeric defaults: poll 30s / probe 60s / staleness 5m are running
  defaults, not yet load-tested at N=100 members (probe traffic is
  O(N²) per cycle ring-wide; fine at civic scale, revisit if not).
- Notify authentication (currently unauthenticated hint; abuse = free
  extra polls, rate-limit if it matters).
