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
