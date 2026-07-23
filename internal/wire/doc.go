// Package wire defines every data structure and byte format that crosses
// the network between ring participants: manifests, the registry, health
// reports, well-known URL paths, canonicalization, and signing.
//
// This package is the future RFC. Treat every exported type and constant
// as a wire-format commitment: changing one is a protocol change and must
// be recorded in WIRE-NOTES.md at the repository root.
//
// # What exactly is signed
//
// A signature never covers "JSON as it appeared on the wire". It covers
// the RFC 8785 (JSON Canonicalization Scheme) canonical form of the
// payload object alone — the value of the "manifest" or "registry" field,
// without its envelope. Verifiers MUST canonicalize the payload as parsed
// generically (preserving fields unknown to this implementation) and
// verify Ed25519 over those bytes; see VerifyManifestBytes. This makes
// on-the-wire whitespace, key order, and unknown-field additions
// irrelevant to signature validity.
//
// # Encodings
//
// Ed25519 public keys and signatures are standard base64 (RFC 4648, with
// padding). Content hashes are lowercase-hex SHA-256. Timestamps are
// RFC 3339 in UTC. The monotonic version number inside a signed payload
// is the only ordering authority; timestamps are informational.
package wire
