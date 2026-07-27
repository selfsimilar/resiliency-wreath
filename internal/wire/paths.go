// Copyright 2026 The Resiliency Ring Authors
// SPDX-License-Identifier: Apache-2.0

package wire

// Well-known URL paths. Every endpoint is versioned under /ring/v0 from
// the start; a breaking wire change bumps the path version.
//
// Origins expose exactly two paths, chosen to map 1:1 onto the on-disk
// bundle layout (manifest.json + blobs/<sha256>) so a member can serve
// its bundle with any static file server:
//
//	GET /.well-known/ring/v0/manifest      → the signed manifest envelope
//	GET /.well-known/ring/v0/blob/<sha256> → a file body, content-addressed
//
// Agents relay every member's bundle under a per-member prefix, and add
// health + notify:
//
//	GET  /.well-known/ring/v0/members/<id>/manifest
//	GET  /.well-known/ring/v0/members/<id>/blob/<sha256>
//	GET  /.well-known/ring/v0/health
//	POST /.well-known/ring/v0/notify       {"member_id": "..."}
const (
	WellKnownPrefix = "/.well-known/ring/v0"

	OriginManifestPath = WellKnownPrefix + "/manifest"
	OriginBlobPrefix   = WellKnownPrefix + "/blob/"

	MembersPrefix = WellKnownPrefix + "/members/"

	HealthPath = WellKnownPrefix + "/health"
	NotifyPath = WellKnownPrefix + "/notify"
)

// OriginBlobPath returns the origin URL path for a blob.
func OriginBlobPath(sha256hex string) string {
	return OriginBlobPrefix + sha256hex
}

// MemberManifestPath returns the agent relay URL path for a member's
// signed manifest.
func MemberManifestPath(memberID string) string {
	return MembersPrefix + memberID + "/manifest"
}

// MemberBlobPath returns the agent relay URL path for a member's blob.
func MemberBlobPath(memberID, sha256hex string) string {
	return MembersPrefix + memberID + "/blob/" + sha256hex
}
