// Copyright 2026 The Resiliency Wreath Authors
// SPDX-License-Identifier: Apache-2.0

package wire

// Health report: the gossiped mesh-health signal (DESIGN §9). Reports
// are NOT signed in v0 — they are observability, not a security
// boundary; nothing in the protocol trusts a health report to accept
// content (only signatures on the content itself do that). Signing
// health gossip is an open question for v1.

// HealthStatus classifies one holder's copy of one member's bundle as
// observed by the reporting agent.
type HealthStatus string

const (
	// StatusHealthy: reachable, signature valid, version fresh.
	StatusHealthy HealthStatus = "healthy"
	// StatusStale: reachable and validly signed, but the version lags
	// the highest known version beyond the staleness tolerance.
	StatusStale HealthStatus = "stale"
	// StatusMissing: holder reachable but has no copy of this bundle.
	StatusMissing HealthStatus = "missing"
	// StatusInvalid: holder served bytes that fail verification
	// (tampered, forged, or garbage).
	StatusInvalid HealthStatus = "invalid"
	// StatusUnreachable: holder did not answer.
	StatusUnreachable HealthStatus = "unreachable"
)

// HealthEntry is one cell of the member × holder matrix. Holder is the
// member ID whose agent was probed; Version is 0 when no valid manifest
// was observed. Fresh means version ≥ the highest version the reporter
// knows, or within the staleness-tolerance grace window of it. LastSeen
// (RFC 3339) is the last time this holder answered validly for this
// member; empty if never.
type HealthEntry struct {
	Member   string       `json:"member"`
	Holder   string       `json:"holder"`
	Status   HealthStatus `json:"status"`
	Version  uint64       `json:"version"`
	Fresh    bool         `json:"fresh"`
	LastSeen string       `json:"last_seen,omitempty"`
	Detail   string       `json:"detail,omitempty"`
}

// HealthReport is served at /.well-known/wreath/v0/health. It is the
// reporting agent's own view; different agents legitimately see
// different matrices (e.g. during a partition).
type HealthReport struct {
	AgentID            string        `json:"agent_id"`
	GeneratedAt        string        `json:"generated_at"`
	StalenessTolerance string        `json:"staleness_tolerance"`
	Entries            []HealthEntry `json:"entries"`
}
