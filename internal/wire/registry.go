package wire

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/url"
	"time"
)

// Member is one ring participant as listed in the registry.
//
// Origin is the base URL of the member's own site, which must expose the
// origin well-known paths (see paths.go). Agent is the base URL of the
// member's peer agent (relay + fallback surface); it may be empty for a
// member that publishes but does not (yet) host an agent. FallbackHost,
// if set, is the hostname (e.g. fallback.example.org) that agents
// recognize in the Host header to serve this member's bundle at the URL
// root — the always-on fallback surface from DESIGN §9.
type Member struct {
	ID           string `json:"id"`
	PublicKey    string `json:"public_key"`
	Origin       string `json:"origin"`
	Agent        string `json:"agent,omitempty"`
	FallbackHost string `json:"fallback_host,omitempty"`
}

// Registry is the signed payload listing the ring's membership: the thin
// "IX of the ring". It is distributed as a file, synced out-of-band
// (e.g. git); there is no registry server. Version is monotonic with the
// same semantics as a manifest version.
type Registry struct {
	RingID    string   `json:"ring_id"`
	Version   uint64   `json:"version"`
	Timestamp string   `json:"timestamp"`
	Members   []Member `json:"members"`
}

// SignedRegistry is the envelope: {"registry": {...}, "signature": "..."}.
type SignedRegistry struct {
	Registry  Registry `json:"registry"`
	Signature string   `json:"signature"`
}

func validBaseURL(s string) error {
	u, err := url.Parse(s)
	if err != nil {
		return err
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("must be absolute http(s) URL, got %q", s)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("must not carry query or fragment: %q", s)
	}
	return nil
}

// Validate checks structural validity. It does not check signatures.
func (r *Registry) Validate() error {
	if !ValidMemberID(r.RingID) {
		return fmt.Errorf("wire: invalid ring_id %q", r.RingID)
	}
	if r.Version < 1 || r.Version > MaxSafeInteger {
		return fmt.Errorf("wire: registry version %d outside 1..2^53-1", r.Version)
	}
	if _, err := time.Parse(time.RFC3339, r.Timestamp); err != nil {
		return fmt.Errorf("wire: registry timestamp %q is not RFC 3339: %w", r.Timestamp, err)
	}
	if len(r.Members) == 0 {
		return fmt.Errorf("wire: registry has no members")
	}
	if len(r.Members) > MaxRegistryMembers {
		return fmt.Errorf("wire: %d members exceeds limit %d", len(r.Members), MaxRegistryMembers)
	}
	seen := make(map[string]bool, len(r.Members))
	for _, m := range r.Members {
		if !ValidMemberID(m.ID) {
			return fmt.Errorf("wire: invalid member id %q", m.ID)
		}
		if seen[m.ID] {
			return fmt.Errorf("wire: duplicate member id %q", m.ID)
		}
		seen[m.ID] = true
		if _, err := DecodePublicKey(m.PublicKey); err != nil {
			return fmt.Errorf("wire: member %q: %w", m.ID, err)
		}
		if err := validBaseURL(m.Origin); err != nil {
			return fmt.Errorf("wire: member %q origin: %w", m.ID, err)
		}
		if m.Agent != "" {
			if err := validBaseURL(m.Agent); err != nil {
				return fmt.Errorf("wire: member %q agent: %w", m.ID, err)
			}
		}
	}
	return nil
}

// Member returns the member with the given ID, or nil.
func (r *Registry) Member(id string) *Member {
	for i := range r.Members {
		if r.Members[i].ID == id {
			return &r.Members[i]
		}
	}
	return nil
}

// MemberKey returns the decoded public key for a member ID, or an error
// if the member is unknown.
func (r *Registry) MemberKey(id string) (ed25519.PublicKey, error) {
	m := r.Member(id)
	if m == nil {
		return nil, fmt.Errorf("wire: unknown member %q", id)
	}
	return DecodePublicKey(m.PublicKey)
}

// SignRegistry validates r, canonicalizes it, and signs it with the
// registry root key.
func SignRegistry(r *Registry, priv ed25519.PrivateKey) (*SignedRegistry, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	canon, err := Canonicalize(r)
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(priv, canon)
	return &SignedRegistry{Registry: *r, Signature: EncodeSignature(sig)}, nil
}

// EncodeSignedRegistry serializes the envelope (pretty-printed; bytes not
// signature-significant).
func EncodeSignedRegistry(sr *SignedRegistry) ([]byte, error) {
	b, err := json.MarshalIndent(sr, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// VerifyRegistryBytes parses a signed-registry envelope, verifies the
// signature over the canonical form of the generically-parsed payload,
// and returns the decoded registry. THE verification path for registry
// files, which arrive out-of-band and must never be trusted on origin.
func VerifyRegistryBytes(data []byte, pub ed25519.PublicKey) (*Registry, error) {
	if len(data) > MaxRegistryBytes {
		return nil, fmt.Errorf("wire: registry document %d bytes exceeds limit %d", len(data), MaxRegistryBytes)
	}
	var env envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("wire: parse envelope: %w", err)
	}
	if len(env.Registry) == 0 {
		return nil, fmt.Errorf("wire: envelope has no registry field")
	}
	canon, err := CanonicalizeJSON(env.Registry)
	if err != nil {
		return nil, err
	}
	sig, err := DecodeSignature(env.Signature)
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(pub, canon, sig) {
		return nil, ErrBadSignature
	}
	var r Registry
	if err := json.Unmarshal(env.Registry, &r); err != nil {
		return nil, fmt.Errorf("wire: decode registry: %w", err)
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return &r, nil
}
