// Copyright 2026 The Resiliency Ring Authors
// SPDX-License-Identifier: Apache-2.0

package wire

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"strings"
	"time"
)

// FileEntry names one file in a bundle. Path is the URL path the file is
// served under (relative, slash-separated); SHA256 is the lowercase-hex
// hash of the file body, which is also the blob's content address.
type FileEntry struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// Manifest is the signed payload describing one member's bundle. The
// signature covers the JCS canonical form of exactly this object.
// Version is the only ordering authority (monotonic, 1..2^53-1);
// Timestamp is informational.
type Manifest struct {
	MemberID  string            `json:"member_id"`
	Version   uint64            `json:"version"`
	Timestamp string            `json:"timestamp"`
	Files     []FileEntry       `json:"files"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// SignedManifest is the envelope that travels on the wire:
// {"manifest": {...}, "signature": "<base64 ed25519>"}.
type SignedManifest struct {
	Manifest  Manifest `json:"manifest"`
	Signature string   `json:"signature"`
}

var memberIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// ValidMemberID reports whether id is a legal member identifier. Member
// IDs appear in URL paths and directory names, hence the tight charset.
func ValidMemberID(id string) bool { return memberIDRe.MatchString(id) }

var sha256HexRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// ValidSHA256Hex reports whether s is a lowercase-hex SHA-256 digest.
func ValidSHA256Hex(s string) bool { return sha256HexRe.MatchString(s) }

// ValidBundlePath reports whether p is a legal bundle file path: clean,
// relative, slash-separated, no "." / ".." segments, no backslashes, no
// control characters.
func ValidBundlePath(p string) bool {
	if p == "" || len(p) > MaxPathLen {
		return false
	}
	if strings.HasPrefix(p, "/") || strings.Contains(p, "\\") {
		return false
	}
	if path.Clean(p) != p {
		return false
	}
	for _, r := range p {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

// Validate checks structural validity. It does not check signatures.
func (m *Manifest) Validate() error {
	if !ValidMemberID(m.MemberID) {
		return fmt.Errorf("wire: invalid member_id %q", m.MemberID)
	}
	if m.Version < 1 || m.Version > MaxSafeInteger {
		return fmt.Errorf("wire: version %d outside 1..2^53-1", m.Version)
	}
	if _, err := time.Parse(time.RFC3339, m.Timestamp); err != nil {
		return fmt.Errorf("wire: timestamp %q is not RFC 3339: %w", m.Timestamp, err)
	}
	if len(m.Files) == 0 {
		return fmt.Errorf("wire: bundle has no files")
	}
	if len(m.Files) > MaxFileCount {
		return fmt.Errorf("wire: %d files exceeds limit %d", len(m.Files), MaxFileCount)
	}
	seen := make(map[string]bool, len(m.Files))
	var total int64
	for _, f := range m.Files {
		if !ValidBundlePath(f.Path) {
			return fmt.Errorf("wire: invalid bundle path %q", f.Path)
		}
		if seen[f.Path] {
			return fmt.Errorf("wire: duplicate bundle path %q", f.Path)
		}
		seen[f.Path] = true
		if !ValidSHA256Hex(f.SHA256) {
			return fmt.Errorf("wire: invalid sha256 for %q", f.Path)
		}
		if f.Size < 0 || f.Size > MaxBlobBytes {
			return fmt.Errorf("wire: size %d for %q outside 0..%d", f.Size, f.Path, int64(MaxBlobBytes))
		}
		total += f.Size
	}
	if total > MaxBundleBytes {
		return fmt.Errorf("wire: bundle totals %d bytes, limit %d", total, int64(MaxBundleBytes))
	}
	for k, v := range m.Metadata {
		if len(k) == 0 || len(k) > 128 || len(v) > 4096 {
			return fmt.Errorf("wire: metadata entry %q outside size limits", k)
		}
	}
	if len(m.Metadata) > 64 {
		return fmt.Errorf("wire: %d metadata entries exceeds limit 64", len(m.Metadata))
	}
	return nil
}

// SignManifest validates m, canonicalizes it, and signs the canonical
// bytes with priv.
func SignManifest(m *Manifest, priv ed25519.PrivateKey) (*SignedManifest, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	canon, err := Canonicalize(m)
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(priv, canon)
	return &SignedManifest{Manifest: *m, Signature: EncodeSignature(sig)}, nil
}

// Verify checks the signature of an in-memory SignedManifest. For bytes
// received over the network, use VerifyManifestBytes instead — it
// preserves fields this implementation doesn't know about.
func (sm *SignedManifest) Verify(pub ed25519.PublicKey) error {
	if err := sm.Manifest.Validate(); err != nil {
		return err
	}
	canon, err := Canonicalize(&sm.Manifest)
	if err != nil {
		return err
	}
	sig, err := DecodeSignature(sm.Signature)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, canon, sig) {
		return ErrBadSignature
	}
	return nil
}

// EncodeSignedManifest serializes the envelope for disk or wire. The
// output is pretty-printed for human auditors; the exact bytes are not
// signature-significant (verifiers re-canonicalize).
func EncodeSignedManifest(sm *SignedManifest) ([]byte, error) {
	b, err := json.MarshalIndent(sm, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// envelope is the generic parse used on received bytes: the payload stays
// a RawMessage so unknown fields count toward the signature.
type envelope struct {
	Manifest  json.RawMessage `json:"manifest"`
	Registry  json.RawMessage `json:"registry"`
	Signature string          `json:"signature"`
}

// VerifyManifestBytes parses a signed-manifest envelope, verifies the
// signature over the JCS canonical form of the generically-parsed
// payload, and returns the decoded manifest. This is THE verification
// path for anything received over the network.
func VerifyManifestBytes(data []byte, pub ed25519.PublicKey) (*Manifest, error) {
	if len(data) > MaxManifestBytes {
		return nil, fmt.Errorf("wire: manifest document %d bytes exceeds limit %d", len(data), MaxManifestBytes)
	}
	var env envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("wire: parse envelope: %w", err)
	}
	if len(env.Manifest) == 0 {
		return nil, fmt.Errorf("wire: envelope has no manifest field")
	}
	canon, err := CanonicalizeJSON(env.Manifest)
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
	var m Manifest
	if err := json.Unmarshal(env.Manifest, &m); err != nil {
		return nil, fmt.Errorf("wire: decode manifest: %w", err)
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return &m, nil
}
