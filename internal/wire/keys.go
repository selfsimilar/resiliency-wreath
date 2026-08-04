// Copyright 2026 The Resiliency Wreath Authors
// SPDX-License-Identifier: Apache-2.0

package wire

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
)

// Key and signature encodings are standard base64 (RFC 4648, with
// padding). A public key is the raw 32-byte Ed25519 public key; a
// signature is the raw 64-byte Ed25519 signature.

// EncodePublicKey renders a public key in its wire encoding.
func EncodePublicKey(pub ed25519.PublicKey) string {
	return base64.StdEncoding.EncodeToString(pub)
}

// DecodePublicKey parses the wire encoding of a public key.
func DecodePublicKey(s string) (ed25519.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("wire: public key is not valid base64: %w", err)
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("wire: public key is %d bytes, want %d", len(b), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(b), nil
}

// EncodeSignature renders a signature in its wire encoding.
func EncodeSignature(sig []byte) string {
	return base64.StdEncoding.EncodeToString(sig)
}

// DecodeSignature parses the wire encoding of a signature.
func DecodeSignature(s string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("wire: signature is not valid base64: %w", err)
	}
	if len(b) != ed25519.SignatureSize {
		return nil, fmt.Errorf("wire: signature is %d bytes, want %d", len(b), ed25519.SignatureSize)
	}
	return b, nil
}
