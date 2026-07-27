// Copyright 2026 The Resiliency Ring Authors
// SPDX-License-Identifier: Apache-2.0

// Package keyfile reads and writes Ed25519 key files. Local formats,
// not wire formats: a private key file is one line of standard base64
// holding the 32-byte seed (mode 0600); a public key file is one line of
// standard base64 holding the 32-byte public key.
package keyfile

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"github.com/selfsimilar/resiliency-ring/internal/wire"
)

// WritePair writes priv's seed to path (0600) and the public key to
// path+".pub" (0644). It refuses to overwrite an existing private key.
func WritePair(path string, priv ed25519.PrivateKey) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("keyfile: %s already exists; refusing to overwrite a private key", path)
	}
	seed := base64.StdEncoding.EncodeToString(priv.Seed())
	if err := os.WriteFile(path, []byte(seed+"\n"), 0o600); err != nil {
		return err
	}
	pub := wire.EncodePublicKey(priv.Public().(ed25519.PublicKey))
	return os.WriteFile(path+".pub", []byte(pub+"\n"), 0o644)
}

// LoadPrivate reads a private key file written by WritePair.
func LoadPrivate(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		return nil, fmt.Errorf("keyfile: %s is not valid base64: %w", path, err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("keyfile: %s holds %d bytes, want %d-byte seed", path, len(seed), ed25519.SeedSize)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// LoadPublic reads a public key from a file written by WritePair.
func LoadPublic(path string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return wire.DecodePublicKey(strings.TrimSpace(string(data)))
}
