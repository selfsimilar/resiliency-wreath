// Copyright 2026 The Resiliency Wreath Authors
// SPDX-License-Identifier: Apache-2.0

// Package bundle builds, writes, and verifies the on-disk bundle layout:
//
//	<dir>/manifest.json    signed manifest envelope
//	<dir>/blobs/<sha256>   content-addressed file bodies
//
// The layout is deliberately origin-servable by any static file server:
// the two origin well-known endpoints map 1:1 onto these paths (see
// wire/paths.go). Blobs are written before the manifest so the manifest
// is always the commit point — a reader that sees a manifest can fetch
// every blob it names.
package bundle

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/selfsimilar/resiliency-wreath/internal/wire"
)

// Build walks siteDir and produces a manifest plus content-addressed
// blob map. Hidden files (dot-prefixed) are skipped; symlinks are not
// followed. The manifest is unsigned; sign it with wire.SignManifest.
func Build(siteDir, memberID string, version uint64, now time.Time, metadata map[string]string) (*wire.Manifest, map[string][]byte, error) {
	m := &wire.Manifest{
		MemberID:  memberID,
		Version:   version,
		Timestamp: now.UTC().Format(time.RFC3339),
		Metadata:  metadata,
	}
	blobs := make(map[string][]byte)
	var total int64
	err := filepath.WalkDir(siteDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := d.Name()
		if strings.HasPrefix(name, ".") && p != siteDir {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(siteDir, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if !wire.ValidBundlePath(rel) {
			return fmt.Errorf("bundle: file %q has no legal bundle path", rel)
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if int64(len(data)) > wire.MaxBlobBytes {
			return fmt.Errorf("bundle: %q is %d bytes, limit %d", rel, len(data), int64(wire.MaxBlobBytes))
		}
		total += int64(len(data))
		if total > wire.MaxBundleBytes {
			return fmt.Errorf("bundle: total exceeds %d bytes", int64(wire.MaxBundleBytes))
		}
		sum := sha256.Sum256(data)
		hash := hex.EncodeToString(sum[:])
		m.Files = append(m.Files, wire.FileEntry{Path: rel, SHA256: hash, Size: int64(len(data))})
		blobs[hash] = data
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	if len(m.Files) > wire.MaxFileCount {
		return nil, nil, fmt.Errorf("bundle: %d files exceeds limit %d", len(m.Files), wire.MaxFileCount)
	}
	if err := m.Validate(); err != nil {
		return nil, nil, err
	}
	return m, blobs, nil
}

// WriteDir writes envelope + blobs in the standard layout. Blobs first,
// manifest last via atomic rename: the manifest is the commit point.
func WriteDir(dir string, envelope []byte, blobs map[string][]byte) error {
	blobDir := filepath.Join(dir, "blobs")
	if err := os.MkdirAll(blobDir, 0o755); err != nil {
		return err
	}
	for hash, data := range blobs {
		if !wire.ValidSHA256Hex(hash) {
			return fmt.Errorf("bundle: invalid blob hash %q", hash)
		}
		if err := os.WriteFile(filepath.Join(blobDir, hash), data, 0o644); err != nil {
			return err
		}
	}
	tmp := filepath.Join(dir, ".manifest.json.tmp")
	if err := os.WriteFile(tmp, envelope, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, "manifest.json"))
}

// ManifestPath returns the manifest location inside a bundle dir.
func ManifestPath(dir string) string { return filepath.Join(dir, "manifest.json") }

// BlobPath returns a blob location inside a bundle dir.
func BlobPath(dir, hash string) string { return filepath.Join(dir, "blobs", hash) }

// ReadManifestBytes reads the (size-capped) manifest envelope.
func ReadManifestBytes(dir string) ([]byte, error) {
	data, err := os.ReadFile(ManifestPath(dir))
	if err != nil {
		return nil, err
	}
	if len(data) > wire.MaxManifestBytes {
		return nil, fmt.Errorf("bundle: manifest %d bytes exceeds limit %d", len(data), wire.MaxManifestBytes)
	}
	return data, nil
}

// VerifyDir verifies the envelope signature and every blob hash and
// size. It returns the manifest on success. Signature failure surfaces
// wire.ErrBadSignature; a corrupt or missing blob surfaces
// wire.ErrHashMismatch — keep them distinguishable for callers.
func VerifyDir(dir string, pub ed25519.PublicKey) (*wire.Manifest, error) {
	data, err := ReadManifestBytes(dir)
	if err != nil {
		return nil, err
	}
	m, err := wire.VerifyManifestBytes(data, pub)
	if err != nil {
		return nil, err
	}
	for _, f := range m.Files {
		blob, err := os.ReadFile(BlobPath(dir, f.SHA256))
		if err != nil {
			return nil, fmt.Errorf("bundle: blob for %q: %w: %v", f.Path, wire.ErrHashMismatch, err)
		}
		if int64(len(blob)) != f.Size {
			return nil, fmt.Errorf("bundle: %q is %d bytes, manifest says %d: %w", f.Path, len(blob), f.Size, wire.ErrHashMismatch)
		}
		sum := sha256.Sum256(blob)
		if hex.EncodeToString(sum[:]) != f.SHA256 {
			return nil, fmt.Errorf("bundle: %q: %w", f.Path, wire.ErrHashMismatch)
		}
	}
	return m, nil
}
