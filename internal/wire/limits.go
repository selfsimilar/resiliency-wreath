// Copyright 2026 The Resiliency Wreath Authors
// SPDX-License-Identifier: Apache-2.0

package wire

// Spec limits. Fetchers and verifiers enforce these before storing or
// serving anything; they exist so a malicious or broken publisher cannot
// exhaust a peer's disk or memory. Raising a limit is a wire-format
// change (record in WIRE-NOTES.md).
const (
	// MaxManifestBytes bounds the serialized signed-manifest document.
	MaxManifestBytes = 1 << 20 // 1 MiB

	// MaxFileCount bounds the number of files in one bundle.
	MaxFileCount = 1024

	// MaxBlobBytes bounds a single file body.
	MaxBlobBytes = 32 << 20 // 32 MiB

	// MaxBundleBytes bounds the sum of all file sizes in one bundle.
	MaxBundleBytes = 64 << 20 // 64 MiB

	// MaxRegistryMembers bounds the member list (full-mesh topology).
	MaxRegistryMembers = 512

	// MaxRegistryBytes bounds the serialized signed-registry document.
	MaxRegistryBytes = 4 << 20 // 4 MiB

	// MaxPathLen bounds one bundle file path.
	MaxPathLen = 512
)
