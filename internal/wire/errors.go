// Copyright 2026 The Resiliency Ring Authors
// SPDX-License-Identifier: Apache-2.0

package wire

import "errors"

// Sentinel errors. Callers distinguish tampering (ErrBadSignature,
// ErrHashMismatch) from structural invalidity; rollback rejection lives
// in the store layer (store.ErrRollback) because it depends on local
// state, not on the document itself.
var (
	// ErrBadSignature means the Ed25519 signature did not verify over
	// the canonicalized payload. Treat the document as forged.
	ErrBadSignature = errors.New("signature verification failed")

	// ErrHashMismatch means a file body did not hash to the SHA-256
	// value its manifest promised. Treat the blob as tampered.
	ErrHashMismatch = errors.New("content hash mismatch")
)
