// Copyright 2026 The Resiliency Wreath Authors
// SPDX-License-Identifier: Apache-2.0

// Command wreath-publish is the publisher client: build, sign, verify, and
// push a member's bundle. See KICKOFF.md; the offline incident-signing
// tool is a deferred mode of this client, not a separate artifact.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/selfsimilar/resiliency-wreath/internal/bundle"
	"github.com/selfsimilar/resiliency-wreath/internal/keyfile"
	"github.com/selfsimilar/resiliency-wreath/internal/wire"
)

const usageText = `wreath-publish — build, sign, verify, and push wreath bundles

Subcommands:
  init             generate a member keypair
  build            build (and optionally sign) a bundle from a site directory
  sign             sign a built bundle
  verify           verify a bundle's signature and content hashes
  push             copy a signed bundle into an origin directory (+ notify agents)
  registry-sign    sign a registry payload with the registry root key
  registry-verify  verify a signed registry file

Run 'wreath-publish <subcommand> -h' for flags.
verify exit codes: 0 ok, 2 bad signature, 3 content hash mismatch, 1 other error.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usageText)
		os.Exit(1)
	}
	var err error
	switch os.Args[1] {
	case "init":
		err = cmdInit(os.Args[2:])
	case "build":
		err = cmdBuild(os.Args[2:])
	case "sign":
		err = cmdSign(os.Args[2:])
	case "verify":
		err = cmdVerify(os.Args[2:])
	case "push":
		err = cmdPush(os.Args[2:])
	case "registry-sign":
		err = cmdRegistrySign(os.Args[2:])
	case "registry-verify":
		err = cmdRegistryVerify(os.Args[2:])
	case "-h", "--help", "help":
		fmt.Print(usageText)
		return
	default:
		fmt.Fprintf(os.Stderr, "wreath-publish: unknown subcommand %q\n\n%s", os.Args[1], usageText)
		os.Exit(1)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "wreath-publish: %v\n", err)
		switch {
		case errors.Is(err, wire.ErrBadSignature):
			os.Exit(2)
		case errors.Is(err, wire.ErrHashMismatch):
			os.Exit(3)
		default:
			os.Exit(1)
		}
	}
}

func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	key := fs.String("key", "", "path for the new private key (public key lands at <path>.pub)")
	fs.Parse(args)
	if *key == "" {
		return errors.New("init: -key is required")
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	if err := keyfile.WritePair(*key, priv); err != nil {
		return err
	}
	fmt.Printf("wrote %s and %s.pub\npublic key: %s\n",
		*key, *key, wire.EncodePublicKey(priv.Public().(ed25519.PublicKey)))
	return nil
}

func metaFlag(fs *flag.FlagSet, meta map[string]string) {
	fs.Func("meta", "metadata entry key=value (repeatable)", func(s string) error {
		k, v, ok := strings.Cut(s, "=")
		if !ok || k == "" {
			return fmt.Errorf("want key=value, got %q", s)
		}
		meta[k] = v
		return nil
	})
}

// unsignedName holds a built-but-unsigned manifest payload inside a
// bundle dir; 'sign' consumes it and writes manifest.json.
const unsignedName = "manifest.unsigned.json"

func cmdBuild(args []string) error {
	fs := flag.NewFlagSet("build", flag.ExitOnError)
	dir := fs.String("dir", "", "site directory to bundle (required)")
	member := fs.String("member", "", "member id (required)")
	version := fs.Uint64("version", 0, "monotonic version, >= 1 (required)")
	out := fs.String("out", "", "output bundle directory (required)")
	key := fs.String("key", "", "private key file; if set, sign in the same step")
	meta := map[string]string{}
	metaFlag(fs, meta)
	fs.Parse(args)
	if *dir == "" || *member == "" || *out == "" {
		return errors.New("build: -dir, -member, and -out are required")
	}
	if *version < 1 {
		return errors.New("build: -version must be >= 1")
	}
	if len(meta) == 0 {
		meta = nil
	}
	m, blobs, err := bundle.Build(*dir, *member, *version, time.Now(), meta)
	if err != nil {
		return err
	}
	if *key != "" {
		priv, err := keyfile.LoadPrivate(*key)
		if err != nil {
			return err
		}
		sm, err := wire.SignManifest(m, priv)
		if err != nil {
			return err
		}
		env, err := wire.EncodeSignedManifest(sm)
		if err != nil {
			return err
		}
		if err := bundle.WriteDir(*out, env, blobs); err != nil {
			return err
		}
		fmt.Printf("built and signed %s v%d: %d files -> %s\n", m.MemberID, m.Version, len(m.Files), *out)
		return nil
	}
	// Unsigned build: write blobs + the bare payload for a later 'sign'.
	if err := os.MkdirAll(*out, 0o755); err != nil {
		return err
	}
	payload, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	if err := bundle.WriteDir(*out, nil, blobs); err != nil {
		return err
	}
	os.Remove(bundle.ManifestPath(*out)) // WriteDir wrote an empty manifest; not a valid envelope
	if err := os.WriteFile(filepath.Join(*out, unsignedName), append(payload, '\n'), 0o644); err != nil {
		return err
	}
	fmt.Printf("built %s v%d (unsigned): %d files -> %s\n", m.MemberID, m.Version, len(m.Files), *out)
	return nil
}

func cmdSign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	dir := fs.String("bundle", "", "bundle directory (required)")
	key := fs.String("key", "", "private key file (required)")
	fs.Parse(args)
	if *dir == "" || *key == "" {
		return errors.New("sign: -bundle and -key are required")
	}
	priv, err := keyfile.LoadPrivate(*key)
	if err != nil {
		return err
	}
	var m wire.Manifest
	unsignedPath := filepath.Join(*dir, unsignedName)
	if data, err := os.ReadFile(unsignedPath); err == nil {
		if err := json.Unmarshal(data, &m); err != nil {
			return fmt.Errorf("sign: parse %s: %w", unsignedPath, err)
		}
	} else {
		// Re-sign an already-signed bundle (e.g. after key rotation).
		data, err := bundle.ReadManifestBytes(*dir)
		if err != nil {
			return fmt.Errorf("sign: no %s and no manifest.json in %s", unsignedName, *dir)
		}
		var sm wire.SignedManifest
		if err := json.Unmarshal(data, &sm); err != nil {
			return err
		}
		m = sm.Manifest
	}
	sm, err := wire.SignManifest(&m, priv)
	if err != nil {
		return err
	}
	env, err := wire.EncodeSignedManifest(sm)
	if err != nil {
		return err
	}
	tmp := bundle.ManifestPath(*dir) + ".tmp"
	if err := os.WriteFile(tmp, env, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, bundle.ManifestPath(*dir)); err != nil {
		return err
	}
	os.Remove(unsignedPath)
	fmt.Printf("signed %s v%d\n", m.MemberID, m.Version)
	return nil
}

func loadPubFlag(pub, pubFile string) (ed25519.PublicKey, error) {
	switch {
	case pub != "":
		return wire.DecodePublicKey(pub)
	case pubFile != "":
		return keyfile.LoadPublic(pubFile)
	default:
		return nil, errors.New("need -pub <base64> or -pub-file <path>")
	}
}

func cmdVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	dir := fs.String("bundle", "", "bundle directory (required)")
	pub := fs.String("pub", "", "member public key, base64")
	pubFile := fs.String("pub-file", "", "member public key file")
	fs.Parse(args)
	if *dir == "" {
		return errors.New("verify: -bundle is required")
	}
	key, err := loadPubFlag(*pub, *pubFile)
	if err != nil {
		return fmt.Errorf("verify: %w", err)
	}
	m, err := bundle.VerifyDir(*dir, key)
	if err != nil {
		return err
	}
	fmt.Printf("OK: %s v%d, %d files, published %s\n", m.MemberID, m.Version, len(m.Files), m.Timestamp)
	return nil
}

func cmdPush(args []string) error {
	fs := flag.NewFlagSet("push", flag.ExitOnError)
	dir := fs.String("bundle", "", "signed bundle directory (required)")
	originDir := fs.String("origin-dir", "", "origin serving directory (required)")
	var notify []string
	fs.Func("notify", "agent base URL to poke after push (repeatable)", func(s string) error {
		notify = append(notify, strings.TrimRight(s, "/"))
		return nil
	})
	fs.Parse(args)
	if *dir == "" || *originDir == "" {
		return errors.New("push: -bundle and -origin-dir are required")
	}
	data, err := bundle.ReadManifestBytes(*dir)
	if err != nil {
		return fmt.Errorf("push: bundle is not signed yet? %w", err)
	}
	var sm wire.SignedManifest
	if err := json.Unmarshal(data, &sm); err != nil {
		return err
	}
	if err := sm.Manifest.Validate(); err != nil {
		return err
	}
	blobs := make(map[string][]byte, len(sm.Manifest.Files))
	for _, f := range sm.Manifest.Files {
		b, err := os.ReadFile(bundle.BlobPath(*dir, f.SHA256))
		if err != nil {
			return fmt.Errorf("push: %w", err)
		}
		blobs[f.SHA256] = b
	}
	if err := bundle.WriteDir(*originDir, data, blobs); err != nil {
		return err
	}
	fmt.Printf("pushed %s v%d to %s\n", sm.Manifest.MemberID, sm.Manifest.Version, *originDir)

	// Best-effort notify: correctness never depends on this arriving.
	body, _ := json.Marshal(map[string]string{"member_id": sm.Manifest.MemberID})
	client := &http.Client{Timeout: 5 * time.Second}
	for _, base := range notify {
		resp, err := client.Post(base+wire.NotifyPath, "application/json", bytes.NewReader(body))
		if err != nil {
			fmt.Fprintf(os.Stderr, "push: notify %s failed (non-fatal): %v\n", base, err)
			continue
		}
		resp.Body.Close()
		fmt.Printf("notified %s (%s)\n", base, resp.Status)
	}
	return nil
}

func cmdRegistrySign(args []string) error {
	fs := flag.NewFlagSet("registry-sign", flag.ExitOnError)
	in := fs.String("in", "", "unsigned registry payload JSON (required)")
	key := fs.String("key", "", "registry root private key file (required)")
	out := fs.String("out", "", "output signed registry file (required)")
	fs.Parse(args)
	if *in == "" || *key == "" || *out == "" {
		return errors.New("registry-sign: -in, -key, and -out are required")
	}
	data, err := os.ReadFile(*in)
	if err != nil {
		return err
	}
	var r wire.Registry
	if err := json.Unmarshal(data, &r); err != nil {
		return fmt.Errorf("registry-sign: parse %s: %w", *in, err)
	}
	priv, err := keyfile.LoadPrivate(*key)
	if err != nil {
		return err
	}
	sr, err := wire.SignRegistry(&r, priv)
	if err != nil {
		return err
	}
	env, err := wire.EncodeSignedRegistry(sr)
	if err != nil {
		return err
	}
	if err := os.WriteFile(*out, env, 0o644); err != nil {
		return err
	}
	fmt.Printf("signed registry %s v%d (%d members) -> %s\n", r.WreathID, r.Version, len(r.Members), *out)
	return nil
}

func cmdRegistryVerify(args []string) error {
	fs := flag.NewFlagSet("registry-verify", flag.ExitOnError)
	in := fs.String("in", "", "signed registry file (required)")
	pub := fs.String("pub", "", "registry root public key, base64")
	pubFile := fs.String("pub-file", "", "registry root public key file")
	fs.Parse(args)
	if *in == "" {
		return errors.New("registry-verify: -in is required")
	}
	key, err := loadPubFlag(*pub, *pubFile)
	if err != nil {
		return fmt.Errorf("registry-verify: %w", err)
	}
	data, err := os.ReadFile(*in)
	if err != nil {
		return err
	}
	r, err := wire.VerifyRegistryBytes(data, key)
	if err != nil {
		return err
	}
	fmt.Printf("OK: wreath %s v%d, %d members\n", r.WreathID, r.Version, len(r.Members))
	for _, m := range r.Members {
		fmt.Printf("  %-20s origin=%s agent=%s\n", m.ID, m.Origin, m.Agent)
	}
	return nil
}
