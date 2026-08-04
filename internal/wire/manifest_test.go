// Copyright 2026 The Resiliency Wreath Authors
// SPDX-License-Identifier: Apache-2.0

package wire

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"testing"
)

func testKey(t *testing.T, name string) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	seed := sha256.Sum256([]byte("test key: " + name))
	priv := ed25519.NewKeyFromSeed(seed[:])
	return priv.Public().(ed25519.PublicKey), priv
}

func fixtureManifest() *Manifest {
	return &Manifest{
		MemberID:  "member-x",
		Version:   3,
		Timestamp: "2026-07-23T00:00:00Z",
		Files: []FileEntry{
			{Path: "index.html", SHA256: hexHash("hello"), Size: 5},
			{Path: "assets/style.css", SHA256: hexHash("body{}"), Size: 6},
		},
		Metadata: map[string]string{"contact": "ops@example.org"},
	}
}

func hexHash(content string) string {
	h := sha256.Sum256([]byte(content))
	const hextable = "0123456789abcdef"
	out := make([]byte, 64)
	for i, b := range h {
		out[i*2] = hextable[b>>4]
		out[i*2+1] = hextable[b&0xf]
	}
	return string(out)
}

func TestManifestSignVerifyRoundTrip(t *testing.T) {
	pub, priv := testKey(t, "member-x")
	sm, err := SignManifest(fixtureManifest(), priv)
	if err != nil {
		t.Fatal(err)
	}
	data, err := EncodeSignedManifest(sm)
	if err != nil {
		t.Fatal(err)
	}
	m, err := VerifyManifestBytes(data, pub)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if m.MemberID != "member-x" || m.Version != 3 || len(m.Files) != 2 {
		t.Errorf("decoded manifest mangled: %+v", m)
	}
}

// Mutating any signed field must fail verification with ErrBadSignature.
func TestManifestTamperEveryField(t *testing.T) {
	pub, priv := testKey(t, "member-x")
	sm, err := SignManifest(fixtureManifest(), priv)
	if err != nil {
		t.Fatal(err)
	}

	mutations := []func(man map[string]any){
		func(m map[string]any) { m["member_id"] = "member-y" },
		func(m map[string]any) { m["version"] = json.Number("4") },
		func(m map[string]any) { m["timestamp"] = "2026-07-24T00:00:00Z" },
		func(m map[string]any) {
			f := m["files"].([]any)[0].(map[string]any)
			f["path"] = "evil.html"
		},
		func(m map[string]any) {
			f := m["files"].([]any)[0].(map[string]any)
			f["sha256"] = hexHash("evil")
		},
		func(m map[string]any) {
			f := m["files"].([]any)[0].(map[string]any)
			f["size"] = json.Number("6")
		},
		func(m map[string]any) {
			m["metadata"].(map[string]any)["contact"] = "evil@example.com"
		},
	}

	for i, mutate := range mutations {
		data, err := EncodeSignedManifest(sm)
		if err != nil {
			t.Fatal(err)
		}
		var env map[string]any
		dec := json.NewDecoder(bytesReader(data))
		dec.UseNumber()
		if err := dec.Decode(&env); err != nil {
			t.Fatal(err)
		}
		mutate(env["manifest"].(map[string]any))
		tampered, err := json.Marshal(env)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyManifestBytes(tampered, pub); !errors.Is(err, ErrBadSignature) {
			t.Errorf("mutation %d: want ErrBadSignature, got %v", i, err)
		}
	}
}

func TestManifestWrongKeyRejected(t *testing.T) {
	_, priv := testKey(t, "member-x")
	otherPub, _ := testKey(t, "member-y")
	sm, err := SignManifest(fixtureManifest(), priv)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := EncodeSignedManifest(sm)
	if _, err := VerifyManifestBytes(data, otherPub); !errors.Is(err, ErrBadSignature) {
		t.Errorf("want ErrBadSignature, got %v", err)
	}
}

// A publisher may add fields this implementation doesn't know about;
// they count toward the signature (generic canonicalization) and
// verification still succeeds.
func TestManifestUnknownFieldForwardCompat(t *testing.T) {
	pub, priv := testKey(t, "member-x")
	man := map[string]any{
		"member_id": "member-x",
		"version":   1,
		"timestamp": "2026-07-23T00:00:00Z",
		"files": []any{
			map[string]any{"path": "index.html", "sha256": hexHash("hi"), "size": 2},
		},
		"x_future_extension": "from a v0.2 publisher",
	}
	canon, err := Canonicalize(man)
	if err != nil {
		t.Fatal(err)
	}
	env := map[string]any{
		"manifest":  man,
		"signature": EncodeSignature(ed25519.Sign(priv, canon)),
	}
	data, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	m, err := VerifyManifestBytes(data, pub)
	if err != nil {
		t.Fatalf("unknown field broke verification: %v", err)
	}
	if m.Version != 1 {
		t.Errorf("decoded version %d", m.Version)
	}
}

func TestManifestValidateRejects(t *testing.T) {
	good := fixtureManifest()
	cases := []struct {
		name   string
		mutate func(*Manifest)
	}{
		{"bad member id", func(m *Manifest) { m.MemberID = "Member X" }},
		{"zero version", func(m *Manifest) { m.Version = 0 }},
		{"huge version", func(m *Manifest) { m.Version = 1 << 60 }},
		{"bad timestamp", func(m *Manifest) { m.Timestamp = "yesterday" }},
		{"no files", func(m *Manifest) { m.Files = nil }},
		{"dotdot path", func(m *Manifest) { m.Files[0].Path = "../escape.html" }},
		{"absolute path", func(m *Manifest) { m.Files[0].Path = "/etc/passwd" }},
		{"unclean path", func(m *Manifest) { m.Files[0].Path = "a//b.html" }},
		{"backslash path", func(m *Manifest) { m.Files[0].Path = `a\b.html` }},
		{"dup path", func(m *Manifest) { m.Files[1].Path = m.Files[0].Path }},
		{"bad hash", func(m *Manifest) { m.Files[0].SHA256 = "XYZ" }},
		{"negative size", func(m *Manifest) { m.Files[0].Size = -1 }},
	}
	for _, tc := range cases {
		m := *good
		m.Files = append([]FileEntry(nil), good.Files...)
		tc.mutate(&m)
		if err := m.Validate(); err == nil {
			t.Errorf("%s: validation passed, want error", tc.name)
		}
	}
	if err := good.Validate(); err != nil {
		t.Errorf("fixture should validate: %v", err)
	}
}

func fixtureRegistry(t *testing.T) *Registry {
	pubA, _ := testKey(t, "member-a")
	pubB, _ := testKey(t, "member-b")
	return &Registry{
		WreathID:  "test-wreath",
		Version:   1,
		Timestamp: "2026-07-23T00:00:00Z",
		Members: []Member{
			{ID: "member-a", PublicKey: EncodePublicKey(pubA), Origin: "http://127.0.0.1:7001", Agent: "http://127.0.0.1:8001"},
			{ID: "member-b", PublicKey: EncodePublicKey(pubB), Origin: "http://127.0.0.1:7002", Agent: "http://127.0.0.1:8002", FallbackHost: "fallback.member-b.example"},
		},
	}
}

func TestRegistrySignVerifyRoundTrip(t *testing.T) {
	rootPub, rootPriv := testKey(t, "registry-root")
	sr, err := SignRegistry(fixtureRegistry(t), rootPriv)
	if err != nil {
		t.Fatal(err)
	}
	data, err := EncodeSignedRegistry(sr)
	if err != nil {
		t.Fatal(err)
	}
	r, err := VerifyRegistryBytes(data, rootPub)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Members) != 2 || r.Member("member-b").FallbackHost == "" {
		t.Errorf("registry mangled: %+v", r)
	}
	if _, err := r.MemberKey("member-a"); err != nil {
		t.Error(err)
	}
	if _, err := r.MemberKey("nobody"); err == nil {
		t.Error("unknown member lookup should fail")
	}
}

func TestRegistryTamperRejected(t *testing.T) {
	rootPub, rootPriv := testKey(t, "registry-root")
	evilPub, _ := testKey(t, "evil")
	sr, err := SignRegistry(fixtureRegistry(t), rootPriv)
	if err != nil {
		t.Fatal(err)
	}
	sr.Registry.Members[0].PublicKey = EncodePublicKey(evilPub)
	data, _ := EncodeSignedRegistry(sr)
	if _, err := VerifyRegistryBytes(data, rootPub); !errors.Is(err, ErrBadSignature) {
		t.Errorf("want ErrBadSignature, got %v", err)
	}
}

func TestRegistryValidateRejects(t *testing.T) {
	rootPriv2 := func() ed25519.PrivateKey { _, p := testKey(t, "registry-root"); return p }()
	r := fixtureRegistry(t)
	r.Members[1].ID = r.Members[0].ID
	if _, err := SignRegistry(r, rootPriv2); err == nil {
		t.Error("duplicate member ids accepted")
	}
	r = fixtureRegistry(t)
	r.Members[0].Origin = "not a url"
	if _, err := SignRegistry(r, rootPriv2); err == nil {
		t.Error("bad origin accepted")
	}
}
