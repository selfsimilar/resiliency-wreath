package wire

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"flag"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// Golden files pin the exact canonical bytes and signatures of fixture
// documents. Any refactor that changes wire bytes fails these tests
// loudly — that is their entire job. Regenerate deliberately with:
//
//	go test ./internal/wire -run Golden -update
//
// and record why in WIRE-NOTES.md, because a golden change IS a protocol
// change.
var update = flag.Bool("update", false, "rewrite golden files")

func bytesReader(b []byte) io.Reader { return bytes.NewReader(b) }

func goldenPath(name string) string {
	return filepath.Join("..", "..", "testdata", name)
}

func checkGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	p := goldenPath(name)
	if *update {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("missing golden file %s (run with -update once): %v", p, err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s: wire bytes changed!\ngot:  %s\nwant: %s\n"+
			"If intentional, this is a PROTOCOL CHANGE: rerun with -update and record it in WIRE-NOTES.md.",
			name, got, want)
	}
}

// goldenKey derives a deterministic keypair so signatures are stable.
// Test-only; never a pattern for production key generation.
func goldenKey(name string) (ed25519.PublicKey, ed25519.PrivateKey) {
	seed := sha256.Sum256([]byte("resiliency-ring golden key: " + name))
	priv := ed25519.NewKeyFromSeed(seed[:])
	return priv.Public().(ed25519.PublicKey), priv
}

func goldenManifest() *Manifest {
	return &Manifest{
		MemberID:  "member-x",
		Version:   3,
		Timestamp: "2026-07-23T00:00:00Z",
		Files: []FileEntry{
			{Path: "index.html", SHA256: hexHash("hello"), Size: 5},
			{Path: "assets/style.css", SHA256: hexHash("body{}"), Size: 6},
		},
		// Unicode on purpose: exercises JCS escaping + UTF-16 ordering.
		Metadata: map[string]string{
			"contact": "ops@example.org",
			"note":    "café ✓ naïve ☎",
			"😀":       "utf-16 sort probe",
		},
	}
}

func TestGoldenManifest(t *testing.T) {
	pub, priv := goldenKey("member-x")

	canon, err := Canonicalize(goldenManifest())
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "manifest-canonical.json", canon)

	sm, err := SignManifest(goldenManifest(), priv)
	if err != nil {
		t.Fatal(err)
	}
	env, err := EncodeSignedManifest(sm)
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "manifest-signed.json", env)

	// The committed envelope must verify with the committed key — this
	// is the cross-implementation conformance anchor.
	golden, err := os.ReadFile(goldenPath("manifest-signed.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyManifestBytes(golden, pub); err != nil {
		t.Fatalf("golden envelope does not verify: %v", err)
	}
}

func TestGoldenRegistry(t *testing.T) {
	rootPub, rootPriv := goldenKey("registry-root")
	pubA, _ := goldenKey("member-a")
	pubB, _ := goldenKey("member-b")

	reg := &Registry{
		RingID:    "golden-ring",
		Version:   2,
		Timestamp: "2026-07-23T00:00:00Z",
		Members: []Member{
			{ID: "member-a", PublicKey: EncodePublicKey(pubA), Origin: "http://127.0.0.1:7001", Agent: "http://127.0.0.1:8001"},
			{ID: "member-b", PublicKey: EncodePublicKey(pubB), Origin: "http://127.0.0.1:7002", Agent: "http://127.0.0.1:8002", FallbackHost: "fallback.member-b.example"},
		},
	}

	canon, err := Canonicalize(reg)
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "registry-canonical.json", canon)

	sr, err := SignRegistry(reg, rootPriv)
	if err != nil {
		t.Fatal(err)
	}
	env, err := EncodeSignedRegistry(sr)
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "registry-signed.json", env)

	golden, err := os.ReadFile(goldenPath("registry-signed.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyRegistryBytes(golden, rootPub); err != nil {
		t.Fatalf("golden registry does not verify: %v", err)
	}
}
