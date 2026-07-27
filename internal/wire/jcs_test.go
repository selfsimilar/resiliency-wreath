// Copyright 2026 The Resiliency Ring Authors
// SPDX-License-Identifier: Apache-2.0

package wire

import (
	"strings"
	"testing"
)

func mustCanonJSON(t *testing.T, raw string) string {
	t.Helper()
	b, err := CanonicalizeJSON([]byte(raw))
	if err != nil {
		t.Fatalf("CanonicalizeJSON(%q): %v", raw, err)
	}
	return string(b)
}

func TestJCSKeySorting(t *testing.T) {
	got := mustCanonJSON(t, `{"b":2,"a":1,"10":4,"1":3}`)
	want := `{"1":3,"10":4,"a":1,"b":2}`
	if got != want {
		t.Errorf("got %s want %s", got, want)
	}
}

// Property names sort by UTF-16 code units, not by UTF-8 bytes. U+1F600
// encodes as the surrogate pair D83D DE00, which sorts BEFORE U+FFFD
// (FFFD) in UTF-16 — the opposite of their UTF-8 byte order. This is the
// cross-implementation footgun the golden files exist to catch.
func TestJCSKeySortingUTF16(t *testing.T) {
	got := mustCanonJSON(t, "{\"�\":3,\"\U0001F600\":2,\"é\":1}")
	want := "{\"é\":1,\"\U0001F600\":2,\"�\":3}"
	if got != want {
		t.Errorf("got %s want %s", got, want)
	}
}

func TestJCSStringEscaping(t *testing.T) {
	// The input is a backtick literal, so the JSON parser receives the
	// escape sequences themselves, never raw control bytes. Mandatory +
	// short escapes stay escaped; other C0 controls become \u00xx with
	// lowercase hex; DEL (0x7f) is not a C0 control and passes through
	// as a literal byte.
	got := mustCanonJSON(t, `{"s":"a\"b\\c\nd\te`+"\\u0001"+`f`+"\\u007f"+`g"}`)
	want := `{"s":"a\"b\\c\nd\te` + "\\u0001" + `f` + "\x7f" + `g"}`
	if got != want {
		t.Errorf("got %q want %q", got, want)
	}
}

func TestJCSIntegers(t *testing.T) {
	got := mustCanonJSON(t, `{"max":9007199254740991,"min":-9007199254740991,"zero":0}`)
	want := `{"max":9007199254740991,"min":-9007199254740991,"zero":0}`
	if got != want {
		t.Errorf("got %s want %s", got, want)
	}
	for _, bad := range []string{`{"n":1.5}`, `{"n":9007199254740992}`, `{"n":1e2}`, `{"n":-9007199254740992}`} {
		if _, err := CanonicalizeJSON([]byte(bad)); err == nil {
			t.Errorf("CanonicalizeJSON(%s): want error, got none", bad)
		}
	}
}

func TestJCSLiteralsAndNesting(t *testing.T) {
	got := mustCanonJSON(t, `{ "z" : [ null , true , false , { } , [ ] ] , "a" : { "y" : 1 , "x" : 2 } }`)
	want := `{"a":{"x":2,"y":1},"z":[null,true,false,{},[]]}`
	if got != want {
		t.Errorf("got %s want %s", got, want)
	}
}

func TestJCSTrailingDataRejected(t *testing.T) {
	if _, err := CanonicalizeJSON([]byte(`{} {}`)); err == nil {
		t.Error("trailing data accepted")
	}
}

func TestJCSIdempotent(t *testing.T) {
	in := `{"b":[1,2,{"k":"v"}],"a":"` + "€ and \U0001F600" + `"}`
	once := mustCanonJSON(t, in)
	twice := mustCanonJSON(t, once)
	if once != twice {
		t.Errorf("not idempotent: %s vs %s", once, twice)
	}
}

func TestCanonicalizeStructMatchesJSONPath(t *testing.T) {
	m := map[string]any{"b": 1, "a": "x"}
	fromValue, err := Canonicalize(m)
	if err != nil {
		t.Fatal(err)
	}
	fromJSON := mustCanonJSON(t, `{"a":"x","b":1}`)
	if string(fromValue) != fromJSON {
		t.Errorf("value path %s != json path %s", fromValue, fromJSON)
	}
	if !strings.HasPrefix(string(fromValue), `{"a"`) {
		t.Errorf("unexpected canonical form %s", fromValue)
	}
}
