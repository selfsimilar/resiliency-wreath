// Copyright 2026 The Resiliency Wreath Authors
// SPDX-License-Identifier: Apache-2.0

package wire

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
)

// MaxSafeInteger is the largest integer exactly representable in an IEEE
// 754 double (2^53 - 1). RFC 8785 number formatting beyond integers in
// ±(2^53-1) is deliberately unsupported; see Canonicalize.
const MaxSafeInteger = 1<<53 - 1

// Canonicalize returns the RFC 8785 (JSON Canonicalization Scheme)
// serialization of v. v is first marshaled with encoding/json and then
// re-parsed generically, so any JSON-marshalable value works. These are
// the bytes an Ed25519 signature covers.
//
// Deliberate subset: JCS number serialization is implemented only for
// integers with absolute value <= 2^53-1. The wreath wire formats contain
// no non-integer numbers; encountering one is a hard error, never a
// silent approximation. String escaping, UTF-16 property ordering,
// arrays, objects, and literals are full RFC 8785.
func Canonicalize(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("wire: marshal before canonicalize: %w", err)
	}
	return CanonicalizeJSON(raw)
}

// CanonicalizeJSON canonicalizes an existing JSON document. Use this on
// received bytes (e.g. the json.RawMessage payload of an envelope) so
// that fields unknown to this implementation still count toward the
// signature.
func CanonicalizeJSON(raw []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("wire: parse before canonicalize: %w", err)
	}
	if dec.More() {
		return nil, errors.New("wire: trailing data after JSON value")
	}
	var buf bytes.Buffer
	if err := appendCanonical(&buf, doc); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func appendCanonical(buf *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if x {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case json.Number:
		s := x.String()
		if strings.ContainsAny(s, ".eE") {
			return fmt.Errorf("wire: non-integer JSON number %q (unsupported by wreath JCS subset)", s)
		}
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return fmt.Errorf("wire: parse number %q: %w", s, err)
		}
		if n > MaxSafeInteger || n < -MaxSafeInteger {
			return fmt.Errorf("wire: integer %d outside ±(2^53-1)", n)
		}
		buf.WriteString(strconv.FormatInt(n, 10))
	case string:
		appendJCSString(buf, x)
	case []any:
		buf.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := appendCanonical(buf, e); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return lessUTF16(keys[i], keys[j]) })
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			appendJCSString(buf, k)
			buf.WriteByte(':')
			if err := appendCanonical(buf, x[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("wire: cannot canonicalize value of type %T", v)
	}
	return nil
}

// lessUTF16 reports whether a sorts before b when both are viewed as
// sequences of UTF-16 code units (RFC 8785 §3.2.3 property ordering).
// This differs from Go's native byte order for supplementary-plane
// characters, which is exactly why it must be pinned here.
func lessUTF16(a, b string) bool {
	ua := utf16.Encode([]rune(a))
	ub := utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

// appendJCSString writes s as a JSON string with RFC 8785 §3.2.2.2
// escaping: the two mandatory escapes (quote, backslash), the five short
// control escapes, \u00xx with lowercase hex for the remaining C0
// controls, and literal UTF-8 for everything else.
func appendJCSString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(buf, `\u%04x`, r)
			} else {
				buf.WriteRune(r)
			}
		}
	}
	buf.WriteByte('"')
}
