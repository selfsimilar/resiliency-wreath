// Copyright 2026 The Resiliency Wreath Authors
// SPDX-License-Identifier: Apache-2.0

package sim

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/selfsimilar/resiliency-wreath/internal/serve"
	"github.com/selfsimilar/resiliency-wreath/internal/wire"
)

func originHandler(dir string) http.Handler { return serve.OriginHandler(dir) }

func jsonDecode(r io.Reader, v any) error { return json.NewDecoder(r).Decode(v) }

// RelayHandler builds a fake peer agent that serves exactly one signed
// envelope (and its blobs) for one member at the standard relay paths —
// the building block for malicious/stale peers in scenarios.
func RelayHandler(target string, envelope []byte, blobs map[string][]byte) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(wire.MemberManifestPath(target), func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(envelope)
	})
	blobPrefix := wire.MembersPrefix + target + "/blob/"
	mux.HandleFunc(blobPrefix, func(w http.ResponseWriter, r *http.Request) {
		hash := r.URL.Path[len(blobPrefix):]
		if data, ok := blobs[hash]; ok {
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Write(data)
			return
		}
		http.NotFound(w, r)
	})
	return mux
}
