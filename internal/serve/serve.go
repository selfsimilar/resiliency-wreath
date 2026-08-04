// Copyright 2026 The Resiliency Wreath Authors
// SPDX-License-Identifier: Apache-2.0

// Package serve exposes an agent's HTTP surface (KICKOFF M2):
//
//   - relay endpoints under /.well-known/wreath/v0/members/<id>/... so
//     peers can backfill from this agent;
//   - the human-facing failover surface: /fallback/<id>/<path> and,
//     when the Host header matches a member's fallback_host, the
//     member's bundle at the URL root (the always-on fallback name);
//   - POST notify ("re-poll now" hint) and GET health (wired in M3).
//
// It also provides OriginHandler, the reference origin: a static
// mapping from the two origin well-known paths onto a bundle directory.
// Real members can replicate it with any web server config.
package serve

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"os"
	"path"
	"strings"
	"time"

	"github.com/selfsimilar/resiliency-wreath/internal/bundle"
	"github.com/selfsimilar/resiliency-wreath/internal/store"
	"github.com/selfsimilar/resiliency-wreath/internal/wire"
)

// Config wires the agent handler. Health may be nil until the prober
// exists; Notify may be nil to ignore pokes.
type Config struct {
	SelfID   string
	Store    *store.Store
	Registry func() *wire.Registry
	Health   func() *wire.HealthReport
	Notify   func(memberID string)
	Logger   *slog.Logger
}

// Handler builds the agent's HTTP handler.
func Handler(cfg Config) http.Handler {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	h := &agentHandler{cfg: cfg}
	return h
}

type agentHandler struct {
	cfg Config
}

func (h *agentHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Vhost check first: a request for a member's always-on fallback
	// hostname serves that member's bundle at the root.
	if id := h.fallbackHostMember(r); id != "" {
		h.serveBundleFile(w, r, id, r.URL.Path)
		return
	}
	p := r.URL.Path
	switch {
	case strings.HasPrefix(p, wire.MembersPrefix):
		h.serveRelay(w, r, strings.TrimPrefix(p, wire.MembersPrefix))
	case p == wire.HealthPath:
		h.serveHealth(w, r)
	case p == wire.NotifyPath:
		h.serveNotify(w, r)
	case strings.HasPrefix(p, "/fallback/"):
		rest := strings.TrimPrefix(p, "/fallback/")
		id, filePath, _ := strings.Cut(rest, "/")
		h.serveBundleFile(w, r, id, filePath)
	case p == "/":
		h.serveIndex(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (h *agentHandler) fallbackHostMember(r *http.Request) string {
	reg := h.cfg.Registry()
	if reg == nil {
		return ""
	}
	host := r.Host
	if hp, _, err := net.SplitHostPort(host); err == nil {
		host = hp
	}
	for _, m := range reg.Members {
		if m.FallbackHost != "" && strings.EqualFold(m.FallbackHost, host) {
			return m.ID
		}
	}
	return ""
}

// serveRelay handles members/<id>/manifest and members/<id>/blob/<hash>.
// Bytes are re-served exactly as stored — a relay never re-serializes,
// so signatures stay byte-stable across any number of hops.
func (h *agentHandler) serveRelay(w http.ResponseWriter, r *http.Request, rest string) {
	id, tail, ok := strings.Cut(rest, "/")
	if !ok || !wire.ValidMemberID(id) {
		http.NotFound(w, r)
		return
	}
	switch {
	case tail == "manifest":
		data, m, ok := h.cfg.Store.Manifest(id)
		if !ok {
			http.Error(w, "bundle not held", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Wreath-Member", id)
		w.Header().Set("Wreath-Version", fmt.Sprintf("%d", m.Version))
		w.Write(data)
	case strings.HasPrefix(tail, "blob/"):
		hash := strings.TrimPrefix(tail, "blob/")
		if !wire.ValidSHA256Hex(hash) {
			http.NotFound(w, r)
			return
		}
		p, ok := h.cfg.Store.BlobPath(id, hash)
		if !ok {
			http.Error(w, "blob not held", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		http.ServeFile(w, r, p)
	default:
		http.NotFound(w, r)
	}
}

// serveBundleFile serves one file of a held bundle to a human visitor —
// the failover surface. Empty or directory-ish paths resolve to
// index.html.
func (h *agentHandler) serveBundleFile(w http.ResponseWriter, r *http.Request, id, filePath string) {
	if !wire.ValidMemberID(id) {
		http.NotFound(w, r)
		return
	}
	_, m, ok := h.cfg.Store.Manifest(id)
	if !ok {
		http.Error(w, "no bundle held for "+id, http.StatusNotFound)
		return
	}
	filePath = strings.TrimPrefix(filePath, "/")
	if filePath == "" {
		filePath = "index.html"
	} else if strings.HasSuffix(filePath, "/") {
		filePath += "index.html"
	}
	entry := findFile(m, filePath)
	if entry == nil {
		// /fallback/member-a/docs -> docs/index.html convenience.
		entry = findFile(m, filePath+"/index.html")
	}
	if entry == nil {
		http.NotFound(w, r)
		return
	}
	p, ok := h.cfg.Store.BlobPath(id, entry.SHA256)
	if !ok {
		http.Error(w, "blob missing", http.StatusInternalServerError)
		return
	}
	f, err := os.Open(p)
	if err != nil {
		http.Error(w, "blob unreadable", http.StatusInternalServerError)
		return
	}
	defer f.Close()
	ctype := mime.TypeByExtension(path.Ext(entry.Path))
	if ctype == "" {
		ctype = "application/octet-stream"
	}
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Wreath-Member", id)
	w.Header().Set("Wreath-Version", fmt.Sprintf("%d", m.Version))
	w.Header().Set("Wreath-Holder", h.cfg.SelfID)
	mod, _ := time.Parse(time.RFC3339, m.Timestamp)
	http.ServeContent(w, r, entry.Path, mod, f)
}

func findFile(m *wire.Manifest, p string) *wire.FileEntry {
	for i := range m.Files {
		if m.Files[i].Path == p {
			return &m.Files[i]
		}
	}
	return nil
}

func (h *agentHandler) serveHealth(w http.ResponseWriter, r *http.Request) {
	if h.cfg.Health == nil {
		http.Error(w, "health not enabled", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(h.cfg.Health())
}

func (h *agentHandler) serveNotify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		MemberID string `json:"member_id"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body); err != nil || !wire.ValidMemberID(body.MemberID) {
		http.Error(w, "want {\"member_id\": \"...\"}", http.StatusBadRequest)
		return
	}
	if h.cfg.Notify != nil {
		h.cfg.Notify(body.MemberID)
	}
	w.WriteHeader(http.StatusAccepted)
}

// serveIndex is a one-line plaintext status for humans poking the agent
// directly. Deliberately not a web UI (KICKOFF: out of scope).
func (h *agentHandler) serveIndex(w http.ResponseWriter, _ *http.Request) {
	held := h.cfg.Store.Held()
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintf(w, "wreath agent %s: holding %d bundles\n", h.cfg.SelfID, len(held))
	for _, id := range held {
		fmt.Fprintf(w, "  /fallback/%s/ (v%d)\n", id, h.cfg.Store.Version(id))
	}
}

// OriginHandler is the reference origin: serves a bundle directory at
// the two origin well-known paths. Equivalent static-server config is
// all a real member needs.
func OriginHandler(dir string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == wire.OriginManifestPath:
			w.Header().Set("Content-Type", "application/json")
			http.ServeFile(w, r, bundle.ManifestPath(dir))
		case strings.HasPrefix(r.URL.Path, wire.OriginBlobPrefix):
			hash := strings.TrimPrefix(r.URL.Path, wire.OriginBlobPrefix)
			if !wire.ValidSHA256Hex(hash) {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/octet-stream")
			http.ServeFile(w, r, bundle.BlobPath(dir, hash))
		default:
			http.NotFound(w, r)
		}
	})
}
