// Package registry loads and watches the signed registry file — the
// thin "IX of the ring" (DESIGN §6). The file is synced out-of-band
// (git, rsync, USB stick; the protocol does not care) and verified
// against the registry root public key on every load. Registry versions
// are monotonic: a reload that presents a LOWER version than the one in
// memory is rejected — an attacker who steals yesterday's registry file
// cannot un-rotate a member's key by re-serving it.
package registry

import (
	"crypto/ed25519"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/selfsimilar/resiliency-ring/internal/wire"
)

// Watcher holds the currently-valid registry and reloads the backing
// file when its mtime changes. Safe for concurrent use.
type Watcher struct {
	path string
	pub  ed25519.PublicKey
	log  *slog.Logger

	mu    sync.RWMutex
	reg   *wire.Registry
	mtime time.Time
}

// Open reads, verifies, and pins the registry file. Unlike Reload, a
// failure here is fatal: an agent must never start without a valid
// registry (it would have no keys to verify anything against).
func Open(path string, pub ed25519.PublicKey, log *slog.Logger) (*Watcher, error) {
	if log == nil {
		log = slog.Default()
	}
	w := &Watcher{path: path, pub: pub, log: log}
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	reg, err := w.load()
	if err != nil {
		return nil, err
	}
	w.reg = reg
	w.mtime = fi.ModTime()
	return w, nil
}

func (w *Watcher) load() (*wire.Registry, error) {
	data, err := os.ReadFile(w.path)
	if err != nil {
		return nil, err
	}
	reg, err := wire.VerifyRegistryBytes(data, w.pub)
	if err != nil {
		return nil, fmt.Errorf("registry %s: %w", w.path, err)
	}
	return reg, nil
}

// Current returns the last known-good registry.
func (w *Watcher) Current() *wire.Registry {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.reg
}

// Reload re-reads the file if its mtime changed. Any failure —
// unreadable file, bad signature, version rollback — keeps the previous
// registry in force and returns the error; a broken sync must never
// take a working agent down.
func (w *Watcher) Reload() error {
	fi, err := os.Stat(w.path)
	if err != nil {
		return err
	}
	w.mu.RLock()
	unchanged := fi.ModTime().Equal(w.mtime)
	w.mu.RUnlock()
	if unchanged {
		return nil
	}
	reg, err := w.load()
	if err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if reg.Version < w.reg.Version {
		return fmt.Errorf("registry %s: version rollback v%d -> v%d rejected", w.path, w.reg.Version, reg.Version)
	}
	if reg.Version > w.reg.Version {
		w.log.Info("registry: updated", "ring", reg.RingID, "version", reg.Version, "members", len(reg.Members))
	}
	w.reg = reg
	w.mtime = fi.ModTime()
	return nil
}
