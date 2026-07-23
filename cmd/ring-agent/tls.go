package main

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net"

	"github.com/caddyserver/certmagic"
	"github.com/selfsimilar/resiliency-ring/internal/agent"
)

// certmagicTLS implements agent.TLSProvider with automatic Let's
// Encrypt certificates (TLS-ALPN-01 rides the agent's own listener;
// HTTP-01 additionally needs port 80 reachable). certmagic is the
// repo's ONLY third-party dependency and it is confined to this
// command — internal packages remain stdlib-only.
//
// Note (DESIGN §5 cert custody): obtaining certs for other members'
// fallback hostnames via delegated DNS-01 is part of the real-DNS
// milestone, deliberately out of MVP scope. This provider covers the
// agent's own names.
type certmagicTLS struct {
	domains []string
	email   string
	log     *slog.Logger
}

func newCertmagicTLS(domains []string, email string, log *slog.Logger) agent.TLSProvider {
	return &certmagicTLS{domains: domains, email: email, log: log}
}

func (c *certmagicTLS) Listener(inner net.Listener) (net.Listener, error) {
	certmagic.DefaultACME.Agreed = true
	certmagic.DefaultACME.Email = c.email
	magic := certmagic.NewDefault()
	// Async: certificates are obtained/renewed in the background so a
	// cold start with ACME trouble still brings the agent up (it can
	// relay and backfill over plain peers meanwhile).
	if err := magic.ManageAsync(context.Background(), c.domains); err != nil {
		return nil, err
	}
	cfg := magic.TLSConfig()
	cfg.NextProtos = append([]string{"h2", "http/1.1"}, cfg.NextProtos...)
	return tls.NewListener(inner, cfg), nil
}
