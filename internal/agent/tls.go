package agent

import "net"

// TLSProvider wraps a plain TCP listener in TLS. The one production
// implementation lives in cmd/ring-agent (certmagic/ACME); tests and
// the simulation run plain HTTP. Deployment concern, not protocol:
// nothing in the wire formats changes when TLS is on.
type TLSProvider interface {
	Listener(inner net.Listener) (net.Listener, error)
}
