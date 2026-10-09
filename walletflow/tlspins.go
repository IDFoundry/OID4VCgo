package walletflow

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strings"
)

// ErrTLSPinMismatch is the error of a request to a pinned host whose
// verified certificate chains hold none of its pins.
var ErrTLSPinMismatch = errors.New("walletflow: the server's certificate matches none of its TLS pins")

// TLSPins pins hosts to public keys: host → base64 SHA-256 digests of
// a certificate's SubjectPublicKeyInfo, as HTTP Public Key Pinning
// wrote them. A host is a name, matched exactly and without case, or
// "*." and a name, matching any name one label below it (not the name
// itself); not an IP address, since a handshake to one names no host
// (no SNI) to match. A request to a pinned host succeeds only when a
// certificate in a chain that verified holds one of the host's pins, so
// a pin adds to certificate verification rather than replacing it: pin
// a CA's key to survive leaf renewals, and keep a backup pin. Hosts
// without pins are verified as before.
type TLSPins map[string][]string

// Validate reports whether every host and pin is well formed: a host
// name, not an IP address, with at most one leading "*.", and at least
// one pin, each 32 bytes in base64.
func (p TLSPins) Validate() error {
	for host, pins := range p {
		name := strings.TrimPrefix(host, "*.")
		if name == "" || strings.ContainsAny(name, "*/: ") || strings.HasPrefix(name, ".") || strings.HasSuffix(name, ".") {
			return fmt.Errorf("walletflow: TLS pins: host %q isn't a host name, or *. and one", host)
		}
		if net.ParseIP(name) != nil {
			return fmt.Errorf("walletflow: TLS pins: host %q is an IP address, which a handshake doesn't name: pin a host name", host)
		}
		if len(pins) == 0 {
			return fmt.Errorf("walletflow: TLS pins: host %q has no pins", host)
		}
		for _, pin := range pins {
			if b, err := base64.StdEncoding.DecodeString(pin); err != nil || len(b) != sha256.Size {
				return fmt.Errorf("walletflow: TLS pins: host %q: %q isn't a base64 SHA-256 digest", host, pin)
			}
		}
	}
	return nil
}

// pinsFor returns host's pins: its own entry, else its parent's "*."
// one.
func (p TLSPins) pinsFor(host string) []string {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for h, pins := range p {
		if strings.EqualFold(h, host) {
			return pins
		}
	}
	if _, parent, ok := strings.Cut(host, "."); ok {
		for h, pins := range p {
			if strings.EqualFold(h, "*."+parent) {
				return pins
			}
		}
	}
	return nil
}

// VerifyConnection is a tls.Config VerifyConnection that checks a
// handshake's verified chains against the pins of the host it was
// made for (ConnectionState.ServerName). It fails with
// ErrTLSPinMismatch, and for a pinned host when no chain verified.
func (p TLSPins) VerifyConnection(cs tls.ConnectionState) error {
	pins := p.pinsFor(cs.ServerName)
	if len(pins) == 0 {
		return nil
	}
	for _, chain := range cs.VerifiedChains {
		for _, cert := range chain {
			sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
			got := base64.StdEncoding.EncodeToString(sum[:])
			for _, pin := range pins {
				if pin == got {
					return nil
				}
			}
		}
	}
	return fmt.Errorf("%w (%s)", ErrTLSPinMismatch, cs.ServerName)
}
