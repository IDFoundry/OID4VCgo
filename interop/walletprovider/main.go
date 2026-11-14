// Command walletprovider runs OID4VCgo's Wallet Provider
// (walletprovider.Provider) for the interop runs, as a deployment runs
// it: its Handler (the v1 protocol) and StatusLists served over HTTPS,
// its instances, instance keys, challenges, status list indices and
// signed tokens in sealed sqlstore stores in a SQLite file,
// RequireSealedStore set, and its attestations signed under a CA it
// makes for the run. Only the platform evidence is a stand-in:
// walletprovidertest.FakeVerifier, as a run has no device. Its stores
// are sqlstore's, a module of its own, so it builds only with the
// conformance_production tag in a workspace holding both modules
// (interop/production.sh's build_production).
//
//	walletprovider -dir DIR -addr 127.0.0.1:PORT -base-url https://localhost:PORT -client-id ID -admin 127.0.0.1:PORT
//
// writes DIR/ca.pem (the attestation signer's CA, an issuer's trust
// anchor for both attestations) and DIR/tls-cert.pem (its TLS
// certificate, self-signed), then serves. Its admin listener, plain
// HTTP on loopback, takes POST /revoke, which revokes every registered
// instance (Provider.RevokeWhere), so that every attestation it issued
// reads INVALID on its status list: a control's revocation.
//
//	walletprovider agent -provider https://localhost:PORT -tls-cert DIR/tls-cert.pem -addr 127.0.0.1:PORT
//
// is the wallet's side for a wallet that isn't written in Go (the EUDI
// issuance driver): it registers one instance (interop/internal/interopwp)
// and serves, over plain HTTP on loopback, POST /wallet-attestation
// {"client_id", "instance_key"} and POST /key-attestation
// {"instance_key", "keys", "nonce"}, the keys public JWKs, each
// answering {"jwt"}, as the Swift and Kotlin libraries'
// HttpWalletProvider does on a device.
package main

import (
	"fmt"
	"net"
	"os"
)

func main() {
	var err error
	if len(os.Args) > 1 && os.Args[1] == "agent" {
		err = runAgent(os.Args[2:])
	} else {
		err = runProvider(os.Args[1:])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "walletprovider:", err)
		os.Exit(1)
	}
}

// loopback checks addr, a listener's host:port, is a loopback IP
// address: what it listens on answers anyone who reaches it.
func loopback(name, addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("-%s: %w", name, err)
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("-%s must be a loopback IP address and port, not %q", name, addr)
	}
	return nil
}
