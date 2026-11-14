// Command tcprelay relays TCP connections, bytes unchanged: for each
// LISTEN=TARGET argument it accepts on LISTEN and copies each
// connection to and from a fresh one to TARGET. TLS passes through it
// end to end, so the client still verifies the server's own
// certificate.
//
// interop/eudi/run-verifier.sh runs it in a container on
// interop/prodnet.sh's network, under the names OID4VCgo's issuer and
// Wallet Provider have there, relaying to them on the Docker host:
// they run there as a deployment's services, and the wallet, at
// production assurance, reaches them as public addresses. On Linux it
// also runs on the host, relaying the Wallet Provider, which listens on
// loopback, to the bridge's gateway, where that container reaches the
// host.
//
// Usage: tcprelay LISTEN=TARGET...
package main

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// dialTimeout bounds a connection to TARGET.
const dialTimeout = 10 * time.Second

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: tcprelay LISTEN=TARGET...")
		os.Exit(2)
	}
	errs := make(chan error, len(os.Args)-1)
	for _, arg := range os.Args[1:] {
		listen, target, ok := strings.Cut(arg, "=")
		if !ok || listen == "" || target == "" {
			log.Fatalf("tcprelay: %q isn't LISTEN=TARGET", arg) // #nosec G706 -- the operator's own argument, quoted
		}
		ln, err := net.Listen("tcp", listen)
		if err != nil {
			log.Fatalf("tcprelay: %v", err)
		}
		log.Printf("tcprelay: listening on %s, relaying to %s", listen, target) // #nosec G706 -- the operator's own arguments
		go func() { errs <- serve(ln, target) }()
	}
	log.Fatalf("tcprelay: %v", <-errs)
}

// serve relays each connection ln accepts to target.
func serve(ln net.Listener, target string) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go relay(c, target)
	}
}

// relay copies c to and from a connection to target until both
// directions end.
func relay(c net.Conn, target string) {
	defer func() { _ = c.Close() }()
	t, err := net.DialTimeout("tcp", target, dialTimeout) // #nosec G704 -- the operator's own target, the relay's whole job
	if err != nil {
		log.Printf("tcprelay: %s: %v", target, err) // #nosec G706 -- the operator's own target
		return
	}
	defer func() { _ = t.Close() }()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); pipe(t, c) }()
	go func() { defer wg.Done(); pipe(c, t) }()
	wg.Wait()
}

// pipe copies src to dst, then half-closes dst, so the other side reads
// the end of what src sent.
func pipe(dst, src net.Conn) {
	if _, err := io.Copy(dst, src); err != nil && !errors.Is(err, net.ErrClosed) {
		log.Printf("tcprelay: %v", err)
	}
	if tc, ok := dst.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
	}
}
