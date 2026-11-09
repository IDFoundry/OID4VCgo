// Command wallet is OID4VCgo's wallet for interop/waltid/run.sh, on
// walletflow at development assurance: it redeems each of walt.id
// Issuer2's pre-authorized code offers (-offer, repeatable), checking
// each credential as walletflow does, its issuer's chain to
// -issuer-ca among them; then, with -request, answers walt.id
// Verifier2's request with them, trusting Verifiers whose Access
// Certificate chains to -verifier-ca.
//
// The parties' TLS certificates chain to -tls-ca; -resolve HOST=ADDR,
// if given, dials ADDR for HOST.
//
// The result, written to -out as JSON, says how far the run got and
// what it saw; run.sh decides whether that's what the case expects.
//
// Usage: go run ./interop/waltid/scripts/wallet -tls-ca FILE -issuer-ca FILE -verifier-ca FILE [-resolve HOST=ADDR] -offer URL [-request URL] -out FILE
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/idfoundry/oid4vcgo/wallet"
	"github.com/idfoundry/oid4vcgo/walletflow"
)

// offers is the repeated -offer flag.
type offers []string

func (o *offers) String() string     { return strings.Join(*o, " ") }
func (o *offers) Set(v string) error { *o = append(*o, v); return nil }

// result is what the run saw: Stage is the last step reached ("done"
// when every step succeeded), Error why the next failed.
type result struct {
	Stage    string     `json:"stage"`
	Error    string     `json:"error,omitempty"`
	Received []received `json:"received"`
	Failed   []string   `json:"failed,omitempty"`
	QueryIDs []string   `json:"query_ids,omitempty"`
}

type received struct {
	Format          string   `json:"format"`
	ConfigurationID string   `json:"configuration_id"`
	Claims          []string `json:"claims"`
}

func main() {
	tlsCA := flag.String("tls-ca", "", "the CA the parties' TLS certificates chain to")
	issuerCA := flag.String("issuer-ca", "", "the CA credential issuers chain to")
	verifierCA := flag.String("verifier-ca", "", "the CA Verifiers' Access Certificates chain to")
	resolve := flag.String("resolve", "", "HOST=ADDR: dial ADDR for HOST")
	var offered offers
	flag.Var(&offered, "offer", "a credential offer to redeem (repeatable)")
	request := flag.String("request", "", "a Verifier's openid4vp request to answer")
	out := flag.String("out", "", "where to write the result")
	flag.Parse()
	if *tlsCA == "" || *issuerCA == "" || *verifierCA == "" || len(offered) == 0 || *out == "" {
		log.Fatal("-tls-ca, -issuer-ca, -verifier-ca, -offer and -out are required")
	}
	res := run(*tlsCA, *issuerCA, *verifierCA, *resolve, offered, *request)
	raw, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(*out, raw, 0o600); err != nil {
		log.Fatal(err)
	}
}

func run(tlsCA, issuerCA, verifierCA, resolve string, offered []string, request string) (res result) {
	res.Stage = "setup"
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	fail := func(err error) result {
		res.Error = err.Error()
		return res
	}
	tlsRoots, err := pool(tlsCA)
	if err != nil {
		return fail(err)
	}
	issuerRoots, err := pool(issuerCA)
	if err != nil {
		return fail(err)
	}
	verifierRoots, err := pool(verifierCA)
	if err != nil {
		return fail(err)
	}
	host, addr, ok := strings.Cut(resolve, "=")
	if resolve != "" && !ok {
		return fail(fmt.Errorf("-resolve %q isn't HOST=ADDR", resolve))
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: tlsRoots, MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if h, port, err := net.SplitHostPort(address); err == nil && ok && h == host {
				address = net.JoinHostPort(addr, port)
			}
			return dialer.DialContext(ctx, network, address)
		},
	}}
	w, err := walletflow.New(walletflow.Config{
		IssuerRoots: issuerRoots, Development: true, VerifierTrust: wallet.X5CVerifierRoots{Roots: verifierRoots},
	}, walletflow.Dependencies{Keys: walletflow.NewMemoryKeyStore(), Credentials: walletflow.NewMemoryCredentialStore(), HTTP: client})
	if err != nil {
		return fail(err)
	}

	for _, offer := range offered {
		res.Stage = "offer"
		s, err := w.StartIssuance(ctx, offer)
		if err != nil {
			return fail(err)
		}
		res.Stage = "token"
		if err := s.RedeemPreAuthorizedCode(ctx, ""); err != nil {
			_ = s.Close(ctx)
			return fail(err)
		}
		res.Stage = "credential"
		got, err := s.RequestCredentials(ctx)
		_ = s.Close(ctx)
		if err != nil {
			return fail(err)
		}
		for _, c := range got.Credentials {
			names := make([]string, 0, len(c.Claims))
			for name := range c.Claims {
				names = append(names, name)
			}
			slices.Sort(names)
			res.Received = append(res.Received, received{Format: c.Format, ConfigurationID: c.ConfigurationID, Claims: names})
		}
		for _, f := range got.Failed {
			res.Failed = append(res.Failed, f.ConfigurationID+": "+f.Err.Error())
		}
		if len(got.Failed) > 0 {
			return fail(errors.New("a credential was refused"))
		}
	}
	if request == "" {
		res.Stage = "done"
		return res
	}

	res.Stage = "request"
	p, err := w.StartPresentation(ctx, request)
	if err != nil {
		return fail(err)
	}
	res.Stage = "selection"
	sel, err := p.DefaultSelection(ctx)
	if err != nil {
		return fail(err)
	}
	res.Stage = "response"
	presented, err := p.Respond(ctx, sel)
	if err != nil {
		return fail(err)
	}
	res.QueryIDs = presented.QueryIDs
	res.Stage = "done"
	return res
}

// pool is a PEM file's certificates.
func pool(path string) (*x509.CertPool, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- the operator's own file
	if err != nil {
		return nil, err
	}
	p := x509.NewCertPool()
	if !p.AppendCertsFromPEM(raw) {
		return nil, fmt.Errorf("%s holds no PEM certificate", path)
	}
	return p, nil
}
