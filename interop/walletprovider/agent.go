package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/jwk"
	"github.com/idfoundry/oid4vcgo/interop/internal/interopwp"
)

// maxAgentRequestBytes bounds an agent request: a few public JWKs.
const maxAgentRequestBytes = 64 * 1024

// runAgent is the agent's command line.
func runAgent(args []string) error {
	fs := flag.NewFlagSet("walletprovider agent", flag.ContinueOnError)
	providerURL := fs.String("provider", "", "the provider's HTTPS base URL (required)")
	tlsCert := fs.String("tls-cert", "", "the provider's TLS certificate, PEM (required)")
	addr := fs.String("addr", "", "the agent's loopback listener (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *providerURL == "" || *tlsCert == "" || *addr == "" {
		return errors.New("agent: -provider, -tls-cert and -addr are required")
	}
	if err := loopback("addr", *addr); err != nil {
		return err
	}
	hc, err := httpClientTrusting(*tlsCert)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	p, err := interopwp.Register(ctx, *providerURL, hc)
	if err != nil {
		return err
	}
	log.Printf("agent: registered instance %s at %s; serving on http %s", p.InstanceID(), *providerURL, *addr)
	srv := &http.Server{Addr: *addr, Handler: agentHandler(p), ReadHeaderTimeout: 10 * time.Second}
	return srv.ListenAndServe()
}

// httpClientTrusting is an HTTP client trusting only the TLS
// certificate in the PEM file at path.
func httpClientTrusting(path string) (*http.Client, error) {
	pemBytes, err := os.ReadFile(path) // #nosec G304 -- the operator's own file
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("%s holds no PEM certificate", path)
	}
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}},
	}, nil
}

// agentRequest is an agent request's body.
type agentRequest struct {
	ClientID    string            `json:"client_id"`
	InstanceKey json.RawMessage   `json:"instance_key"`
	Keys        []json.RawMessage `json:"keys"`
	Nonce       string            `json:"nonce"`
}

// agentHandler serves the agent's two endpoints over p. A refusal is
// answered 502 with the provider's error, so the driver can tell it
// from the issuer's.
func agentHandler(p *interopwp.Provider) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /ready", func(w http.ResponseWriter, _ *http.Request) { _, _ = fmt.Fprintln(w, "ready") })
	mux.HandleFunc("POST /wallet-attestation", func(w http.ResponseWriter, r *http.Request) {
		req, instanceKey, ok := readAgentRequest(w, r)
		if !ok {
			return
		}
		jwt, err := p.WalletAttestation(r.Context(), req.ClientID, instanceKey)
		answer(w, jwt, err)
	})
	mux.HandleFunc("POST /key-attestation", func(w http.ResponseWriter, r *http.Request) {
		req, instanceKey, ok := readAgentRequest(w, r)
		if !ok {
			return
		}
		keys := make([]*ecdsa.PublicKey, len(req.Keys))
		for i, raw := range req.Keys {
			k, err := jwk.ParsePublicKey(raw)
			ec, isEC := k.(*ecdsa.PublicKey)
			if err != nil || !isEC {
				http.Error(w, fmt.Sprintf("keys[%d] isn't a public EC JWK", i), http.StatusBadRequest)
				return
			}
			keys[i] = ec
		}
		jwt, err := p.KeyAttestation(r.Context(), instanceKey, keys, req.Nonce)
		answer(w, jwt, err)
	})
	return mux
}

// readAgentRequest reads an agent request and its instance key.
func readAgentRequest(w http.ResponseWriter, r *http.Request) (agentRequest, crypto.PublicKey, bool) {
	var req agentRequest
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxAgentRequestBytes))
	if err == nil {
		err = json.Unmarshal(body, &req)
	}
	if err != nil {
		http.Error(w, "malformed request: "+err.Error(), http.StatusBadRequest)
		return req, nil, false
	}
	instanceKey, err := jwk.ParsePublicKey(req.InstanceKey)
	if err != nil {
		http.Error(w, "instance_key: "+err.Error(), http.StatusBadRequest)
		return req, nil, false
	}
	return req, instanceKey, true
}

// answer writes {"jwt"} or the provider's refusal.
func answer(w http.ResponseWriter, jwt string, err error) {
	if err != nil {
		log.Printf("agent: %v", err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"jwt": jwt})
}
