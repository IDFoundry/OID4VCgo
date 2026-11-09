// Command serve runs interop/waltid/run.sh's TLS endpoints, under
// setup's tls-cert.pem: a reverse proxy in front of each walt.id
// service, which speak plain HTTP, and a Wallet Attestation stub, the
// Wallet Provider walt.id's Wallet asks for a Wallet Attestation
// before it redeems an offer of OID4VCgo's issuer.
//
// The attester answers walt.id's GenericHttpWalletAttestationProvider:
// a POST of {"jwk": <the wallet instance's public key>} gets back
// {"walletInstanceAttestation": <a Client Attestation JWT for that
// key>}, signed with interop/eudi/scripts/setup-issuer's attester key
// and x5c, which the issuer trusts, naming its attester issuer and
// client_id. The file -attester-mode names which: "trusted", or
// "untrusted" for its other attester key, which the issuer doesn't
// trust; it's read on each request, so a control switches it.
//
// Usage: go run ./interop/waltid/scripts/serve -dir DIR -proxy ADDR=URL ... -attester ADDR -attester-config FILE -attester-mode FILE
//
// Each request is logged.
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// proxies is the repeated -proxy flag: ADDR=URL.
type proxies map[string]*url.URL

func (p proxies) String() string { return fmt.Sprint(map[string]*url.URL(p)) }

func (p proxies) Set(v string) error {
	addr, upstream, ok := strings.Cut(v, "=")
	if !ok {
		return fmt.Errorf("want ADDR=URL, not %q", v)
	}
	u, err := url.Parse(upstream)
	if err != nil {
		return err
	}
	p[addr] = u
	return nil
}

func main() {
	dir := flag.String("dir", "", "the directory setup wrote")
	to := proxies{}
	flag.Var(to, "proxy", "ADDR=URL: serve TLS on ADDR, proxying to URL (repeatable)")
	attester := flag.String("attester", "", "the attester's address")
	attesterConfig := flag.String("attester-config", "", "setup-issuer's driver.json")
	attesterMode := flag.String("attester-mode", "", `a file naming the attester key: "trusted" or "untrusted"`)
	flag.Parse()
	if *dir == "" || (len(to) == 0 && *attester == "") {
		log.Fatal("-dir and a -proxy or -attester are required")
	}
	pair, err := tls.LoadX509KeyPair(filepath.Join(*dir, "tls-cert.pem"), filepath.Join(*dir, "tls-key.pem"))
	if err != nil {
		log.Fatal(err)
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}

	errs := make(chan error)
	listen := func(addr string, h http.Handler) {
		srv := &http.Server{Addr: addr, Handler: h, TLSConfig: cfg, ReadHeaderTimeout: 10 * time.Second}
		go func() { errs <- srv.ListenAndServeTLS("", "") }()
		log.Printf("listening on %s", addr)
	}
	for addr, upstream := range to {
		rp := httputil.NewSingleHostReverseProxy(upstream)
		listen(addr, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.Printf("%s %q %q", addr, r.Method, r.URL.Path) // #nosec G706 -- quoted: a request can't forge a log line
			rp.ServeHTTP(w, r)
		}))
	}
	if *attester != "" {
		if *attesterConfig == "" || *attesterMode == "" {
			log.Fatal("-attester needs -attester-config and -attester-mode")
		}
		h, err := attesterHandler(*attesterConfig, *attesterMode)
		if err != nil {
			log.Fatal(err)
		}
		listen(*attester, h)
	}
	log.Fatal(<-errs)
}

// attesterKeys are setup-issuer's driver.json, as far as the attester
// uses it.
type attesterKeys struct {
	Issuer   string            `json:"attester_issuer"`
	ClientID string            `json:"client_id"`
	Key      map[string]string `json:"attester_key"`
	X5C      []string          `json:"attester_x5c"`
	Other    map[string]string `json:"other_attester_key"`
	OtherX5C []string          `json:"other_attester_x5c"`
}

func attesterHandler(configPath, modePath string) (http.Handler, error) {
	raw, err := os.ReadFile(configPath) // #nosec G304 -- the operator's own config
	if err != nil {
		return nil, err
	}
	var keys attesterKeys
	if err := json.Unmarshal(raw, &keys); err != nil {
		return nil, err
	}
	trusted, err := privateKey(keys.Key)
	if err != nil {
		return nil, fmt.Errorf("attester_key: %w", err)
	}
	untrusted, err := privateKey(keys.Other)
	if err != nil {
		return nil, fmt.Errorf("other_attester_key: %w", err)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			JWK json.RawMessage `json:"jwk"`
		}
		if r.Method != http.MethodPost || json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body) != nil || len(body.JWK) == 0 {
			http.Error(w, `want a POST of {"jwk": ...}`, http.StatusBadRequest)
			return
		}
		mode, err := os.ReadFile(modePath) // #nosec G304 -- the operator's own file
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		key, x5c := trusted, keys.X5C
		if string(bytes.TrimSpace(mode)) == "untrusted" {
			key, x5c = untrusted, keys.OtherX5C
		}
		log.Printf("attester: %s attestation for %s", bytes.TrimSpace(mode), body.JWK)
		jwt, err := attestation(key, x5c, keys.Issuer, keys.ClientID, body.JWK)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"walletInstanceAttestation": jwt})
	}), nil
}

// attestation is a Client Attestation JWT (draft-ietf-oauth-attestation-
// based-client-auth §5.1) binding the wallet instance's key, cnf.
func attestation(key *ecdsa.PrivateKey, x5c []string, iss, sub string, cnf json.RawMessage) (string, error) {
	header, err := json.Marshal(map[string]any{"alg": "ES256", "typ": "oauth-client-attestation+jwt", "x5c": x5c})
	if err != nil {
		return "", err
	}
	now := time.Now().Unix()
	payload, err := json.Marshal(map[string]any{
		"iss": iss, "sub": sub, "iat": now, "exp": now + 600, "cnf": map[string]json.RawMessage{"jwk": cnf},
	})
	if err != nil {
		return "", err
	}
	b := base64.RawURLEncoding.EncodeToString
	input := b(header) + "." + b(payload)
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return "", err
	}
	return input + "." + b(append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)), nil
}

// privateKey is a P-256 private JWK's key.
func privateKey(jwk map[string]string) (*ecdsa.PrivateKey, error) {
	d, err := base64.RawURLEncoding.DecodeString(jwk["d"])
	if err != nil {
		return nil, err
	}
	return ecdsa.ParseRawPrivateKey(elliptic.P256(), d)
}
