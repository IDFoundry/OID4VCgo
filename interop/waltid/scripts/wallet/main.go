// Command wallet is OID4VCgo's wallet for interop/waltid/run.sh, on
// walletflow at development assurance (or production, -assurance): it
// redeems each of walt.id Issuer2's pre-authorized code offers
// (-offer, repeatable), checking
// each credential as walletflow does, its issuer's chain to
// -issuer-ca among them; then, with -request, answers walt.id
// Verifier2's request with them, trusting Verifiers whose Access
// Certificate chains to -verifier-ca.
//
// The parties' TLS certificates chain to -tls-ca; -resolve HOST=ADDR,
// if given, dials ADDR for HOST.
//
// To redeem OID4VCgo's issuer's offers instead, which take a Wallet
// Attestation (HAIP 1.0 §4.4.1), -attester-config names
// interop/eudi/scripts/setup-issuer's driver.json: its client_id, and
// the keys of a stand-in Wallet Provider the issuer trusts
// (provider.go); or -wallet-provider names OID4VCgo's Wallet Provider
// (interop/walletprovider), whose TLS certificate is
// -wallet-provider-tls, which issues the wallet's attestations for
// -client-id over its protocol (interop/internal/interopwp);
// -mdoc-issuer-ca, its mdocs' IACA. With -revoke, the
// issuer's POST /status, the wallet has the issuer revoke every
// credential it received before it answers -request, as an issuer
// revokes one after issuing it: the result's "revoked" lists the
// status list entries.
//
// The result, written to -out as JSON, says how far the run got and
// what it saw; run.sh decides whether that's what the case expects.
// Its "observed" records what walt.id sent of what SPECIFICATIONS.md's
// "Known leniencies" concern, read off the wire by the wallet's HTTP
// transport: each Token Response's token_type, each encryption JWK's
// alg and kid in the issuer's credential_request_encryption, and in
// a Verifier's request object's client_metadata.
//
// With -assurance production, walletflow runs as a deployment runs it
// (production.go): its own HTTP client, the system's TLS roots, its
// stores in -store; -tls-ca, -resolve and the observing transport are
// then unused.
//
// With -tamper, the transport changes the presentation on its way to
// Verifier2, for the negative presentations a correct Verifier must
// refuse (tamper.go); the result's "tampered" records the change and
// Verifier2's answer to it.
//
// Usage: go run ./interop/waltid/scripts/wallet -tls-ca FILE -issuer-ca FILE -verifier-ca FILE [-resolve HOST=ADDR] [-attester-config FILE | -wallet-provider URL -wallet-provider-tls FILE -client-id ID] [-mdoc-issuer-ca FILE] -offer URL [-revoke URL] [-request URL [-tamper MODE -verifier2-key FILE]] -out FILE
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
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
	Observed *observed  `json:"observed"`
	Tampered *tampered  `json:"tampered,omitempty"`
	Revoked  []string   `json:"revoked,omitempty"`
}

// tampered is what -tamper changed of the presentation, and Verifier2's
// answer to it.
type tampered struct {
	Mode    string `json:"mode"`
	Changed string `json:"changed"`
	Reply   *reply `json:"reply"`
}

// observed is what the transport saw walt.id send: token_types, one per
// Token Response; IssuerMetadata, how many JSON Credential Issuer
// Metadata documents it read, and RequestEncryption whether one had
// credential_request_encryption; RequestEncryptionJWKs, that member's
// jwks keys; and VerifierJWKs, the request object's client_metadata.jwks
// keys. Each key is {"alg": ..., "kid": ...}, "absent" for a member it
// lacks.
type observed struct {
	mu                    sync.Mutex
	TokenTypes            []string            `json:"token_types"`
	IssuerMetadata        int                 `json:"issuer_metadata"`
	RequestEncryption     bool                `json:"credential_request_encryption"`
	RequestEncryptionJWKs []map[string]string `json:"request_encryption_jwks"`
	VerifierJWKs          []map[string]string `json:"verifier_jwks"`
}

// maxRecordedBody bounds what the recorder reads of a response.
const maxRecordedBody = 4 << 20

// recorder is an http.RoundTripper recording into observed what each
// response says.
type recorder struct {
	next http.RoundTripper
	seen *observed
}

func (r recorder) RoundTrip(req *http.Request) (*http.Response, error) {
	res, err := r.next.RoundTrip(req)
	if err != nil {
		return res, err
	}
	// One byte past the bound shows a body that exceeds it: an error,
	// not a body cut short and handed on as if whole.
	body, err := io.ReadAll(io.LimitReader(res.Body, maxRecordedBody+1))
	_ = res.Body.Close()
	if err != nil {
		return nil, err
	}
	if len(body) > maxRecordedBody {
		return nil, fmt.Errorf("wallet: the response from %s exceeds %d bytes", req.URL.Redacted(), maxRecordedBody)
	}
	res.Body = io.NopCloser(bytes.NewReader(body))
	r.seen.record(req, res.Header.Get("Content-Type"), body)
	return res, nil
}

func (o *observed) record(req *http.Request, contentType string, body []byte) {
	o.mu.Lock()
	defer o.mu.Unlock()
	switch {
	case strings.HasPrefix(contentType, "application/oauth-authz-req+jwt"):
		var claims struct {
			ClientMetadata struct {
				JWKS struct {
					Keys []map[string]any `json:"keys"`
				} `json:"jwks"`
			} `json:"client_metadata"`
		}
		if segments := strings.Split(string(body), "."); len(segments) == 3 {
			if raw, err := base64.RawURLEncoding.DecodeString(segments[1]); err == nil && json.Unmarshal(raw, &claims) == nil {
				o.VerifierJWKs = append(o.VerifierJWKs, members(claims.ClientMetadata.JWKS.Keys)...)
			}
		}
	case strings.Contains(req.URL.Path, "/.well-known/openid-credential-issuer"):
		var meta struct {
			Encryption *struct {
				JWKS struct {
					Keys []map[string]any `json:"keys"`
				} `json:"jwks"`
			} `json:"credential_request_encryption"`
		}
		if json.Unmarshal(body, &meta) != nil {
			return
		}
		o.IssuerMetadata++
		if meta.Encryption != nil {
			o.RequestEncryption = true
			o.RequestEncryptionJWKs = append(o.RequestEncryptionJWKs, members(meta.Encryption.JWKS.Keys)...)
		}
	default:
		var token struct {
			TokenType *string `json:"token_type"`
		}
		if json.Unmarshal(body, &token) == nil && token.TokenType != nil {
			o.TokenTypes = append(o.TokenTypes, *token.TokenType)
		}
	}
}

// members is each key's alg and kid, "absent" for one it lacks.
func members(keys []map[string]any) []map[string]string {
	out := make([]map[string]string, 0, len(keys))
	for _, k := range keys {
		m := map[string]string{}
		for _, name := range []string{"alg", "kid"} {
			m[name] = "absent"
			if v, ok := k[name]; ok {
				m[name] = fmt.Sprint(v)
			}
		}
		out = append(out, m)
	}
	return out
}

type received struct {
	Format          string   `json:"format"`
	ConfigurationID string   `json:"configuration_id"`
	Claims          []string `json:"claims"`
	// StatusLists are its copies' status list entries, uri#idx.
	StatusLists []string `json:"status_lists,omitempty"`
}

// options are the flags that change what the wallet is, beyond the
// parties' trust: OID4VCgo's issuer's Wallet Provider and IACA, and the
// issuer's revocation endpoint.
type options struct {
	attesterConfig, mdocIssuerCA, revoke string
	crlSet                               string
	// walletProvider, walletProviderTLS and clientID: OID4VCgo's
	// Wallet Provider, in place of attesterConfig's stand-in.
	walletProvider, walletProviderTLS, clientID string
	// assurance is "development" or "production" (production.go), and
	// store the directory of production's durable stores.
	assurance, store string
	// allowedPrivateHosts are the hosts production's client may reach
	// at a private address: Issuer2's and Verifier2's, on the run's
	// Docker network.
	allowedPrivateHosts []string
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
	tamper := flag.String("tamper", "", "change the presentation on its way to Verifier2: "+strings.Join(tamperModes, ", "))
	verifier2Key := flag.String("verifier2-key", "", "Verifier2's request object key, for -tamper")
	var opts options
	flag.StringVar(&opts.attesterConfig, "attester-config", "", "setup-issuer's driver.json: attest the wallet to OID4VCgo's issuer as its client_id")
	flag.StringVar(&opts.walletProvider, "wallet-provider", "", "OID4VCgo's Wallet Provider's base URL: attest the wallet to OID4VCgo's issuer with its attestations, as -client-id")
	flag.StringVar(&opts.walletProviderTLS, "wallet-provider-tls", "", "the Wallet Provider's TLS certificate, PEM")
	flag.StringVar(&opts.clientID, "client-id", "", "the client_id the Wallet Provider attests the wallet as")
	flag.StringVar(&opts.mdocIssuerCA, "mdoc-issuer-ca", "", "the IACA mdocs chain to, if not -issuer-ca")
	flag.StringVar(&opts.revoke, "revoke", "", "OID4VCgo's issuer's POST /status: revoke every credential received before answering -request")
	flag.StringVar(&opts.crlSet, "crl-set", "current", "the CA's CRL this process publishes, setup's crl-publisher-SET.json in the working directory, which the wallet checks Issuer2's and Verifier2's certificates against: current, revoked-issuer, revoked-verifier or expired; none checks no revocation (OID4VCgo's issuer's CAs publish no CRL)")
	flag.StringVar(&opts.assurance, "assurance", "development", "development, or production: walletflow as a deployment runs it (production.go), its stores in -store; -tls-ca and -resolve are then unused, the TLS roots the system's")
	flag.StringVar(&opts.store, "store", "", "with -assurance production, the directory of the wallet's durable stores")
	flag.Func("allowed-private-host", "with -assurance production, a host the wallet may reach at a private address (repeatable)", func(host string) error {
		opts.allowedPrivateHosts = append(opts.allowedPrivateHosts, host)
		return nil
	})
	flag.Parse()
	if *tamper != "" && (!slices.Contains(tamperModes, *tamper) || *verifier2Key == "") {
		log.Fatal("-tamper takes one of " + strings.Join(tamperModes, ", ") + ", and -verifier2-key")
	}
	if (opts.assurance != "development" && opts.assurance != "production") || (opts.assurance == "production") != (opts.store != "") ||
		(opts.assurance == "production" && *tamper != "") {
		log.Fatal("-assurance is development or production, which needs -store and takes no -tamper (its transport is walletflow's own)")
	}
	if *tlsCA == "" || *issuerCA == "" || *verifierCA == "" || len(offered) == 0 || *out == "" {
		log.Fatal("-tls-ca, -issuer-ca, -verifier-ca, -offer and -out are required")
	}
	res := run(*tlsCA, *issuerCA, *verifierCA, *resolve, offered, *request, *tamper, *verifier2Key, opts)
	raw, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(*out, raw, 0o600); err != nil {
		log.Fatal(err)
	}
}

func run(tlsCA, issuerCA, verifierCA, resolve string, offered []string, request, tamper, verifier2Key string, opts options) (res result) {
	res.Stage = "setup"
	res.Observed = &observed{}
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
	var transport http.RoundTripper = recorder{seen: res.Observed, next: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: tlsRoots, MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if h, port, err := net.SplitHostPort(address); err == nil && ok && h == host {
				address = net.JoinHostPort(addr, port)
			}
			return dialer.DialContext(ctx, network, address)
		},
	}}
	keys := &keyring{KeyStore: walletflow.NewMemoryKeyStore()}
	var t *tamperer
	if tamper != "" {
		if t, err = newTamperer(transport, tamper, verifier2Key, keys); err != nil {
			return fail(err)
		}
		transport = t
		defer func() { res.Tampered = t.outcome() }()
	}
	client := &http.Client{Transport: transport}
	// Issuer2's and Verifier2's certificates are checked for
	// revocation, against the CA's CRL this process publishes at the
	// distribution point they name (startCRL).
	revocation, err := startCRL(ctx, opts.crlSet)
	if err != nil {
		return fail(err)
	}
	cfg := walletflow.Config{
		IssuerRoots: issuerRoots, IssuerRevocation: revocation, Development: true,
		VerifierTrust: wallet.X5CVerifierRoots{Roots: verifierRoots, Revocation: revocation},
	}
	deps := walletflow.Dependencies{Keys: keys, Credentials: walletflow.NewMemoryCredentialStore(), HTTP: client}
	if opts.attesterConfig != "" {
		p, err := loadProvider(opts.attesterConfig)
		if err != nil {
			return fail(err)
		}
		cfg.ClientID, deps.Provider = p.cfg.ClientID, p
	}
	if opts.walletProvider != "" {
		p, err := registerAtProvider(ctx, opts.walletProvider, opts.walletProviderTLS)
		if err != nil {
			return fail(err)
		}
		cfg.ClientID, deps.Provider = opts.clientID, p
	}
	if opts.mdocIssuerCA != "" {
		if cfg.MdocIssuerRoots, err = pool(opts.mdocIssuerCA); err != nil {
			return fail(err)
		}
	}
	stores, err := assurance(opts, &cfg, &deps, revocation)
	if err != nil {
		return fail(err)
	}
	defer func() { _ = stores.Close() }()
	w, err := walletflow.New(cfg, deps)
	if err != nil {
		return fail(err)
	}

	var got []walletflow.StoredCredential
	for _, offer := range offered {
		creds, err := redeem(ctx, w, offer, &res)
		if err != nil {
			return fail(err)
		}
		got = append(got, creds...)
	}
	if opts.revoke != "" {
		res.Stage = "revoke"
		if err := revoke(ctx, opts.revoke, got, &res); err != nil {
			return fail(err)
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

// redeem redeems offer's pre-authorized code, recording in res how far
// it got and the credentials it received or refused, which it returns.
func redeem(ctx context.Context, w *walletflow.Wallet, offer string, res *result) ([]walletflow.StoredCredential, error) {
	res.Stage = "offer"
	s, err := w.StartIssuance(ctx, offer)
	if err != nil {
		return nil, err
	}
	defer func() { _ = s.Close(ctx) }()
	res.Stage = "token"
	if err := s.RedeemPreAuthorizedCode(ctx, ""); err != nil {
		return nil, err
	}
	res.Stage = "credential"
	got, err := s.RequestCredentials(ctx)
	if err != nil {
		return nil, err
	}
	for _, c := range got.Credentials {
		names := make([]string, 0, len(c.Claims))
		for name := range c.Claims {
			names = append(names, name)
		}
		slices.Sort(names)
		var lists []string
		for _, cp := range c.AllCopies() {
			if cp.StatusList != nil {
				lists = append(lists, fmt.Sprintf("%s#%d", cp.StatusList.URI, cp.StatusList.Idx))
			}
		}
		if len(lists) == 0 && c.StatusList != nil {
			lists = append(lists, fmt.Sprintf("%s#%d", c.StatusList.URI, c.StatusList.Idx))
		}
		res.Received = append(res.Received, received{Format: c.Format, ConfigurationID: c.ConfigurationID, Claims: names, StatusLists: lists})
	}
	for _, f := range got.Failed {
		res.Failed = append(res.Failed, f.ConfigurationID+": "+f.Err.Error())
	}
	if len(got.Failed) > 0 {
		return nil, errors.New("a credential was refused")
	}
	return got.Credentials, nil
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
