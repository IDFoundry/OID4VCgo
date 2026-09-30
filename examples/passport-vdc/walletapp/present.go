package walletapp

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/idfoundry/fapigo/fapihttp"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// PresentOptions controls Present.
type PresentOptions struct {
	// Format, if set, restricts which stored credentials are offered to
	// the Verifier's query ("mso_mdoc" or "dc+sd-jwt") — how the demo
	// shows a Verifier accepting either format.
	Format string
	// HTTP makes every request; nil means a client with a 10 s timeout.
	HTTP *http.Client
	// VerifierTrust decides which verifiers to answer (OpenID4VP
	// §5.9.3). REQUIRED — see LoadVerifierTrust.
	VerifierTrust wallet.VerifierTrust
}

// Presented summarizes what was sent.
type Presented struct {
	VerifierClientID string
	// Credentials are the DCQL credential query IDs presented.
	Credentials []string
	// RedirectURI, when the verifier returned one, is where the wallet
	// MUST now send the user agent (OpenID4VP §8.2) — the same-device
	// flow's way back to the verifier's page.
	RedirectURI string
}

// Prepared is a verified presentation request the holder hasn't
// answered yet, with every way the wallet's stored credentials can
// satisfy it.
type Prepared struct {
	// VerifierClientID identifies the verifier: its x509_hash client
	// identifier, checked against the Request Object's signature.
	VerifierClientID string
	// VerifierName is the subject common name of the verifier's
	// request-signing certificate, which chains to a trusted CA.
	VerifierName string
	// ResponseURI is where the answer would be sent.
	ResponseURI string
	// Options are the ways to answer, one per format the wallet can
	// answer in.
	Options []Option

	authReq wallet.AuthorizationRequest
	store   Store
	http    *http.Client
}

// Option is one way to answer a request.
type Option struct {
	Format string
	// QueryID is the DCQL credential query this answers.
	QueryID string
	// Claims are the claim paths that would be disclosed (e.g.
	// ["family_name"], or [namespace, element] for an mdoc).
	Claims [][]string
}

// Present answers an OpenID4VP Authorization Request without asking
// the holder — Prepare then Send with opts.Format.
func Present(ctx context.Context, requestLink string, store Store, opts PresentOptions) (Presented, error) {
	p, err := Prepare(ctx, requestLink, store, opts.HTTP, opts.VerifierTrust)
	if err != nil {
		return Presented{}, err
	}
	return p.Send(ctx, opts.Format)
}

// Prepare fetches and verifies an OpenID4VP Authorization Request (an
// openid4vp:// link carrying client_id and request_uri) from a verifier
// trust accepts, and works out how the stored credentials can answer
// it, without sending anything — so a wallet can ask the holder first.
func Prepare(ctx context.Context, requestLink string, store Store, httpClient *http.Client, trust wallet.VerifierTrust) (*Prepared, error) {
	if trust == nil {
		return nil, fmt.Errorf("walletapp: a VerifierTrust is required")
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: httpTimeout}
	}
	// request_uri_method=post is accepted and fetched with GET, which
	// OID4VP §5 allows a Wallet without POST support to do.
	link, err := wallet.ParseAuthorizationRequestLink(requestLink)
	if err != nil {
		return nil, fmt.Errorf("walletapp: %w", err)
	}

	w, err := wallet.New(wallet.Config{
		Assurance: wallet.AssuranceDevelopment, ProofSigningAlg: oid4vci.ES256,
		Fetch:         fapihttp.Config{MaxResponseBytes: 1 << 20, RequestTimeout: httpTimeout, MaxRedirects: 2, AllowLoopbackHTTP: true},
		VerifierTrust: trust,
	}, wallet.Dependencies{HTTP: httpClient, Clock: wallet.ClockFunc(time.Now), Random: rand.Reader})
	if err != nil {
		return nil, fmt.Errorf("walletapp: %w", err)
	}
	// FetchAuthorizationRequest checks the signing certificate chains
	// to a trusted CA, the Request Object's signature, and that
	// client_id is that certificate's x509_hash.
	authReq, err := w.FetchAuthorizationRequest(ctx, link.RequestURI, link.ClientID)
	if err != nil {
		return nil, fmt.Errorf("walletapp: presentation request: %w", err)
	}

	p := &Prepared{
		VerifierClientID: authReq.ClientID, VerifierName: authReq.VerifierCertificate.Subject.CommonName,
		ResponseURI: authReq.ResponseURI, authReq: authReq, store: store, http: httpClient,
	}
	// One option per format: exactly what Send would present in that
	// format (wallet.PreviewPresentation makes the same choices, claim
	// sets included), for the holder to see before choosing.
	for _, format := range []string{"mso_mdoc", "dc+sd-jwt"} {
		held, err := heldCredentials(store, format)
		if err != nil {
			continue
		}
		preview, err := wallet.PreviewPresentation(ctx, authReq.Query, held, dcql.AKITrustedAuthoritiesChecker{})
		if err != nil {
			continue
		}
		for _, c := range preview {
			p.Options = append(p.Options, Option{Format: format, QueryID: c.QueryID, Claims: pathStrings(c.Claims)})
		}
	}
	if len(p.Options) == 0 {
		return nil, fmt.Errorf("walletapp: no stored credential satisfies the request")
	}
	return p, nil
}

// Send answers the request with the stored credential of format ("" for
// whichever matches first): it builds selectively disclosed
// presentations bound to the verifier's nonce and POSTs them to the
// response_uri as an encrypted direct_post.jwt response.
func (p *Prepared) Send(ctx context.Context, format string) (Presented, error) {
	held, err := heldCredentials(p.store, format)
	if err != nil {
		return Presented{}, err
	}
	// Offer only credentials from an issuer the query's
	// trusted_authorities names.
	responded, err := wallet.Respond(ctx, p.http, p.authReq, held, dcql.AKITrustedAuthoritiesChecker{})
	if err != nil {
		return Presented{}, fmt.Errorf("walletapp: %w", err)
	}
	presented := Presented{VerifierClientID: p.authReq.ClientID, RedirectURI: responded.Reply.RedirectURI}
	for id := range responded.VPToken {
		presented.Credentials = append(presented.Credentials, id)
	}
	sort.Strings(presented.Credentials)
	return presented, nil
}

// heldCredentials loads the store as wallet.HeldCredentials, optionally
// only those of one format.
func heldCredentials(store Store, format string) ([]wallet.HeldCredential, error) {
	stored, err := store.List()
	if err != nil {
		return nil, err
	}
	var held []wallet.HeldCredential
	for _, s := range stored {
		if format != "" && s.Format != format {
			continue
		}
		block, _ := pem.Decode([]byte(s.HolderKeyPEM))
		if block == nil {
			return nil, fmt.Errorf("walletapp: %s: no holder key", s.Path)
		}
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("walletapp: %s: holder key: %w", s.Path, err)
		}
		held = append(held, wallet.HeldCredential{
			Format: s.Format, Credential: s.Credential,
			HolderKey: key, HolderKeyAlg: oid4vci.ES256, MdocDocType: s.DocType,
		})
	}
	if len(held) == 0 {
		return nil, fmt.Errorf("walletapp: no stored credentials to present")
	}
	return held, nil
}

// LoadVerifierTrust trusts verifiers whose request-signing certificate
// chains to a CA in the comma-separated PEM files (the demo verifier
// writes its CA to verifier-ca.pem).
func LoadVerifierTrust(files string) (wallet.VerifierTrust, error) {
	roots, err := LoadCertPool(files)
	if err != nil {
		return nil, fmt.Errorf("walletapp: verifier CA: %w", err)
	}
	return wallet.X5CVerifierRoots{Roots: roots}, nil
}

// LoadCertPool reads the certificates in the comma-separated PEM files
// into a pool — e.g. Config.IssuerRoots from the demo issuer's
// issuer-ca.pem.
func LoadCertPool(files string) (*x509.CertPool, error) {
	roots := x509.NewCertPool()
	for _, f := range strings.Split(files, ",") {
		if f = strings.TrimSpace(f); f == "" {
			continue
		}
		pemBytes, err := os.ReadFile(f) // #nosec G304 -- operator-supplied path
		if err != nil {
			return nil, err
		}
		if !roots.AppendCertsFromPEM(pemBytes) {
			return nil, fmt.Errorf("%s holds no PEM certificates", f)
		}
	}
	return roots, nil
}

// pathStrings renders claim paths as their components, for display.
func pathStrings(paths []dcql.Path) [][]string {
	out := make([][]string, len(paths))
	for i, p := range paths {
		out[i] = make([]string, len(p))
		for j, el := range p {
			out[i][j] = el.Key()
		}
	}
	return out
}
