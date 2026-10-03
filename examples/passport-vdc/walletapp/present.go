package walletapp

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strings"

	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/wallet"
	"github.com/idfoundry/oid4vcgo/walletflow"
)

// PresentOptions controls Present.
type PresentOptions struct {
	// Format, if set, presents a stored credential of that format
	// ("mso_mdoc" or "dc+sd-jwt") — how the demo shows a Verifier
	// accepting either — the first such option; CredentialID presents
	// that credential. Neither: the first option.
	Format       string
	CredentialID string
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
	// Options are the ways to answer: one per stored credential that
	// can, in each format it can answer in.
	Options []Option
	// Several is whether the request takes several credentials (DCQL
	// multiple, OpenID4VP 1.0 §6.1): Send may then be given several
	// Options, of one format. Otherwise it takes one.
	Several bool

	p *walletflow.Presentation
}

// Option is one way to answer a request: one stored credential, whose
// holder Holder names — a wallet can hold several people's passports.
type Option struct {
	CredentialID string
	Holder       string
	Format       string
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
	id := opts.CredentialID
	for _, o := range p.Options {
		if id == "" && (opts.Format == "" || o.Format == opts.Format) {
			id = o.CredentialID
		}
	}
	if id == "" {
		return Presented{}, fmt.Errorf("walletapp: no stored %s credential answers the request", opts.Format)
	}
	return p.Send(ctx, id)
}

// Prepare fetches and verifies an OpenID4VP Authorization Request (an
// openid4vp:// link carrying client_id and request_uri) from a verifier
// trust accepts, and works out how the stored credentials can answer
// it, without sending anything — so a wallet can ask the holder first.
// request_uri_method=post is accepted and fetched with GET, which
// OID4VP §5 allows a Wallet without POST support to do.
func Prepare(ctx context.Context, requestLink string, store Store, hc *http.Client, trust wallet.VerifierTrust) (*Prepared, error) {
	if trust == nil {
		return nil, fmt.Errorf("walletapp: a VerifierTrust is required")
	}
	view, keys, err := store.view()
	if err != nil {
		return nil, err
	}
	w, err := walletflow.New(walletflow.Config{VerifierTrust: trust, Development: true}, walletflow.Dependencies{
		Keys: keys, Credentials: view, HTTP: httpClient(hc),
	})
	if err != nil {
		return nil, fmt.Errorf("walletapp: %w", err)
	}
	// StartPresentation checks the signing certificate chains to a
	// trusted CA, the Request Object's signature, and that client_id is
	// that certificate's x509_hash.
	p, err := w.StartPresentation(ctx, requestLink)
	if err != nil {
		return nil, fmt.Errorf("walletapp: %w", err)
	}
	v := p.Verifier()
	prepared := &Prepared{VerifierClientID: v.ClientID, VerifierName: v.Name, ResponseURI: v.ResponseURI, p: p}
	// One option per stored credential that answers: exactly what Send
	// would present for it, claim sets included, and whose it is, for
	// the holder to choose.
	for _, q := range p.Queries() {
		prepared.Several = prepared.Several || q.Multiple
		for _, c := range q.Credentials {
			// The demo verifier's queries are alternatives (a credential
			// set), so one credential answers the request.
			disclosed, err := p.Preview(ctx, walletflow.Selection{q.ID: {c.ID}})
			if err != nil {
				continue
			}
			claims, _ := ReadClaims(c.Format, c.Credential)
			for _, d := range disclosed {
				prepared.Options = append(prepared.Options, Option{
					CredentialID: c.ID, Holder: HolderName(claims), Format: c.Format, QueryID: d.QueryID, Claims: pathStrings(d.Claims),
				})
			}
		}
	}
	if len(prepared.Options) == 0 {
		return nil, fmt.Errorf("walletapp: no stored credential satisfies the request")
	}
	return prepared, nil
}

// Send answers the request with the stored credentials credentialIDs
// name, each one of Options' — several only when the request takes
// Several, and then of one format: a selectively disclosed presentation
// of each, bound to the verifier's nonce, POSTed to the response_uri as
// an encrypted direct_post.jwt response.
func (p *Prepared) Send(ctx context.Context, credentialIDs ...string) (Presented, error) {
	if len(credentialIDs) == 0 {
		return Presented{}, fmt.Errorf("walletapp: choose a credential to share")
	}
	if len(credentialIDs) > 1 && !p.Several {
		return Presented{}, fmt.Errorf("walletapp: the request takes one credential, not %d", len(credentialIDs))
	}
	// The demo verifier's formats are alternatives: it takes the first
	// one answered, so several credentials must share one.
	queryID := ""
	for _, id := range credentialIDs {
		i := slices.IndexFunc(p.Options, func(o Option) bool { return o.CredentialID == id })
		switch {
		case i < 0:
			return Presented{}, fmt.Errorf("walletapp: credential %q doesn't answer the request", id)
		case queryID != "" && p.Options[i].QueryID != queryID:
			return Presented{}, fmt.Errorf("walletapp: share credentials of one format")
		}
		queryID = p.Options[i].QueryID
	}
	presented, err := p.p.Respond(ctx, walletflow.Selection{queryID: credentialIDs})
	if err != nil {
		return Presented{}, fmt.Errorf("walletapp: %w", err)
	}
	return Presented{VerifierClientID: p.VerifierClientID, Credentials: presented.QueryIDs, RedirectURI: presented.RedirectURI}, nil
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
