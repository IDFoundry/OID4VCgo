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

	p        *walletflow.Presentation
	byFormat map[string][]string // candidate credential IDs, by format
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
	prepared := &Prepared{
		VerifierClientID: v.ClientID, VerifierName: v.Name, ResponseURI: v.ResponseURI,
		p: p, byFormat: map[string][]string{},
	}
	for _, cs := range p.Candidates() {
		for _, c := range cs.Credentials {
			if !slices.Contains(prepared.byFormat[c.Format], c.ID) {
				prepared.byFormat[c.Format] = append(prepared.byFormat[c.Format], c.ID)
			}
		}
	}
	// One option per format: exactly what Send would present in that
	// format, claim sets included, for the holder to see before
	// choosing.
	for _, format := range []string{"mso_mdoc", "dc+sd-jwt"} {
		ids := prepared.byFormat[format]
		if len(ids) == 0 {
			continue
		}
		disclosed, err := p.Preview(ctx, ids)
		if err != nil {
			continue
		}
		for _, d := range disclosed {
			prepared.Options = append(prepared.Options, Option{Format: format, QueryID: d.QueryID, Claims: pathStrings(d.Claims)})
		}
	}
	if len(prepared.Options) == 0 {
		return nil, fmt.Errorf("walletapp: no stored credential satisfies the request")
	}
	return prepared, nil
}

// Send answers the request with the stored credentials of format (""
// for whichever the query chooses): selectively disclosed presentations
// bound to the verifier's nonce, POSTed to the response_uri as an
// encrypted direct_post.jwt response.
func (p *Prepared) Send(ctx context.Context, format string) (Presented, error) {
	var ids []string
	if format != "" {
		if ids = p.byFormat[format]; len(ids) == 0 {
			return Presented{}, fmt.Errorf("walletapp: no stored %s credential answers the request", format)
		}
	}
	presented, err := p.p.Respond(ctx, ids)
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
