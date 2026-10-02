//go:build mobiletest

package mobile

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/walletflow/walletflowtest"
)

// TestEnv is an in-process HAIP issuer, Wallet Provider and OpenID4VP
// Verifier (walletflowtest), for the Swift package's end-to-end tests.
// It's only in a framework built with the mobiletest build tag, never in
// one an app ships; while one runs, every Wallet trusts its TLS
// certificate.
type TestEnv struct {
	env *walletflowtest.Env
	v   *walletflowtest.Verifier
}

// StartTestEnv starts a TestEnv; deferIssuance has the issuer defer
// every credential until Decide.
func StartTestEnv(deferIssuance bool) (*TestEnv, error) {
	env, err := walletflowtest.New(walletflowtest.Options{Defer: deferIssuance})
	if err != nil {
		return nil, newError(CodeInternal, err)
	}
	v, err := env.StartVerifier()
	if err != nil {
		env.Close()
		return nil, newError(CodeInternal, err)
	}
	testHTTP = env.HTTP
	return &TestEnv{env: env, v: v}, nil
}

// Close stops the TestEnv.
func (e *TestEnv) Close() {
	testHTTP = nil
	e.env.Close()
}

// ConfigJSON is a NewWallet configuration for the TestEnv.
func (e *TestEnv) ConfigJSON() string {
	text, _ := marshal(config{
		ClientID: walletflowtest.ClientID, RedirectURI: walletflowtest.RedirectURI,
		IssuerRoots:   string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: e.env.IssuerCA.Raw})),
		VerifierRoots: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: e.v.CA.Raw})),
		Development:   true,
	})
	return text
}

// Provider is the TestEnv's Wallet Provider.
func (e *TestEnv) Provider() WalletProvider { return testProvider{e.env.Provider} }

// AuthorizationCodeOffer returns an offer of both credentials (SD-JWT VC
// and mdoc) through the authorization code grant.
func (e *TestEnv) AuthorizationCodeOffer() (string, error) {
	uri, err := e.env.AuthorizationCodeOffer(walletflowtest.SDJWTConfigurationID, walletflowtest.MdocConfigurationID)
	return uri, wrapTest(err)
}

// PreAuthorizedOffer returns an offer of the SD-JWT VC through the
// pre-authorized code grant, redeemed with pin.
func (e *TestEnv) PreAuthorizedOffer(pin string) (string, error) {
	uri, err := e.env.PreAuthorizedOffer(pin, walletflowtest.SDJWTConfigurationID)
	return uri, wrapTest(err)
}

// Approve opens authorizationURL as the holder's browser, and returns
// the redirect back to the wallet: the issuer approves at once.
func (e *TestEnv) Approve(authorizationURL string) (string, error) {
	redirect, err := e.env.Approve(context.Background(), authorizationURL)
	return redirect, wrapTest(err)
}

// Decide approves or denies every deferred credential.
func (e *TestEnv) Decide(approve bool) { e.env.Decide(approve) }

// Request has the Verifier ask for family_name from an SD-JWT VC
// ("dc+sd-jwt"), an mdoc ("mso_mdoc"), or either ("") and returns
// {"id", "link"}.
func (e *TestEnv) Request(format string) (string, error) {
	sdjwt, err := e.env.SDJWTQuery("pid", "family_name")
	if err != nil {
		return "", wrapTest(err)
	}
	mdoc, err := walletflowtest.MdocQuery("mdl", "family_name")
	if err != nil {
		return "", wrapTest(err)
	}
	var q dcql.Query
	switch format {
	case "dc+sd-jwt":
		q.Credentials = []dcql.CredentialQuery{sdjwt}
	case "mso_mdoc":
		q.Credentials = []dcql.CredentialQuery{mdoc}
	default:
		q.Credentials = []dcql.CredentialQuery{mdoc, sdjwt}
		q.CredentialSets = []dcql.CredentialSetQuery{{Options: [][]string{{"mdl"}, {"pid"}}}}
	}
	id, link, err := e.v.Begin(q)
	if err != nil {
		return "", wrapTest(err)
	}
	return marshal(map[string]string{"id": id, "link": link})
}

// RequestResult returns the Verifier's view of request id: {"status":
// "pending" | "done", "claims": {…}, "last_error"}.
func (e *TestEnv) RequestResult(id string) (string, error) {
	view, err := e.v.Lookup(id)
	if err != nil {
		return "", wrapTest(err)
	}
	out := map[string]any{"status": "pending", "last_error": view.LastError}
	if view.Result != nil && len(view.Result.Credentials) > 0 {
		out["status"], out["claims"] = "done", view.Result.Credentials[0].Claims
	}
	return marshal(out)
}

func wrapTest(err error) error {
	if err == nil {
		return nil
	}
	return newError(CodeInternal, err)
}

// testProvider is walletflowtest's Wallet Provider as a WalletProvider.
type testProvider struct{ p *walletflowtest.Provider }

func (t testProvider) WalletAttestation(clientID string, instanceKeyJWK []byte) ([]byte, error) {
	key, err := parseJWK(instanceKeyJWK)
	if err != nil {
		return nil, err
	}
	jwt, err := t.p.WalletAttestation(context.Background(), clientID, key)
	return []byte(jwt), err
}

func (t testProvider) KeyAttestation(keysJWK []byte, nonce string) ([]byte, error) {
	var raw []json.RawMessage
	if err := json.Unmarshal(keysJWK, &raw); err != nil {
		return nil, err
	}
	keys := make([]*ecdsa.PublicKey, 0, len(raw))
	for _, r := range raw {
		k, err := parseJWK(r)
		if err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	jwt, err := t.p.KeyAttestation(context.Background(), keys, nonce)
	return []byte(jwt), err
}

// parseJWK parses a P-256 public JWK.
func parseJWK(raw []byte) (*ecdsa.PublicKey, error) {
	var jwk struct{ Kty, Crv, X, Y string }
	if err := json.Unmarshal(raw, &jwk); err != nil {
		return nil, err
	}
	if jwk.Kty != "EC" || jwk.Crv != "P-256" {
		return nil, fmt.Errorf("not a P-256 JWK: %s", raw)
	}
	x, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, err
	}
	y, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil {
		return nil, err
	}
	if len(x) != 32 || len(y) != 32 {
		return nil, errors.New("malformed P-256 coordinates")
	}
	return ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, x...), y...))
}
