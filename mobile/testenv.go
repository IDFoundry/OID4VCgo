//go:build mobiletest

package mobile

import (
	"context"
	"encoding/pem"

	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/mobile/internal/devjwk"
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
	// rv is a Verifier the registrar registered for family_name.
	rv *walletflowtest.Verifier
}

// StartTestEnv starts a TestEnv; deferIssuance has the issuer defer
// every credential until Decide.
func StartTestEnv(deferIssuance bool) (*TestEnv, error) {
	return StartBatchTestEnv(deferIssuance, 0)
}

// StartBatchTestEnv is StartTestEnv with an issuer offering batches of up
// to batchSize copies of a credential (none below 2).
func StartBatchTestEnv(deferIssuance bool, batchSize int) (*TestEnv, error) {
	env, err := walletflowtest.New(walletflowtest.Options{Defer: deferIssuance, BatchSize: batchSize})
	if err != nil {
		return nil, newError(CodeInternal, err)
	}
	v, err := env.StartVerifier()
	if err != nil {
		env.Close()
		return nil, newError(CodeInternal, err)
	}
	rv, err := env.StartRegisteredVerifier(dcql.Path{dcql.PathKey("family_name")}, dcql.Path{dcql.PathKey(walletflowtest.NameSpace), dcql.PathKey("family_name")})
	if err != nil {
		env.Close()
		return nil, newError(CodeInternal, err)
	}
	testHTTP.Store(env.HTTP)
	return &TestEnv{env: env, v: v, rv: rv}, nil
}

// Close stops the TestEnv.
func (e *TestEnv) Close() {
	testHTTP.Store(nil)
	e.env.Close()
}

// ConfigJSON is a NewWallet configuration for the TestEnv.
func (e *TestEnv) ConfigJSON() string {
	text, _ := marshal(config{
		ClientID: walletflowtest.ClientID, RedirectURI: walletflowtest.RedirectURI,
		IssuerRoots: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: e.env.IssuerCA.Raw})),
		VerifierRoots: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: e.v.CA.Raw})) +
			string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: e.rv.CA.Raw})),
		RegistrarRoots: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: e.env.RegistrarCA.Raw})),
		Development:    true,
		// The test issuer issues refresh tokens for offline_access.
		RequestRefresh: true,
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

// Revoke revokes every credential the issuer has issued: its status
// list then says so.
func (e *TestEnv) Revoke() { e.env.Revoke() }

// RevokeGrants revokes every authorization code grant so far: their
// refresh tokens are refused, and RefreshCredential is then
// reissue_required.
func (e *TestEnv) RevokeGrants() { e.env.RevokeGrants() }

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

// RegisteredRequest is Request from a Verifier registered (with a
// registrar registrar_roots trusts) for family_name only, asking for
// family_name and also extra, if set: a claim beyond its registration.
func (e *TestEnv) RegisteredRequest(format, extra string) (string, error) {
	claims := []string{"family_name"}
	if extra != "" {
		claims = append(claims, extra)
	}
	var q dcql.Query
	if format == "mso_mdoc" {
		mdoc, err := walletflowtest.MdocQuery("mdl", claims...)
		if err != nil {
			return "", wrapTest(err)
		}
		q.Credentials = []dcql.CredentialQuery{mdoc}
	} else {
		sdjwt, err := e.env.SDJWTQuery("pid", claims...)
		if err != nil {
			return "", wrapTest(err)
		}
		q.Credentials = []dcql.CredentialQuery{sdjwt}
	}
	id, link, err := e.rv.Begin(q)
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
	key, err := devjwk.ParseP256(instanceKeyJWK)
	if err != nil {
		return nil, err
	}
	jwt, err := t.p.WalletAttestation(context.Background(), clientID, key)
	return []byte(jwt), err
}

func (t testProvider) KeyAttestation(keysJWK []byte, nonce string) ([]byte, error) {
	keys, err := devjwk.ParseP256Set(keysJWK)
	if err != nil {
		return nil, err
	}
	jwt, err := t.p.KeyAttestation(context.Background(), keys, nonce)
	return []byte(jwt), err
}
