package issuer_test

// Several Credential Issuers on one fapigo/server Authorization Server,
// each serving its Credential Endpoint through issuer/fapiresource over
// its own serverresource.NewVerifier. A pre-authorized access token is
// issued for the Credential Issuer that redeemed the code, and another
// Credential Issuer refuses it rather than issue its own holder's
// Credential for the token's subject, which is meaningful to the first
// issuer only.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/keys/ephemeral"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/serverresource"
	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/attestation"
	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/haip"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/jwk"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/issuer"
	"github.com/idfoundry/oid4vcgo/issuer/fapiresource"
	oid4vcstorage "github.com/idfoundry/oid4vcgo/storage"
)

const (
	sharedASAS             = "https://as.example.com"
	sharedASTenantA        = "https://tenant-a.example.com"
	sharedASTenantB        = "https://tenant-b.example.com"
	sharedASWalletProvider = "https://wallet-provider.example.com"
	sharedASClientID       = "wallet"
	sharedASPreAuthGrant   = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
)

func sharedASURL(t *testing.T, raw string) fapi.URL {
	t.Helper()
	u, err := fapi.ParseEndpointURL(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// sharedASServer is the shared Authorization Server, wired as haip's own
// tests and walletflowtest wire one: HAIP config, the pre-authorized
// code grant as an additional grant type, attestation-based client
// authentication, serving resources (RFC 8707), with refresh tokens.
// Its wallet client isn't confined by AllowedResources.
func sharedASServer(t *testing.T, wpRoots *x509.CertPool, resources ...string) (*server.Server, server.Config, server.Dependencies) {
	t.Helper()
	cfg, err := haip.RecommendedAuthorizationServerConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Issuer, err = fapi.ParseIssuerURL(sharedASAS); err != nil {
		t.Fatal(err)
	}
	cfg.Endpoints = server.Endpoints{
		Authorization: sharedASURL(t, sharedASAS+"/authorize"), Token: sharedASURL(t, sharedASAS+"/token"),
		PushedAuthorizationRequest: sharedASURL(t, sharedASAS+"/par"), JWKS: sharedASURL(t, sharedASAS+"/jwks"),
	}
	cfg.Assurance = server.AssuranceDevelopment
	cfg.Limits.MaxClientAttestationLifetime = 24 * time.Hour
	cfg.Limits.RefreshTokenLifetime = time.Hour
	cfg.AdditionalGrantTypes = []string{sharedASPreAuthGrant}
	cfg.Resources = resources
	keyManager, err := ephemeral.NewKeyManager(map[keys.SigningPurpose]fapi.SignatureAlgorithm{keys.AccessTokenSigning: fapi.ES256})
	if err != nil {
		t.Fatal(err)
	}
	clientKeys, err := ephemeral.NewClientKeySource(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	deps := server.Dependencies{
		Clients: sharedASClients(t), Transactions: memstore.NewTransactionStore(),
		Grants: memstore.NewGrantStore(), Replay: memstore.NewReplayStore(), ClientKeys: clientKeys, Keys: keyManager,
		AccessTokens: server.JWTAccessTokens{Keys: keyManager, Algorithm: fapi.ES256}, Revocation: memstore.NewRevocationStore(),
		Clock: server.SystemClock{}, Random: rand.Reader, ClientCertificateTrust: server.NoPKIClientAuthentication{},
		AttesterTrust: server.X5CAttesterChain{
			TrustAnchors:  server.StaticAttesterTrustAnchors{Roots: wpRoots},
			IssuerBinding: server.AttesterIssuerInCertificate,
			Revocation:    server.NoClientCertificateRevocationCheck{},
		},
	}
	srv, err := server.New(cfg, deps)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	return srv, cfg, deps
}

// sharedASClients registers the wallet client, confined by
// storage.RegisteredClientConfig.AllowedResources to allowed (none:
// unconfined).
func sharedASClients(t *testing.T, allowed ...string) storage.ClientRepository {
	t.Helper()
	clientCfg := haip.RecommendedWalletClient(sharedASClientID, sharedASWalletProvider)
	clientCfg.ApplicationType = storage.ApplicationTypeNative
	clientCfg.RedirectURIs = []fapi.RegisteredRedirectURI{"com.example.wallet:/callback"}
	clientCfg.AllowedScopes = []string{"diploma"}
	clientCfg.AllowedResources = allowed
	client, err := storage.NewRegisteredClient(clientCfg)
	if err != nil {
		t.Fatal(err)
	}
	return memstore.NewClientRepository([]storage.RegisteredClient{client})
}

type sharedASTenant struct {
	iss     *issuer.Issuer
	handler http.Handler
	url     string
}

// sharedASNewTenant is one Credential Issuer of the deployment: its own
// signer, its own pre-authorized codes, a "diploma" configuration
// granted by the "diploma" scope, and a Prepare that looks up what to
// issue by grant.Subject in its own user database (issuer's documented
// recipe). resource is serverresource.Options.Resource ("" accepts
// tokens addressed to the Authorization Server), accepted
// Config.AcceptedAccessTokenAudiences. A tenant whose base is the
// Authorization Server's own identifier is co-hosted with it: its
// Config.AuthorizationServers is empty.
func sharedASNewTenant(t *testing.T, base string, asCfg server.Config, asDeps server.Dependencies, resource string, accepted []fapi.URL, db map[string]string) sharedASTenant {
	t.Helper()
	var servers []fapi.URL
	if base != sharedASAS {
		servers = []fapi.URL{sharedASURL(t, sharedASAS)}
	}
	ca, caKey := testcert.CA(t, base+" CA")
	u, _ := url.Parse(base)
	signerCert, signerKey := testcert.Issue(t, &x509.Certificate{Subject: pkix.Name{CommonName: base}, URIs: []*url.URL{u}}, ca, caKey)
	iss, err := issuer.New(issuer.Config{
		Assurance: issuer.AssuranceDevelopment,
		Issuer:    sharedASURL(t, base),
		Endpoints: issuer.Endpoints{Credential: sharedASURL(t, base+"/credential")},
		Limits: issuer.Limits{
			NonceLifetime: 5 * time.Minute, AccessTokenLifetime: asCfg.Limits.AccessTokenLifetime,
			MaxTxCodeAttempts: 3, MaxProofAge: time.Minute,
		},
		PreAuthorizedCodeClientAuthentication: issuer.VerifiedPreAuthorizedCode{},
		AuthorizationServers:                  servers,
		AcceptedAccessTokenAudiences:          accepted,
		CredentialConfigurationsSupported: map[string]issuer.CredentialConfiguration{
			"diploma": {
				Format: sdjwtvc.CredentialFormat, VCT: base + "/diploma", Scope: "diploma",
				CryptographicBindingMethodsSupported: []string{"jwk"},
				ProofTypesSupported: map[string]oid4vci.ProofTypeConfiguration{
					oid4vci.ProofTypeJWT: {ProofSigningAlgValuesSupported: []string{oid4vci.ES256}},
				},
			},
		},
	}, issuer.Dependencies{
		Nonces: oid4vcstorage.NewNonceStore(), PreAuthorizedCodes: oid4vcstorage.NewPreAuthorizedCodeStore(),
		Clock: issuer.ClockFunc(time.Now), Random: rand.Reader,
		SDJWTSigner: &issuer.SDJWTSigner{Signer: signerKey, Alg: oid4vci.ES256, IssuerCertificate: signerCert},
	})
	if err != nil {
		t.Fatalf("issuer.New(%s): %v", base, err)
	}
	verifier, err := serverresource.NewVerifier(asCfg, asDeps, serverresource.Options{
		ResourceURLs: []fapi.URL{sharedASURL(t, base)}, Resource: resource,
	})
	if err != nil {
		t.Fatalf("serverresource.NewVerifier(%s): %v", base, err)
	}
	tokens, err := fapiresource.New(verifier)
	if err != nil {
		t.Fatal(err)
	}
	credURL, _ := url.Parse(base + "/credential")
	handler, err := iss.CredentialHandler(issuer.CredentialHandlerConfig{
		URL: credURL, Tokens: tokens,
		Prepare: func(_ context.Context, grant issuer.Grant, req *issuer.CredentialRequest) (func(bool), error) {
			name, ok := db[grant.Subject]
			if !ok {
				return nil, issuer.NewError(issuer.ErrorCredentialRequestDenied, "no such holder")
			}
			req.SDJWTClaims = &sdjwtvc.Claims{VCT: base + "/diploma", Additional: map[string]any{"holder_name": name, "tenant": base}}
			return nil, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return sharedASTenant{iss: iss, handler: handler, url: base}
}

func sharedASB64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func sharedASJWK(t *testing.T, pub *ecdsa.PublicKey) map[string]any {
	t.Helper()
	k, err := jwk.Marshal(pub)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(k)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func sharedASSign(t *testing.T, key *ecdsa.PrivateKey, header map[string]any, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	compact, err := jose.Sign(jose.ES256, key, header, payload)
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

func sharedASDPoP(t *testing.T, key *ecdsa.PrivateKey, method, htu, accessToken string) string {
	t.Helper()
	claims := map[string]any{"jti": rand.Text(), "htm": method, "htu": htu, "iat": time.Now().Unix()}
	if accessToken != "" {
		sum := sha256.Sum256([]byte(accessToken))
		claims["ath"] = sharedASB64(sum[:])
	}
	return sharedASSign(t, key, map[string]any{"typ": "dpop+jwt", "jwk": sharedASJWK(t, &key.PublicKey)}, claims)
}

// sharedASCredentialRequest posts a Credential Request for "diploma" to
// tenant's handler with the DPoP-bound accessToken, and a jwt proof for
// tenant signed by holderKey.
func sharedASCredentialRequest(t *testing.T, tenant sharedASTenant, accessToken string, dpopKey, holderKey *ecdsa.PrivateKey) (int, map[string]any) {
	t.Helper()
	proof := sharedASSign(t, holderKey, map[string]any{"typ": "openid4vci-proof+jwt", "jwk": sharedASJWK(t, &holderKey.PublicKey)},
		map[string]any{"aud": tenant.url, "iat": time.Now().Unix()})
	body, _ := json.Marshal(map[string]any{"credential_configuration_id": "diploma", "proofs": map[string]any{"jwt": []string{proof}}})
	r := httptest.NewRequest(http.MethodPost, tenant.url+"/credential", strings.NewReader(string(body)))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "DPoP "+accessToken)
	r.Header.Set("DPoP", sharedASDPoP(t, dpopKey, http.MethodPost, tenant.url+"/credential", accessToken))
	w := httptest.NewRecorder()
	tenant.handler.ServeHTTP(w, r)
	raw, _ := io.ReadAll(w.Result().Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return w.Code, out
}

// sharedASClaims extracts the issued SD-JWT VC's disclosed claims.
func sharedASClaims(t *testing.T, resp map[string]any) map[string]any {
	t.Helper()
	creds, _ := resp["credentials"].([]any)
	if len(creds) == 0 {
		t.Fatalf("no credentials in %v", resp)
	}
	compact, _ := creds[0].(map[string]any)["credential"].(string)
	pres, err := sdjwtvc.Parse(compact)
	if err != nil {
		t.Fatalf("parse issued SD-JWT VC: %v", err)
	}
	claims := map[string]any{}
	parts := strings.Split(pres.IssuerJWT, ".")
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	_ = json.Unmarshal(payload, &claims)
	for _, d := range pres.Disclosures {
		claims[d.Name] = d.Value
	}
	return claims
}

// sharedASRedeem has tenant redeem a pre-authorized code it offered to
// subject, with a Wallet Attestation, its PoP and DPoP, and the
// Authorization Server issue its access token, restricted to the
// redemption's Resource when restrict is set. It returns the token,
// its DPoP key and the redemption.
func sharedASRedeem(t *testing.T, provider sharedASProvider, srv *server.Server, tenant sharedASTenant, subject string, restrict bool) (string, *ecdsa.PrivateKey, issuer.RedeemedPreAuthorizedCode) {
	t.Helper()
	token, dpopKey, redeemed, err := sharedASRedeemNaming(t, provider, srv, tenant, subject, restrict)
	if err != nil {
		t.Fatalf("RedeemPreAuthorizedCode: %v", err)
	}
	return token, dpopKey, redeemed
}

// sharedASRedeemNaming is sharedASRedeem with the Token Request naming
// resources, which the Token Endpoint passes to RedeemPreAuthorizedCode;
// it returns RedeemPreAuthorizedCode's error.
func sharedASRedeemNaming(t *testing.T, provider sharedASProvider, srv *server.Server, tenant sharedASTenant, subject string, restrict bool, resources ...string) (string, *ecdsa.PrivateKey, issuer.RedeemedPreAuthorizedCode, error) {
	t.Helper()
	w := newSharedASWallet(t, provider)
	token, redeemed, _, err := w.redeem(t, srv, tenant, subject, restrict, resources...)
	return token, w.dpopKey, redeemed, err
}

// sharedASWallet is one installation of the Wallet Provider's wallet:
// the instance key its Wallet Attestations bind, which its refresh
// tokens are bound to, and its DPoP key.
type sharedASWallet struct {
	provider    sharedASProvider
	instanceKey *ecdsa.PrivateKey
	dpopKey     *ecdsa.PrivateKey
}

func newSharedASWallet(t *testing.T, provider sharedASProvider) sharedASWallet {
	t.Helper()
	instanceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dpopKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return sharedASWallet{provider: provider, instanceKey: instanceKey, dpopKey: dpopKey}
}

// tokenRequest is a Token Request with form, authenticated by a fresh
// Wallet Attestation and its PoP, with a DPoP proof.
func (w sharedASWallet) tokenRequest(t *testing.T, form url.Values) server.TokenEndpointRequest {
	t.Helper()
	now := time.Now()
	wa, err := attestation.IssueWalletAttestation(w.provider.key, oid4vci.ES256, attestation.Header{X5C: []string{base64.StdEncoding.EncodeToString(w.provider.attester.Raw)}}, attestation.WalletAttestationClaims{
		Issuer: sharedASWalletProvider, Subject: sharedASClientID, InstanceKey: &w.instanceKey.PublicKey,
		IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	pop := sharedASSign(t, w.instanceKey, map[string]any{"typ": "oauth-client-attestation-pop+jwt"},
		map[string]any{"iss": sharedASClientID, "aud": sharedASAS, "jti": rand.Text(), "iat": now.Unix()})
	hr := httptest.NewRequest(http.MethodPost, sharedASAS+"/token", strings.NewReader(form.Encode()))
	hr.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	hr.Header.Set("OAuth-Client-Attestation", wa)
	hr.Header.Set("OAuth-Client-Attestation-PoP", pop)
	hr.Header.Set("DPoP", sharedASDPoP(t, w.dpopKey, http.MethodPost, sharedASAS+"/token", ""))
	treq, err := server.TokenEndpointRequestFromHTTP(hr)
	if err != nil {
		t.Fatal(err)
	}
	return treq
}

// redeem has tenant redeem a pre-authorized code it offered to subject,
// at a Token Request naming resources, and the Authorization Server
// issue its access token, restricted to the redemption's Resource when
// restrict is set. It returns the token, the redemption and the access
// token's request, to issue the grant's refresh token from; and
// RedeemPreAuthorizedCode's error.
func (w sharedASWallet) redeem(t *testing.T, srv *server.Server, tenant sharedASTenant, subject string, restrict bool, resources ...string) (string, issuer.RedeemedPreAuthorizedCode, server.IssueAccessTokenRequest, error) {
	t.Helper()
	ctx := context.Background()
	code := rand.Text()
	if err := tenant.iss.IssuePreAuthorizedCode(ctx, code, "", issuer.PreAuthorizedCodeRecord{
		Subject: subject, Scopes: []string{"diploma"}, ExpiresAt: time.Now().Add(10 * time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	treq := w.tokenRequest(t, url.Values{"grant_type": {sharedASPreAuthGrant}, "pre-authorized_code": {code}, "resource": resources})
	attested, err := srv.AuthenticateAttestedClient(ctx, treq.AttestedClientAuthentication())
	if err != nil {
		t.Fatalf("AuthenticateAttestedClient: %v", err)
	}
	binding, err := srv.VerifyTokenRequestBinding(ctx, attested.Client, treq)
	if err != nil {
		t.Fatalf("VerifyTokenRequestBinding: %v", err)
	}
	redeemed, err := tenant.iss.RedeemPreAuthorizedCode(ctx, issuer.ExchangePreAuthorizedCodeRequest{
		PreAuthorizedCode: code, Resources: treq.Resources(),
		Verified: &issuer.VerifiedTokenRequest{ClientID: attested.Client.ID().String(), DPoPThumbprint: binding.Thumbprint},
	})
	if err != nil {
		return "", redeemed, server.IssueAccessTokenRequest{}, err
	}
	subjectID, err := server.NewSubjectID(redeemed.Subject)
	if err != nil {
		t.Fatal(err)
	}
	req := server.IssueAccessTokenRequest{
		GrantType: sharedASPreAuthGrant, Client: attested, Binding: binding, Subject: subjectID, Scope: redeemed.Scope,
	}
	if restrict {
		req.Resources = []string{redeemed.Resource}
	}
	result, err := srv.IssueAccessToken(ctx, req)
	if err != nil {
		t.Fatalf("IssueAccessToken: %v", err)
	}
	return result.AccessToken.Reveal(), redeemed, req, nil
}

// refresh redeems refreshToken at srv as this wallet installation,
// naming no resource.
func (w sharedASWallet) refresh(t *testing.T, srv *server.Server, refreshToken fapi.Secret) (string, error) {
	t.Helper()
	treq := w.tokenRequest(t, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken.Reveal()}})
	result, err := srv.RefreshAccessToken(context.Background(), treq.RefreshToken())
	if err != nil {
		return "", err
	}
	return result.AccessToken.Reveal(), nil
}

// sharedASAudience is the access token's "aud".
func sharedASAudience(t *testing.T, accessToken string) any {
	t.Helper()
	parts := strings.Split(accessToken, ".")
	if len(parts) != 3 {
		t.Fatalf("access token isn't a JWT")
	}
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	return claims["aud"]
}

// sharedASProvider is the Wallet Provider: its CA's roots, and the
// attester certificate and key it signs Wallet Attestations with.
type sharedASProvider struct {
	roots    *x509.CertPool
	attester *x509.Certificate
	key      *ecdsa.PrivateKey
}

func newSharedASProvider(t *testing.T) sharedASProvider {
	t.Helper()
	wpCA, wpCAKey := testcert.CA(t, "wallet provider CA")
	p := sharedASProvider{roots: x509.NewCertPool()}
	p.roots.AddCert(wpCA)
	wpURL, _ := url.Parse(sharedASWalletProvider)
	p.attester, p.key = testcert.Issue(t, &x509.Certificate{Subject: pkix.Name{CommonName: sharedASWalletProvider}, URIs: []*url.URL{wpURL}}, wpCA, wpCAKey)
	return p
}

var (
	sharedASUsersA = map[string]string{"user-42": "tenant A's user-42"}
	sharedASUsersB = map[string]string{"user-42": "tenant B's user-42"}
)

// TestSharedAuthorizationServer_PreAuthorizedTokenBoundToItsIssuer: a
// token issued with RedeemedPreAuthorizedCode.Resource names the
// Credential Issuer that redeemed the code, which accepts it, and
// another Credential Issuer refuses it, with its verifier pinned to
// its own identifier or not.
func TestSharedAuthorizationServer_PreAuthorizedTokenBoundToItsIssuer(t *testing.T) {
	provider := newSharedASProvider(t)
	srv, asCfg, asDeps := sharedASServer(t, provider.roots, sharedASTenantA, sharedASTenantB)
	tenantA := sharedASNewTenant(t, sharedASTenantA, asCfg, asDeps, sharedASTenantA, nil, sharedASUsersA)
	tenantB := sharedASNewTenant(t, sharedASTenantB, asCfg, asDeps, sharedASTenantB, nil, sharedASUsersB)
	tenantBUnpinned := sharedASNewTenant(t, sharedASTenantB, asCfg, asDeps, "", nil, sharedASUsersB)

	accessToken, dpopKey, redeemed := sharedASRedeem(t, provider, srv, tenantA, "user-42", true)
	if redeemed.Resource != sharedASTenantA {
		t.Fatalf("RedeemedPreAuthorizedCode.Resource = %q, want %q", redeemed.Resource, sharedASTenantA)
	}
	if aud := sharedASAudience(t, accessToken); aud != sharedASTenantA {
		t.Fatalf("access token aud = %v, want %s", aud, sharedASTenantA)
	}
	holderKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	status, resp := sharedASCredentialRequest(t, tenantA, accessToken, dpopKey, holderKey)
	if status != http.StatusOK {
		t.Fatalf("tenant A refused its own token: %d %v", status, resp)
	}
	if name := sharedASClaims(t, resp)["holder_name"]; name != sharedASUsersA["user-42"] {
		t.Fatalf("tenant A issued holder_name %v", name)
	}
	for name, tenant := range map[string]sharedASTenant{"pinned": tenantB, "unpinned": tenantBUnpinned} {
		status, resp := sharedASCredentialRequest(t, tenant, accessToken, dpopKey, holderKey)
		if status != http.StatusUnauthorized || resp["error"] != "invalid_token" {
			t.Errorf("tenant B (%s) answered tenant A's token: %d %v, want 401 invalid_token", name, status, resp)
		}
	}
}

// TestSharedAuthorizationServer_AuthorizationServerAudience: a token
// addressed to the Authorization Server itself, as one issued without
// a resource is, is refused by a Credential Issuer whose verifier
// accepts it (no serverresource Options.Resource), unless its
// Config.AcceptedAccessTokenAudiences lists the Authorization Server,
// as one served alone by it may.
func TestSharedAuthorizationServer_AuthorizationServerAudience(t *testing.T) {
	provider := newSharedASProvider(t)
	srv, asCfg, asDeps := sharedASServer(t, provider.roots)
	tenantA := sharedASNewTenant(t, sharedASTenantA, asCfg, asDeps, "", nil, sharedASUsersA)
	soleTenantA := sharedASNewTenant(t, sharedASTenantA, asCfg, asDeps, "", []fapi.URL{sharedASURL(t, sharedASAS)}, sharedASUsersA)
	tenantB := sharedASNewTenant(t, sharedASTenantB, asCfg, asDeps, "", nil, sharedASUsersB)

	accessToken, dpopKey, _ := sharedASRedeem(t, provider, srv, tenantA, "user-42", false)
	if aud := sharedASAudience(t, accessToken); aud != sharedASAS {
		t.Fatalf("access token aud = %v, want %s", aud, sharedASAS)
	}
	holderKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	for name, tenant := range map[string]sharedASTenant{"tenant A": tenantA, "tenant B": tenantB} {
		status, resp := sharedASCredentialRequest(t, tenant, accessToken, dpopKey, holderKey)
		if status != http.StatusUnauthorized || resp["error"] != "invalid_token" {
			t.Errorf("%s answered a token addressed to the Authorization Server: %d %v, want 401 invalid_token", name, status, resp)
		}
	}
	status, resp := sharedASCredentialRequest(t, soleTenantA, accessToken, dpopKey, holderKey)
	if status != http.StatusOK {
		t.Fatalf("tenant A accepting the Authorization Server's audience refused: %d %v", status, resp)
	}
}

// TestSharedAuthorizationServer_PreAuthorizedRequestNamingAnotherIssuer:
// a pre-authorized Token Request naming another Credential Issuer as
// its resource is refused with invalid_target, rather than getting a
// token tenant B takes for its own user-42; one naming the redeeming
// Credential Issuer gets its token.
func TestSharedAuthorizationServer_PreAuthorizedRequestNamingAnotherIssuer(t *testing.T) {
	provider := newSharedASProvider(t)
	srv, asCfg, asDeps := sharedASServer(t, provider.roots, sharedASTenantA, sharedASTenantB)
	tenantA := sharedASNewTenant(t, sharedASTenantA, asCfg, asDeps, sharedASTenantA, nil, sharedASUsersA)

	for name, resources := range map[string][]string{
		"tenant B":             {sharedASTenantB},
		"tenant A, then B":     {sharedASTenantA, sharedASTenantB},
		"tenant A's near miss": {sharedASTenantA + "/"},
	} {
		_, _, _, err := sharedASRedeemNaming(t, provider, srv, tenantA, "user-42", true, resources...)
		var ierr *issuer.Error
		if !errors.As(err, &ierr) || ierr.Code() != issuer.ErrorInvalidTarget || ierr.HTTPStatus() != http.StatusBadRequest {
			t.Errorf("a Token Request naming %s: %v, want 400 invalid_target", name, err)
		}
	}

	accessToken, _, _, err := sharedASRedeemNaming(t, provider, srv, tenantA, "user-42", true, sharedASTenantA)
	if err != nil {
		t.Fatalf("a Token Request naming tenant A: %v", err)
	}
	if aud := sharedASAudience(t, accessToken); aud != sharedASTenantA {
		t.Errorf("access token aud = %v, want %s", aud, sharedASTenantA)
	}
}

// TestSharedAuthorizationServer_CoHostedIssuer: tenant A shares the
// Authorization Server's identifier, so it takes every token the
// Authorization Server issues without a resource, from any tenant's
// grant, for its own. With the wallet client confined by
// AllowedResources to both Credential Issuers, the Authorization
// Server issues no such token: tenant B's refresh token, issued with
// the redemption's Resource, refreshes into a token tenant B alone
// takes; one issued without Resources is refused, and so is the refresh
// of one issued without Resources before the client was confined, whose
// wallet must authorize again.
func TestSharedAuthorizationServer_CoHostedIssuer(t *testing.T) {
	ctx := context.Background()
	provider := newSharedASProvider(t)
	unconfined, asCfg, asDeps := sharedASServer(t, provider.roots, sharedASAS, sharedASTenantB)
	confinedDeps := asDeps
	confinedDeps.Clients = sharedASClients(t, sharedASAS, sharedASTenantB)
	srv, err := server.New(asCfg, confinedDeps)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	tenantA := sharedASNewTenant(t, sharedASAS, asCfg, asDeps, sharedASAS, nil, sharedASUsersA)
	tenantB := sharedASNewTenant(t, sharedASTenantB, asCfg, asDeps, sharedASTenantB, nil, sharedASUsersB)
	holderKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	w := newSharedASWallet(t, provider)
	_, redeemed, grant, err := w.redeem(t, srv, tenantB, "user-42", true)
	if err != nil {
		t.Fatal(err)
	}
	refreshReq := server.IssueRefreshTokenRequest(grant)
	refreshReq.Resources = []string{redeemed.Resource}
	refreshToken, err := srv.IssueRefreshToken(ctx, refreshReq)
	if err != nil {
		t.Fatalf("IssueRefreshToken with the redemption's Resource: %v", err)
	}
	refreshed, err := w.refresh(t, srv, refreshToken)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if aud := sharedASAudience(t, refreshed); aud != sharedASTenantB {
		t.Errorf("refreshed access token aud = %v, want %s", aud, sharedASTenantB)
	}
	if status, resp := sharedASCredentialRequest(t, tenantB, refreshed, w.dpopKey, holderKey); status != http.StatusOK {
		t.Errorf("tenant B refused its refreshed token: %d %v", status, resp)
	}
	if status, resp := sharedASCredentialRequest(t, tenantA, refreshed, w.dpopKey, holderKey); status != http.StatusUnauthorized || resp["error"] != "invalid_token" {
		t.Errorf("tenant A answered tenant B's refreshed token: %d %v, want 401 invalid_token", status, resp)
	}

	// Without a resource, the Authorization Server issues neither.
	refreshReq.Resources = nil
	if _, err := srv.IssueRefreshToken(ctx, refreshReq); !sharedASInvalidTarget(err) {
		t.Errorf("IssueRefreshToken without Resources: %v, want invalid_target", err)
	}
	grant.Resources = nil
	if _, err := srv.IssueAccessToken(ctx, grant); !sharedASInvalidTarget(err) {
		t.Errorf("IssueAccessToken without Resources: %v, want invalid_target", err)
	}

	// A refresh token issued without Resources before the client was
	// confined: refreshing it is refused.
	old := newSharedASWallet(t, provider)
	_, _, oldGrant, err := old.redeem(t, unconfined, tenantB, "user-42", true)
	if err != nil {
		t.Fatal(err)
	}
	oldRefreshReq := server.IssueRefreshTokenRequest(oldGrant)
	oldRefreshReq.Resources = nil
	oldRefreshToken, err := unconfined.IssueRefreshToken(ctx, oldRefreshReq)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := old.refresh(t, srv, oldRefreshToken); !sharedASInvalidTarget(err) {
		t.Errorf("refreshing a grant made without resources before the client was confined: %v, want invalid_target", err)
	}
}

// TestSharedAuthorizationServer_RefreshWithoutResource: on an
// Authorization Server with its own identifier, a refresh token issued
// without Resources, as one issued before the Credential Issuers
// restricted their tokens was, refreshes into a token addressed to the
// Authorization Server, which neither Credential Issuer takes; one
// issued with the redemption's Resource refreshes into a token for that
// Credential Issuer.
func TestSharedAuthorizationServer_RefreshWithoutResource(t *testing.T) {
	ctx := context.Background()
	provider := newSharedASProvider(t)
	srv, asCfg, asDeps := sharedASServer(t, provider.roots, sharedASTenantA, sharedASTenantB)
	tenantA := sharedASNewTenant(t, sharedASTenantA, asCfg, asDeps, sharedASTenantA, nil, sharedASUsersA)
	tenantB := sharedASNewTenant(t, sharedASTenantB, asCfg, asDeps, sharedASTenantB, nil, sharedASUsersB)
	holderKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	for name, restrict := range map[string]bool{"without Resources": false, "with the redemption's Resource": true} {
		w := newSharedASWallet(t, provider)
		_, redeemed, grant, err := w.redeem(t, srv, tenantB, "user-42", true)
		if err != nil {
			t.Fatal(err)
		}
		refreshReq := server.IssueRefreshTokenRequest(grant)
		refreshReq.Resources = nil
		if restrict {
			refreshReq.Resources = []string{redeemed.Resource}
		}
		refreshToken, err := srv.IssueRefreshToken(ctx, refreshReq)
		if err != nil {
			t.Fatalf("%s: IssueRefreshToken: %v", name, err)
		}
		refreshed, err := w.refresh(t, srv, refreshToken)
		if err != nil {
			t.Fatalf("%s: refresh: %v", name, err)
		}
		statusA, _ := sharedASCredentialRequest(t, tenantA, refreshed, w.dpopKey, holderKey)
		statusB, _ := sharedASCredentialRequest(t, tenantB, refreshed, w.dpopKey, holderKey)
		if statusA != http.StatusUnauthorized {
			t.Errorf("%s: tenant A answered tenant B's refreshed token with %d, want 401", name, statusA)
		}
		if want := map[bool]int{false: http.StatusUnauthorized, true: http.StatusOK}[restrict]; statusB != want {
			t.Errorf("%s: tenant B answered its refreshed token (aud %v) with %d, want %d", name, sharedASAudience(t, refreshed), statusB, want)
		}
	}
}

// sharedASInvalidTarget reports whether err is fapigo/server's
// invalid_target.
func sharedASInvalidTarget(err error) bool {
	var serr *server.Error
	return errors.As(err, &serr) && serr.Code() == server.ErrorInvalidTarget
}
