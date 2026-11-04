package haip_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/fapihttp"
	"github.com/idfoundry/fapigo/server"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/attestation"
	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/haip"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/internal/teststatuslist"
	"github.com/idfoundry/oid4vcgo/issuer"
	"github.com/idfoundry/oid4vcgo/statuslist"
)

const walletProvider = "https://wallet-provider.example.com"

// attesterUnder issues a Wallet Attestation signing certificate naming
// provider, under ca.
func attesterUnder(t *testing.T, provider string, ca *x509.Certificate, caKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	u, err := url.Parse(provider)
	if err != nil {
		t.Fatal(err)
	}
	return testcert.Issue(t, &x509.Certificate{Subject: pkix.Name{CommonName: provider}, URIs: []*url.URL{u}}, ca, caKey)
}

// attestedRequest is a Wallet Attestation for the "wallet" client,
// signed by attester with status ("nil" for none), and its PoP for the
// Authorization Server issuerURL.
func attestedRequest(t *testing.T, attester *x509.Certificate, attesterKey *ecdsa.PrivateKey, issuerURL string, status map[string]any) server.AttestedClientAuthenticationRequest {
	t.Helper()
	instanceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	att, err := attestation.IssueWalletAttestation(attesterKey, oid4vci.ES256, attestation.Header{X5C: []string{base64.StdEncoding.EncodeToString(attester.Raw)}}, attestation.WalletAttestationClaims{
		Issuer: walletProvider, Subject: "wallet", InstanceKey: &instanceKey.PublicKey,
		IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(), Extra: attestation.WalletAttestationExtraClaims{Status: status},
	})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(map[string]any{"iss": "wallet", "aud": issuerURL, "jti": rand.Text(), "iat": now.Unix()})
	if err != nil {
		t.Fatal(err)
	}
	pop, err := jose.Sign(jose.ES256, instanceKey, map[string]any{"typ": "oauth-client-attestation-pop+jwt"}, payload)
	if err != nil {
		t.Fatal(err)
	}
	return server.AttestedClientAuthenticationRequest{ClientAttestations: []string{att}, ClientAttestationPoPs: []string{pop}}
}

// TestWalletAttestationStatusList_AuthorizationServer runs a real
// fapigo/server authenticating a Wallet Attestation with
// WalletAttestationStatusList as its ClientAttestationStatus: VALID
// authenticates; revoked, suspended or no status where one is required
// is invalid_client; a list another Wallet Provider under the same
// trust list signed, or one that can't be fetched, is server_error.
func TestWalletAttestationStatusList_AuthorizationServer(t *testing.T) {
	root, rootKey := testcert.CA(t, "shared trust list root")
	roots := x509.NewCertPool()
	roots.AddCert(root)
	attester, attesterKey := attesterUnder(t, walletProvider, root, rootKey)
	other, otherKey := attesterUnder(t, "https://other-wallet-provider.example.com", root, rootKey)
	for name, tc := range map[string]struct {
		publish  func(srv *teststatuslist.JWTServer)
		noStatus bool
		fapihttp bool
		idx      int
		want     server.ErrorCode
	}{
		"valid": {publish: func(srv *teststatuslist.JWTServer) {
			srv.Publish(t, attesterKey, []*x509.Certificate{attester}, 0, 1, 2)
		}},
		"valid, fetched with a fapihttp client": {
			publish: func(srv *teststatuslist.JWTServer) { srv.Publish(t, attesterKey, []*x509.Certificate{attester}, 0) }, fapihttp: true,
		},
		"revoked": {publish: func(srv *teststatuslist.JWTServer) {
			srv.Publish(t, attesterKey, []*x509.Certificate{attester}, 0, 1, 2)
		}, idx: 1, want: server.ErrorInvalidClient},
		"suspended": {publish: func(srv *teststatuslist.JWTServer) {
			srv.Publish(t, attesterKey, []*x509.Certificate{attester}, 0, 1, 2)
		}, idx: 2, want: server.ErrorInvalidClient},
		"no status": {publish: func(*teststatuslist.JWTServer) {}, noStatus: true, want: server.ErrorInvalidClient},
		"list signed by another Wallet Provider": {
			publish: func(srv *teststatuslist.JWTServer) { srv.Publish(t, otherKey, []*x509.Certificate{other}, 0) }, want: server.ErrorServerError,
		},
		"list unavailable": {publish: func(*teststatuslist.JWTServer) {}, want: server.ErrorServerError},
	} {
		t.Run(name, func(t *testing.T) {
			list := teststatuslist.ServeJWT(t)
			tc.publish(list)
			if tc.fapihttp {
				tlsRoots := x509.NewCertPool()
				tlsRoots.AddCert(list.Certificate)
				transport := fapihttp.RecommendedTransportConfig()
				transport.RootCAs = tlsRoots
				client, err := fapihttp.NewClient(transport)
				if err != nil {
					t.Fatal(err)
				}
				list.Fetcher.HTTP = client
			}
			cfg := completeAuthorizationServerConfig(t)
			deps := haipServerDependencies(t)
			deps.AttesterTrust = server.X5CAttesterChain{
				TrustAnchors:  server.StaticAttesterTrustAnchors{Roots: roots},
				IssuerBinding: server.AttesterIssuerInCertificate,
				Revocation:    server.NoClientCertificateRevocationCheck{},
			}
			status := haip.WalletAttestationStatusList{
				Checker:       statuslist.Checker{Fetcher: list.Fetcher, Roots: roots, Cache: statuslist.NewCache(statuslist.CacheOptions{})},
				RequireStatus: true,
			}
			if err := status.CheckConfiguration(cfg.Assurance); err != nil {
				t.Fatalf("CheckConfiguration: %v", err)
			}
			deps.ClientAttestationStatus = status
			srv, err := server.New(cfg, deps)
			if err != nil {
				t.Fatalf("server.New: %v", err)
			}
			claim := list.Claim(tc.idx)
			if tc.noStatus {
				claim = nil
			}
			_, err = srv.AuthenticateAttestedClient(context.Background(), attestedRequest(t, attester, attesterKey, cfg.Issuer.String(), claim))
			var serr *server.Error
			switch {
			case tc.want == "" && err != nil:
				t.Errorf("AuthenticateAttestedClient: %v", err)
			case tc.want != "" && (!errors.As(err, &serr) || serr.Code() != tc.want):
				t.Errorf("AuthenticateAttestedClient = %v, want %s", err, tc.want)
			case tc.want == server.ErrorInvalidClient && !errors.Is(err, issuer.ErrKeyAttestationRevoked):
				t.Errorf("AuthenticateAttestedClient = %v, want it to wrap the checker's refusal", err)
			}
		})
	}
}

// TestWalletAttestationStatusList_Claims: a status claim that can't be
// read refuses the attestation, as revoked.
func TestWalletAttestationStatusList_Claims(t *testing.T) {
	s := haip.WalletAttestationStatusList{Checker: statuslist.Checker{Roots: x509.NewCertPool()}}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{
		`null`, `"revoked"`, `[1]`, `{"identifier_list":{}}`,
		`{"status_list":{"idx":-1,"uri":"https://wallet-provider.example.com/1"}}`,
		`{"status_list":{"idx":0,"idx":1,"uri":"https://wallet-provider.example.com/1"}}`,
	} {
		err := s.CheckClientAttestationStatus(context.Background(), server.VerifiedClientAttestation{
			Claims: map[string]json.RawMessage{"status": json.RawMessage(raw)}, SignerKey: &key.PublicKey,
		})
		if !errors.Is(err, server.ErrClientAttestationRevoked) {
			t.Errorf("status %s: err = %v, want server.ErrClientAttestationRevoked", raw, err)
		}
	}
	if err := s.CheckClientAttestationStatus(context.Background(), server.VerifiedClientAttestation{SignerKey: &key.PublicKey}); err != nil {
		t.Errorf("no status, not required: %v", err)
	}
}

func TestWalletAttestationStatusList_CheckConfiguration(t *testing.T) {
	adequate := statuslist.Checker{
		Roots: x509.NewCertPool(), Options: statuslist.VerifyOptions{Revocation: certrevocation.NoCheck{}},
		Cache: statuslist.NewCache(statuslist.CacheOptions{}),
	}
	if err := (haip.WalletAttestationStatusList{Checker: adequate}).CheckConfiguration(server.AssuranceProduction); err != nil {
		t.Errorf("CheckConfiguration: %v", err)
	}
	unhardened := adequate
	unhardened.Fetcher.AllowLoopback = true
	s := haip.WalletAttestationStatusList{Checker: unhardened}
	if err := s.CheckConfiguration(server.AssuranceProduction); err == nil || !strings.Contains(err.Error(), "HardenedForProduction") {
		t.Errorf("CheckConfiguration(production) with a loopback Fetcher = %v, want a HardenedForProduction error", err)
	}
	if err := s.CheckConfiguration(server.AssuranceDevelopment); err != nil {
		t.Errorf("CheckConfiguration(development) with a loopback Fetcher: %v", err)
	}
}
