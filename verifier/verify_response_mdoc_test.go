package verifier_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/internal/cose"
	"github.com/idfoundry/oid4vcgo/internal/testmdoc"
	"github.com/idfoundry/oid4vcgo/internal/testverify"
	"github.com/idfoundry/oid4vcgo/oid4vpmdoc"
	"github.com/idfoundry/oid4vcgo/verifier"
)

// fixedMdocIssuerKeyResolver always resolves to the one issuer key a
// test signed with — the mdoc analog of fixedSDJWTVCIssuerKeyResolver.
type fixedMdocIssuerKeyResolver struct {
	pub crypto.PublicKey
	alg cose.Alg
}

func (r fixedMdocIssuerKeyResolver) ResolveMdocIssuerKey(context.Context, [][]byte, string) (crypto.PublicKey, cose.Alg, error) {
	return r.pub, r.alg, nil
}

// mdocVerifyFixture bundles a real *verifier.Verifier, the DCQL query
// it was given, the Nonce/ResponseDecryptionKey a prior Build*Request
// call returned, and a real issued "mso_mdoc" credential's own
// response-encryption thumbprint — the setup every VerifyResponse
// mdoc test needs before building its own Presentation with whichever
// aud/nonce that specific case wants. Origin is empty for the
// redirect flow (newMdocVerifyFixture), set for the DC API flow
// (newMdocDCAPIVerifyFixture) — verify's own single implementation
// dispatches on it rather than each flow needing its own copy.
type mdocVerifyFixture struct {
	v                     *verifier.Verifier
	cfg                   verifier.Config
	query                 dcql.Query
	nonce                 string
	responseDecryptionKey *ecdsa.PrivateKey
	thumbprint            []byte
	f                     testmdoc.Fixture
	origin                string
}

func newMdocVerifyFixture(t *testing.T) mdocVerifyFixture {
	t.Helper()
	cfg, deps := validConfig(t)
	v, err := verifier.New(cfg, deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	query := testmdoc.Query(t)
	built, err := v.BuildAuthorizationRequest(verifier.BuildAuthorizationRequestRequest{Query: query})
	if err != nil {
		t.Fatalf("BuildAuthorizationRequest: %v", err)
	}
	return newMdocVerifyFixtureFromKey(t, v, cfg, query, built.Nonce, built.ResponseDecryptionKey, "")
}

// newMdocDCAPIVerifyFixture is newMdocVerifyFixture's own DC API
// counterpart, built via BuildDCAPIAuthorizationRequest instead.
func newMdocDCAPIVerifyFixture(t *testing.T) mdocVerifyFixture {
	t.Helper()
	v := newTestVerifier(t)
	query := testmdoc.Query(t)
	origin := "https://verifier.example.com"
	built, err := v.BuildDCAPIAuthorizationRequest(verifier.BuildDCAPIAuthorizationRequestRequest{
		Query: query, ExpectedOrigins: []string{origin},
	})
	if err != nil {
		t.Fatalf("BuildDCAPIAuthorizationRequest: %v", err)
	}
	return newMdocVerifyFixtureFromKey(t, v, verifier.Config{}, query, built.Nonce, built.ResponseDecryptionKey, origin)
}

func newMdocVerifyFixtureFromKey(t *testing.T, v *verifier.Verifier, cfg verifier.Config, query dcql.Query, nonce string, responseDecryptionKey *ecdsa.PrivateKey, origin string) mdocVerifyFixture {
	t.Helper()
	thumbprint := testmdoc.ResponseEncryptionThumbprint(t, responseDecryptionKey)
	f := testmdoc.Issue(t)
	return mdocVerifyFixture{
		v: v, cfg: cfg, query: query, nonce: nonce, responseDecryptionKey: responseDecryptionKey,
		thumbprint: thumbprint, f: f, origin: origin,
	}
}

// verify builds a Presentation bound to nonce (not necessarily
// mf.nonce — a test deliberately mismatching it uses this to build
// one that won't validate) and calls VerifyResponse with it, via
// whichever flow mf.origin selects.
func (mf mdocVerifyFixture) verify(t *testing.T, nonce string) (verifier.VerifyResponseResult, error) {
	t.Helper()
	return mf.verifyWith(t, nonce, func(*verifier.VerifyResponseRequest) {})
}

// verifyWith is verify, with mutate applied to the VerifyResponseRequest.
func (mf mdocVerifyFixture) verifyWith(t *testing.T, nonce string, mutate func(*verifier.VerifyResponseRequest)) (verifier.VerifyResponseResult, error) {
	t.Helper()
	var presented string
	if mf.origin != "" {
		presented = testmdoc.PresentDCAPI(t, mf.f, oid4vpmdoc.DCAPIHandoverParams{
			Origin: mf.origin, Nonce: nonce, ResponseEncryptionJWKThumbprint: mf.thumbprint,
		})
	} else {
		presented = testmdoc.Present(t, mf.f, oid4vpmdoc.HandoverParams{
			ClientID: mf.v.ClientID(), Nonce: nonce, ResponseURI: mf.cfg.ResponseURI.String(), ResponseEncryptionJWKThumbprint: mf.thumbprint,
		})
	}
	req := verifier.VerifyResponseRequest{
		Query:                 mf.query,
		Response:              verifier.ParsedResponse{VPToken: map[string][]string{"mdl": {presented}}},
		ExpectedNonce:         mf.nonce,
		MdocIssuerKeys:        fixedMdocIssuerKeyResolver{pub: &mf.f.IssuerKey.PublicKey, alg: cose.ES256},
		ResponseEncryptionKey: mf.responseDecryptionKey,
		Origin:                mf.origin,
	}
	mutate(&req)
	return mf.v.VerifyResponse(context.Background(), req)
}

// assertMdocGivenNameAlice asserts a successful VerifyResponse call
// returned exactly one "mdl" VerifiedCredential whose own
// org.iso.18013.5.1 namespace carries given_name "Alice" —
// testmdoc.Issue's own fixed claim — shared by TestVerifyMdocResponse
// and TestVerifyMdocResponseDCAPI, which differ only in which flow
// mf's own fixture exercises.
func assertMdocGivenNameAlice(t *testing.T, result verifier.VerifyResponseResult, err error) {
	t.Helper()
	vc := testverify.RequireOneCredential(t, result, err, "mdl")
	namespace, ok := vc.Claims["org.iso.18013.5.1"].(map[string]interface{})
	if !ok || namespace["given_name"] != "Alice" {
		t.Errorf("Claims[org.iso.18013.5.1] = %v", vc.Claims["org.iso.18013.5.1"])
	}
}

// TestVerifyMdocResponse drives a real end-to-end round trip: build a
// real Authorization Request, issue and present a real "mso_mdoc"
// credential bound to that exact clientID/nonce/responseURI/response-
// encryption-key thumbprint, and verify it via VerifyResponse.
func TestVerifyMdocResponse(t *testing.T) {
	mf := newMdocVerifyFixture(t)
	result, err := mf.verify(t, mf.nonce)
	assertMdocGivenNameAlice(t, result, err)
}

func TestVerifyMdocResponseRejectsWrongNonce(t *testing.T) {
	mf := newMdocVerifyFixture(t)
	if _, err := mf.verify(t, "wrong-nonce"); err == nil {
		t.Fatalf("VerifyResponse = nil error, want error")
	}
}

// TestVerifyMdocResponseDCAPI mirrors TestVerifyMdocResponse for the
// DC API flow: a real "mso_mdoc" credential presented with a
// DC-API-shaped SessionTranscript (Appendix B.2.6.2, origin-bound)
// verifies via the same VerifyResponse, given Origin.
func TestVerifyMdocResponseDCAPI(t *testing.T) {
	mf := newMdocDCAPIVerifyFixture(t)
	result, err := mf.verify(t, mf.nonce)
	assertMdocGivenNameAlice(t, result, err)
}

func TestVerifyMdocResponseDCAPIRejectsWrongNonce(t *testing.T) {
	mf := newMdocDCAPIVerifyFixture(t)
	if _, err := mf.verify(t, "wrong-nonce"); err == nil {
		t.Fatalf("VerifyResponse = nil error, want error")
	}
}

// rejectCaseMdocMissingDependency builds a VerifyResponseRequest for
// testmdoc.Query missing exactly one of MdocIssuerKeys/
// ResponseEncryptionKey — both are checked before the (irrelevant
// here) presented content is even decoded, so a placeholder string is
// enough.
func rejectCaseMdocMissingDependency(t *testing.T, v *verifier.Verifier, nonce string, missingResponseEncryptionKey bool) verifier.VerifyResponseRequest {
	t.Helper()
	req := verifier.VerifyResponseRequest{
		Query: testmdoc.Query(t), ExpectedNonce: nonce,
		Response: verifier.ParsedResponse{VPToken: map[string][]string{"mdl": {"irrelevant"}}},
	}
	if missingResponseEncryptionKey {
		req.MdocIssuerKeys = fixedMdocIssuerKeyResolver{}
	} else {
		req.ResponseEncryptionKey = testP256Key(t)
	}
	return req
}

// TestVerifyMdocResponse_SurfacesStatus checks an mdoc's issuer-signed
// revocation reference (MSO status, ISO/IEC 18013-5 §12.3.6) reaches the
// caller as VerifiedCredential.MdocStatus, since VerifyResponse doesn't
// check revocation itself.
func TestVerifyMdocResponse_SurfacesStatus(t *testing.T) {
	mf := newMdocVerifyFixture(t)
	mf.f = testmdoc.IssueWith(t, func(c *mdoc.Claims) {
		c.Status = &mdoc.StatusListRef{Idx: 7, URI: "https://issuer.example.com/statuslists/1"}
	})
	result, err := mf.verify(t, mf.nonce)
	vc := testverify.RequireOneCredential(t, result, err, "mdl")
	if vc.MdocStatus == nil || vc.MdocStatus.StatusList == nil ||
		vc.MdocStatus.StatusList.Idx != 7 || vc.MdocStatus.StatusList.URI != "https://issuer.example.com/statuslists/1" {
		t.Errorf("MdocStatus = %+v, want status_list idx 7 at the issuer's list", vc.MdocStatus)
	}

	plain := newMdocVerifyFixture(t)
	result, err = plain.verify(t, plain.nonce)
	if vc := testverify.RequireOneCredential(t, result, err, "mdl"); vc.MdocStatus != nil {
		t.Errorf("MdocStatus = %+v for an mdoc without a status, want nil", vc.MdocStatus)
	}
}

// TestVerifyMdocResponse_UsesNow checks the MSO validity window is judged
// at VerifyResponseRequest.Now, like every other time check.
func TestVerifyMdocResponse_UsesNow(t *testing.T) {
	mf := newMdocVerifyFixture(t)
	_, err := mf.verifyWith(t, mf.nonce, func(r *verifier.VerifyResponseRequest) {
		r.Now = func() time.Time { return time.Now().Add(2 * time.Hour) } // past the fixture's validUntil
	})
	if err == nil {
		t.Fatal("VerifyResponse at a Now past the MSO's validUntil = nil error, want error")
	}
}

// failingMdocIssuerKeyResolver fails every issuer key resolution.
type failingMdocIssuerKeyResolver struct{}

func (failingMdocIssuerKeyResolver) ResolveMdocIssuerKey(context.Context, [][]byte, string) (crypto.PublicKey, cose.Alg, error) {
	return nil, 0, errors.New("untrusted issuer")
}

// TestVerifyMdocResponseRejects table-drives the mso_mdoc rejection paths
// VerifyResponse covers beyond a wrong nonce: a malformed Presentation,
// an issuer key that can't be resolved, a response encryption key the
// session transcript can't be built from, a credential that doesn't
// satisfy the query, and an issuer the query's trusted_authorities
// doesn't name.
func TestVerifyMdocResponseRejects(t *testing.T) {
	p384Key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(r *verifier.VerifyResponseRequest){
		"presentation isn't base64url": func(r *verifier.VerifyResponseRequest) {
			r.Response.VPToken["mdl"] = []string{"not base64url!"}
		},
		"presentation isn't a DeviceResponse": func(r *verifier.VerifyResponseRequest) {
			r.Response.VPToken["mdl"] = []string{"oA"} // CBOR {} — no documents
		},
		"issuer key can't be resolved": func(r *verifier.VerifyResponseRequest) {
			r.MdocIssuerKeys = failingMdocIssuerKeyResolver{}
		},
		"response encryption key isn't P-256": func(r *verifier.VerifyResponseRequest) {
			r.ResponseEncryptionKey = p384Key
		},
		"credential doesn't satisfy the query": func(r *verifier.VerifyResponseRequest) {
			r.Query.Credentials[0].Claims = []dcql.ClaimsQuery{{Path: dcql.Path{dcql.PathKey("org.iso.18013.5.1"), dcql.PathKey("no_such_element")}}}
		},
		"issuer isn't a trusted authority": func(r *verifier.VerifyResponseRequest) {
			r.Query.Credentials[0].TrustedAuthorities = []dcql.TrustedAuthoritiesQuery{{Type: dcql.TrustedAuthorityAKI, Values: []string{"bm90LXRoaXMtaXNzdWVy"}}}
			r.TrustedAuthorities = dcql.AKITrustedAuthoritiesChecker{Roots: x509.NewCertPool()}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			mf := newMdocVerifyFixture(t)
			mf.query = testmdoc.Query(t)
			if _, err := mf.verifyWith(t, mf.nonce, mutate); err == nil {
				t.Fatalf("VerifyResponse(%s) = nil error, want error", name)
			}
		})
	}
}

// x5chainLeafIssuerKey resolves an mdoc's issuer key from its x5chain
// leaf without any trust check — for tests whose presentation comes from
// a freshly issued testmdoc fixture, with its own issuer key.
type x5chainLeafIssuerKey struct{}

func (x5chainLeafIssuerKey) ResolveMdocIssuerKey(_ context.Context, chain [][]byte, _ string) (crypto.PublicKey, cose.Alg, error) {
	if len(chain) == 0 {
		return nil, 0, errors.New("no x5chain")
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return nil, 0, err
	}
	return leaf.PublicKey, cose.ES256, nil
}

// presentDocument encodes doc as the base64url DeviceResponse a VP Token
// carries.
func presentDocument(t *testing.T, doc oid4vpmdoc.Document) string {
	t.Helper()
	raw, err := oid4vpmdoc.MarshalDeviceResponse(doc)
	if err != nil {
		t.Fatalf("MarshalDeviceResponse: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

// transcript is the redirect-flow SessionTranscript mf's request binds a
// presentation to.
func (mf mdocVerifyFixture) transcript(t *testing.T) []byte {
	t.Helper()
	st, err := oid4vpmdoc.BuildSessionTranscriptBytes(oid4vpmdoc.HandoverParams{
		ClientID: mf.v.ClientID(), Nonce: mf.nonce, ResponseURI: mf.cfg.ResponseURI.String(), ResponseEncryptionJWKThumbprint: mf.thumbprint,
	})
	if err != nil {
		t.Fatalf("BuildSessionTranscriptBytes: %v", err)
	}
	return st
}

// deviceSigned signs mf's transcript with f's device key, carrying the
// given self-asserted device-signed elements.
func (mf mdocVerifyFixture) deviceSigned(t *testing.T, f testmdoc.Fixture, nameSpaces map[string]map[string]interface{}) mdoc.DeviceSigned {
	t.Helper()
	ds, err := mdoc.SignDeviceSignature(f.DeviceKey, cose.ES256, mf.transcript(t), testmdoc.DocType, nameSpaces)
	if err != nil {
		t.Fatalf("SignDeviceSignature: %v", err)
	}
	return ds
}

// TestVerifyMdocResponseRejectsCraftedPresentations covers the mso_mdoc
// rejection paths that need a hand-built presentation: an IssuerAuth that
// isn't a COSE_Sign1, MAC device authentication (which needs a reader
// key this redirect flow doesn't have), and a device-signed element
// outside the MSO's key authorizations (ISO/IEC 18013-5 §12.3.4).
func TestVerifyMdocResponseRejectsCraftedPresentations(t *testing.T) {
	readerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(t *testing.T, mf mdocVerifyFixture) string{
		"IssuerAuth isn't a COSE_Sign1": func(t *testing.T, mf mdocVerifyFixture) string {
			issuerSigned := mf.f.IssuerSigned
			issuerSigned.IssuerAuth = []byte{0x01} // a CBOR integer
			return presentDocument(t, oid4vpmdoc.Document{DocType: testmdoc.DocType, IssuerSigned: issuerSigned, DeviceSigned: mf.deviceSigned(t, mf.f, nil)})
		},
		"device authentication by MAC": func(t *testing.T, mf mdocVerifyFixture) string {
			ds, err := mdoc.ComputeDeviceMAC(mf.f.DeviceKey, &readerKey.PublicKey, mf.transcript(t), testmdoc.DocType, map[string]map[string]interface{}{})
			if err != nil {
				t.Fatalf("ComputeDeviceMAC: %v", err)
			}
			return presentDocument(t, oid4vpmdoc.Document{DocType: testmdoc.DocType, IssuerSigned: mf.f.IssuerSigned, DeviceSigned: ds})
		},
		"device-signed element outside the key authorizations": func(t *testing.T, mf mdocVerifyFixture) string {
			f := testmdoc.IssueWith(t, func(c *mdoc.Claims) {
				c.KeyAuthorizations = &mdoc.KeyAuthorizations{NameSpaces: []string{"org.iso.18013.5.1"}}
			})
			selfAsserted := map[string]map[string]interface{}{"org.example.self": {"note": "not authorized"}}
			return presentDocument(t, oid4vpmdoc.Document{DocType: testmdoc.DocType, IssuerSigned: f.IssuerSigned, DeviceSigned: mf.deviceSigned(t, f, selfAsserted)})
		},
	}
	for name, present := range cases {
		t.Run(name, func(t *testing.T) {
			mf := newMdocVerifyFixture(t)
			presented := present(t, mf)
			_, err := mf.verifyWith(t, mf.nonce, func(r *verifier.VerifyResponseRequest) {
				r.Response.VPToken["mdl"] = []string{presented}
				r.MdocIssuerKeys = x5chainLeafIssuerKey{}
			})
			if err == nil {
				t.Fatalf("VerifyResponse(%s) = nil error, want error", name)
			}
		})
	}
}

// A Verifier whose clock is behind the issuer's refuses an mdoc
// presented just after it was issued valid from its signing time —
// unless MaxClockSkew covers the difference.
func TestVerifyMdocResponse_MaxClockSkew(t *testing.T) {
	mf := newMdocVerifyFixture(t)
	behind := func(skew time.Duration) func(*verifier.VerifyResponseRequest) {
		return func(req *verifier.VerifyResponseRequest) {
			req.Now = func() time.Time { return time.Now().Add(-30 * time.Second) }
			req.MaxClockSkew = skew
		}
	}
	if _, err := mf.verifyWith(t, mf.nonce, behind(0)); err == nil {
		t.Error("a clock 30 s behind the issuer's, no skew allowed: accepted")
	}
	result, err := mf.verifyWith(t, mf.nonce, behind(time.Minute))
	assertMdocGivenNameAlice(t, result, err)
}
