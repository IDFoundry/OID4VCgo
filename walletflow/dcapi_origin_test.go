package walletflow_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"testing"

	fapi "github.com/idfoundry/fapigo"

	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/jwe"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/verifier"
	"github.com/idfoundry/oid4vcgo/wallet"
	"github.com/idfoundry/oid4vcgo/walletflow"
)

// A page that replays a Verifier's signed request — its DC API request
// for its own pages, or its redirect-flow Request Object, which its
// request_uri serves to anyone — gets the same plain error whether or
// not the wallet trusts that Verifier: no RequestRefusedError, so no
// DCAPIResponse to hand back, and nothing that says which Verifiers the
// wallet trusts (audit 2026-11-18, WVP-1).
func TestDCAPIPresentation_AnotherOriginLearnsNothing(t *testing.T) {
	const page = "https://attacker.example"
	ctx := context.Background()
	trustedCA, trustedCAKey := testcert.CA(t, "trusted verifier CA")
	otherCA, otherCAKey := testcert.CA(t, "other verifier CA")
	roots := x509.NewCertPool()
	roots.AddCert(trustedCA)
	w, err := walletflow.New(walletflow.Config{Development: true, VerifierTrust: wallet.X5CVerifierRoots{Roots: roots}},
		walletflow.Dependencies{Keys: walletflow.NewMemoryKeyStore(), Credentials: walletflow.NewMemoryCredentialStore()})
	if err != nil {
		t.Fatal(err)
	}
	meta, err := dcql.NewSDJWTVCMeta(dcql.SDJWTVCMeta{VCTValues: []string{"urn:eudi:pid:1"}})
	if err != nil {
		t.Fatal(err)
	}
	query := dcql.Query{Credentials: []dcql.CredentialQuery{{ID: "pid", Format: "dc+sd-jwt", Meta: meta}}}
	newVerifier := func(ca *x509.Certificate, caKey *ecdsa.PrivateKey) *verifier.Verifier {
		t.Helper()
		leaf, key := testcert.Leaf(t, "a verifier", ca, caKey)
		responseURI, err := fapi.ParseEndpointURL("https://verifier.example/response")
		if err != nil {
			t.Fatal(err)
		}
		v, err := verifier.New(verifier.Config{
			Assurance: verifier.AssuranceDevelopment, ClientCertificate: leaf, ResponseURI: responseURI,
			SigningAlg: jose.ES256, EncValuesSupported: []jwe.Enc{jwe.A128GCM},
			VPFormatsSupported: map[string]any{"dc+sd-jwt": map[string]any{"sd-jwt_alg_values": []string{"ES256"}}},
		}, verifier.Dependencies{Signer: key, Random: rand.Reader})
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	requests := func(v *verifier.Verifier) map[string][]byte {
		t.Helper()
		redirect, err := v.BuildAuthorizationRequest(verifier.BuildAuthorizationRequestRequest{Query: query})
		if err != nil {
			t.Fatal(err)
		}
		dcapi, err := v.BuildDCAPIAuthorizationRequest(verifier.BuildDCAPIAuthorizationRequestRequest{Query: query, ExpectedOrigins: []string{dcapiOrigin}})
		if err != nil {
			t.Fatal(err)
		}
		out := map[string][]byte{}
		for name, requestObject := range map[string]string{"redirect flow": redirect.RequestObject, "DC API": dcapi.RequestObject} {
			if out[name], err = json.Marshal(map[string]string{"request": requestObject}); err != nil {
				t.Fatal(err)
			}
		}
		return out
	}
	trusted := requests(newVerifier(trustedCA, trustedCAKey))
	untrusted := requests(newVerifier(otherCA, otherCAKey))

	for name := range trusted {
		var texts []string
		for _, data := range [][]byte{trusted[name], untrusted[name]} {
			_, err := w.StartDCAPIPresentation(ctx, wallet.DCAPIProtocolSigned, data, page)
			switch {
			case err == nil:
				t.Fatalf("%s: opened from a page it doesn't name", name)
			case errors.As(err, new(*walletflow.RequestRefusedError)):
				t.Fatalf("%s: refused with a DCAPIResponse for the page: %v", name, err)
			case errors.Is(err, walletflow.ErrUntrustedVerifier):
				t.Fatalf("%s: refused as untrusted before the origin: %v", name, err)
			}
			texts = append(texts, err.Error())
		}
		if texts[0] != texts[1] {
			t.Errorf("%s: a trusted Verifier's request refused as %q, an untrusted one's as %q", name, texts[0], texts[1])
		}
	}

	// From the page it names, the untrusted Verifier's request is
	// refused as untrusted: that page is its own.
	if _, err := w.StartDCAPIPresentation(ctx, wallet.DCAPIProtocolSigned, untrusted["DC API"], dcapiOrigin); !errors.Is(err, walletflow.ErrUntrustedVerifier) {
		t.Errorf("an untrusted Verifier's request from its own page: %v, want ErrUntrustedVerifier", err)
	}
}
