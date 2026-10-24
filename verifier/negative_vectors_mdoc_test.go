package verifier_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/internal/cose"
	"github.com/idfoundry/oid4vcgo/internal/testmdoc"
	"github.com/idfoundry/oid4vcgo/oid4vpmdoc"
	"github.com/idfoundry/oid4vcgo/verifier"
)

// negativeVector is a valid presentation with exactly one thing changed,
// which a verifier must refuse. layer says whose job the refusal is,
// clause the requirement it rests on (ISO/IEC 18013-5 by section number
// only), and want the verifier.Error reason it must be refused with: a
// refusal for another reason doesn't count.
type negativeVector struct {
	id, layer, clause string
	want              verifier.Reason
	// present builds the presentation; mutate, if set, changes the
	// request it's verified with.
	present func(t *testing.T, mf mdocVerifyFixture) string
	mutate  func(r *verifier.VerifyResponseRequest)
}

// mdocNegativeVectors are the mso_mdoc presentations a verifier must
// refuse, each a valid one with one change.
var mdocNegativeVectors = []negativeVector{
	{
		id: "mdoc-element-value-tampered", layer: "mso", clause: "ISO/IEC 18013-5 §9.1.2.4 (digests)",
		want: verifier.ReasonInvalidCredential,
		present: func(t *testing.T, mf mdocVerifyFixture) string {
			// Another issuance's elements under this MSO: their digests
			// aren't the MSO's.
			other := testmdoc.IssueWith(t, func(c *mdoc.Claims) {
				c.NameSpaces = map[string]map[string]interface{}{"org.iso.18013.5.1": {"given_name": "Mallory", "family_name": "Doe"}}
			}).IssuerSigned
			other.IssuerAuth = mf.f.IssuerSigned.IssuerAuth
			return presentDocument(t, oid4vpmdoc.Document{DocType: testmdoc.DocType, IssuerSigned: other, DeviceSigned: mf.deviceSigned(t, mf.f, nil)})
		},
	},
	{
		id: "mdoc-issuer-signature-corrupt", layer: "mso", clause: "ISO/IEC 18013-5 §9.1.2.4 (IssuerAuth signature)",
		want: verifier.ReasonInvalidCredential,
		present: func(t *testing.T, mf mdocVerifyFixture) string {
			issuerSigned := mf.f.IssuerSigned
			auth := append([]byte(nil), issuerSigned.IssuerAuth...)
			auth[len(auth)-1] ^= 0xff // the signature's last byte
			issuerSigned.IssuerAuth = auth
			return presentDocument(t, oid4vpmdoc.Document{DocType: testmdoc.DocType, IssuerSigned: issuerSigned, DeviceSigned: mf.deviceSigned(t, mf.f, nil)})
		},
	},
	{
		id: "mdoc-doctype-not-the-mso", layer: "mso", clause: "ISO/IEC 18013-5 §9.1.2.4 (docType)",
		want: verifier.ReasonInvalidCredential,
		present: func(t *testing.T, mf mdocVerifyFixture) string {
			f := testmdoc.IssueWith(t, func(c *mdoc.Claims) { c.DocType = "org.example.other.1" })
			return presentDocument(t, oid4vpmdoc.Document{DocType: testmdoc.DocType, IssuerSigned: f.IssuerSigned, DeviceSigned: mf.deviceSigned(t, f, nil)})
		},
	},
	{
		id: "mdoc-expired", layer: "mso", clause: "ISO/IEC 18013-5 §9.1.2.4 (validUntil)",
		want: verifier.ReasonInvalidCredential,
		present: func(t *testing.T, mf mdocVerifyFixture) string {
			f := testmdoc.IssueWith(t, func(c *mdoc.Claims) {
				c.Signed, c.ValidFrom, c.ValidUntil = time.Now().Add(-2*time.Hour), time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour)
			})
			return presentDocument(t, oid4vpmdoc.Document{DocType: testmdoc.DocType, IssuerSigned: f.IssuerSigned, DeviceSigned: mf.deviceSigned(t, f, nil)})
		},
	},
	{
		id: "mdoc-not-yet-valid", layer: "mso", clause: "ISO/IEC 18013-5 §9.1.2.4 (validFrom)",
		want: verifier.ReasonInvalidCredential,
		present: func(t *testing.T, mf mdocVerifyFixture) string {
			f := testmdoc.IssueWith(t, func(c *mdoc.Claims) {
				c.ValidFrom = time.Now().Add(30 * time.Minute)
			})
			return presentDocument(t, oid4vpmdoc.Document{DocType: testmdoc.DocType, IssuerSigned: f.IssuerSigned, DeviceSigned: mf.deviceSigned(t, f, nil)})
		},
	},
	{
		id: "mdoc-device-signed-by-another-key", layer: "device-auth", clause: "ISO/IEC 18013-5 §9.1.3",
		want: verifier.ReasonHolderBinding,
		present: func(t *testing.T, mf mdocVerifyFixture) string {
			other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			f := mf.f
			f.DeviceKey = other
			return presentDocument(t, oid4vpmdoc.Document{DocType: testmdoc.DocType, IssuerSigned: mf.f.IssuerSigned, DeviceSigned: mf.deviceSigned(t, f, nil)})
		},
	},
	{
		id: "mdoc-device-signed-another-transcript", layer: "openid4vp", clause: "OpenID4VP 1.0 Appendix B.2.6 (SessionTranscript)",
		want: verifier.ReasonHolderBinding,
		present: func(t *testing.T, mf mdocVerifyFixture) string {
			st, err := oid4vpmdoc.BuildSessionTranscriptBytes(oid4vpmdoc.HandoverParams{
				ClientID: mf.v.ClientID(), Nonce: "another-nonce", ResponseURI: mf.cfg.ResponseURI.String(), ResponseEncryptionJWKThumbprint: mf.thumbprint,
			})
			if err != nil {
				t.Fatal(err)
			}
			ds, err := mdoc.SignDeviceSignature(mf.f.DeviceKey, cose.ES256, st, testmdoc.DocType, nil)
			if err != nil {
				t.Fatal(err)
			}
			return presentDocument(t, oid4vpmdoc.Document{DocType: testmdoc.DocType, IssuerSigned: mf.f.IssuerSigned, DeviceSigned: ds})
		},
	},
	{
		// deviceSigned is a required member of a DeviceResponse document,
		// so the response is malformed before device authentication runs.
		id: "mdoc-device-authentication-missing", layer: "device-auth", clause: "ISO/IEC 18013-5 §8.3.2.1.2.2 (Document: deviceSigned)",
		want: verifier.ReasonMalformed,
		present: func(t *testing.T, mf mdocVerifyFixture) string {
			// Our encoder won't write a document without deviceSigned,
			// so it's taken out of a valid one at the CBOR level.
			valid := presentDocument(t, oid4vpmdoc.Document{DocType: testmdoc.DocType, IssuerSigned: mf.f.IssuerSigned, DeviceSigned: mf.deviceSigned(t, mf.f, nil)})
			raw, err := base64.RawURLEncoding.DecodeString(valid)
			if err != nil {
				t.Fatal(err)
			}
			var response map[string]any
			if err := cbor.Unmarshal(raw, &response); err != nil {
				t.Fatal(err)
			}
			docs, _ := response["documents"].([]any)
			doc, _ := docs[0].(map[any]any)
			delete(doc, "deviceSigned")
			out, err := cbor.Marshal(response)
			if err != nil {
				t.Fatal(err)
			}
			return base64.RawURLEncoding.EncodeToString(out)
		},
	},
	{
		id: "mdoc-issuer-untrusted", layer: "x5chain", clause: "ISO/IEC 18013-5 §9.1.2.4 (document signer certificate)",
		want: verifier.ReasonUntrustedIssuer,
		present: func(t *testing.T, mf mdocVerifyFixture) string {
			return presentDocument(t, oid4vpmdoc.Document{DocType: testmdoc.DocType, IssuerSigned: mf.f.IssuerSigned, DeviceSigned: mf.deviceSigned(t, mf.f, nil)})
		},
		mutate: func(r *verifier.VerifyResponseRequest) {
			r.MdocIssuerKeys = verifier.X5ChainIssuerKeyResolver{Roots: x509.NewCertPool(), Revocation: certrevocation.NoCheck{}}
		},
	},
}

// Every mdoc negative vector is refused, for its reason; and the
// unchanged presentation, the control, is accepted.
func TestMdocNegativeVectors(t *testing.T) {
	control := newMdocVerifyFixture(t)
	if _, err := control.verifyWith(t, control.nonce, func(r *verifier.VerifyResponseRequest) {
		r.Response.VPToken["mdl"] = []string{presentDocument(t, oid4vpmdoc.Document{DocType: testmdoc.DocType, IssuerSigned: control.f.IssuerSigned, DeviceSigned: control.deviceSigned(t, control.f, nil)})}
		r.MdocIssuerKeys = x5chainLeafIssuerKey{}
	}); err != nil {
		t.Fatalf("the control is refused, so no refusal below means anything: %v", err)
	}
	for _, vec := range mdocNegativeVectors {
		t.Run(vec.id, func(t *testing.T) {
			mf := newMdocVerifyFixture(t)
			presented := vec.present(t, mf)
			_, err := mf.verifyWith(t, mf.nonce, func(r *verifier.VerifyResponseRequest) {
				r.Response.VPToken["mdl"] = []string{presented}
				r.MdocIssuerKeys = x5chainLeafIssuerKey{}
				if vec.mutate != nil {
					vec.mutate(r)
				}
			})
			var verr *verifier.Error
			switch {
			case err == nil:
				t.Fatalf("accepted (%s, %s)", vec.layer, vec.clause)
			case !errors.As(err, &verr) || verr.Reason() != vec.want:
				t.Errorf("refused for another reason: %v, want reason %q (%s)", err, vec.want, vec.clause)
			}
		})
	}
}

// An IssuerAuth carrying its x5chain in the protected header, as a
// reader should accept (ISO/IEC 18013-5 §12.3.4), verifies: the issuer
// key resolver is given that chain.
func TestVerifyMdocResponse_ProtectedX5Chain(t *testing.T) {
	mf := newMdocVerifyFixture(t)
	protected, unprotected, payload, err := cose.DecodeUnverified(mf.f.IssuerSigned.IssuerAuth)
	if err != nil {
		t.Fatal(err)
	}
	if len(unprotected.X5Chain) == 0 || len(protected.X5Chain) != 0 {
		t.Fatal("the fixture's x5chain isn't where this test expects it")
	}
	protected.X5Chain, unprotected.X5Chain = unprotected.X5Chain, nil
	resigned, err := cose.Sign(cose.ES256, mf.f.IssuerKey, protected, unprotected, payload, []byte{})
	if err != nil {
		t.Fatal(err)
	}
	mf.f.IssuerSigned.IssuerAuth = resigned
	result, err := mf.verifyWith(t, mf.nonce, func(r *verifier.VerifyResponseRequest) { r.MdocIssuerKeys = x5chainLeafIssuerKey{} })
	assertMdocGivenNameAlice(t, result, err)
}
