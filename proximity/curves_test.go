package proximity

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/internal/cose"
)

// newDeviceSessionOn is NewDeviceSession, peripheral server mode only,
// with an EDeviceKey on curve: a holder this package's own never is,
// as a reader meets in another implementation.
func newDeviceSessionOn(t *testing.T, curve elliptic.Curve) *DeviceSession {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	uuid, err := randomUUID(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	de, err := encodeDeviceEngagement(&key.PublicKey, uuid, nil)
	if err != nil {
		t.Fatal(err)
	}
	s := newDeviceSession(key, uuid, de, nullHandover)
	s.peripheralUUID = uuid
	return s
}

// issueFixtureOn is issueFixture with the IACA, the document signer
// and the device key each on its own curve.
func issueFixtureOn(t *testing.T, iacaCurve, signerCurve, deviceCurve elliptic.Curve) fixture {
	t.Helper()
	ca, caKey := testCertOn(t, iacaCurve, pkix.Name{CommonName: "Test IACA", Country: []string{"SG"}}, nil, nil, true, nil)
	ds, dsKey := testCertOn(t, signerCurve, pkix.Name{CommonName: "Test Document Signer", Country: []string{"SG"}}, ca, caKey, false, []asn1.ObjectIdentifier{MDLDocumentSignerEKU})
	deviceKey, err := ecdsa.GenerateKey(deviceCurve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	alg, err := cose.AlgForKey(&dsKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	signed := time.Now().Add(-time.Minute)
	issuerSigned, err := mdoc.Issue(dsKey, alg, mdoc.Claims{
		DocType:    mDL,
		NameSpaces: map[string]map[string]interface{}{mDLNS: {"age_over_18": true, "given_name": "Alice"}},
		DeviceKey:  &deviceKey.PublicKey,
		Signed:     signed, ValidFrom: signed, ValidUntil: signed.Add(time.Hour),
	}, mdoc.IssueOptions{X5Chain: [][]byte{ds.Raw}})
	if err != nil {
		t.Fatalf("mdoc.Issue: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	return fixture{docType: mDL, issuerSigned: issuerSigned, deviceKey: deviceKey, roots: roots, ca: ca, caKey: caKey, signer: ds}
}

// establishOn engages and establishes a session with holder.
func establishOn(t *testing.T, holder *DeviceSession, opts ...ReaderOption) flow {
	t.Helper()
	reader, err := NewReaderSession(holder.QRCode(), devReader(opts...)...)
	if err != nil {
		t.Fatalf("NewReaderSession: %v", err)
	}
	est, err := reader.Establishment(mDL, ageOver18)
	if err != nil {
		t.Fatalf("Establishment: %v", err)
	}
	reqBytes, err := holder.HandleSessionEstablishment(est)
	if err != nil {
		t.Fatalf("HandleSessionEstablishment: %v", err)
	}
	reqs, err := ParseDeviceRequest(reqBytes)
	if err != nil || len(reqs) != 1 {
		t.Fatalf("ParseDeviceRequest: %d, %v", len(reqs), err)
	}
	return flow{holder: holder, reader: reader, req: reqs[0]}
}

// A holder whose EDeviceKey is on P-384 or P-521 gets an EReaderKey on
// the same curve (§9.1.5.2), the session keys agree, and its
// DeviceResponse — from an mdoc whose IACA, document signer and device
// key are on that curve — verifies, by device signature and by device
// MAC.
func TestSessionWithNISTCurveEDeviceKey(t *testing.T) {
	for _, curve := range []elliptic.Curve{elliptic.P384(), elliptic.P521()} {
		t.Run(curve.Params().Name, func(t *testing.T) {
			fx := issueFixtureOn(t, curve, curve, curve)
			for _, mac := range []bool{false, true} {
				f := establishOn(t, newDeviceSessionOn(t, curve))
				if f.reader.eReaderKey.Curve != curve || f.holder.EReaderKey().Curve != curve {
					t.Fatalf("EReaderKey on %s", f.reader.eReaderKey.Curve.Params().Name)
				}
				var resp []byte
				var err error
				if mac {
					resp, err = BuildDeviceResponseMAC(f.req, fx.issuerSigned, agreeOnlyKey{fx.deviceKey}, f.holder.EReaderKey(), f.holder.SessionTranscriptBytes(), f.req.Elements)
				} else {
					resp, err = buildDeviceResponse(fx.issuerSigned, fx.docType, fx.deviceKey, f.holder.SessionTranscriptBytes(), f.req.Elements)
				}
				if err != nil {
					t.Fatalf("build DeviceResponse (MAC %v): %v", mac, err)
				}
				msg, err := f.holder.Encrypt(resp, false)
				if err != nil {
					t.Fatal(err)
				}
				v, err := f.reader.Verify(context.Background(), msg, fx.roots, time.Now())
				if err != nil {
					t.Fatalf("Verify (MAC %v): %v", mac, err)
				}
				if v.Claims[mDLNS]["age_over_18"] != true || (v.DeviceAuth == mdoc.DeviceAuthMAC) != mac {
					t.Errorf("Verified = %+v", v)
				}
			}
		})
	}
}

// Over this package's own P-256 session, an mdoc whose document signer
// is on P-384 and device key on P-521, under a P-521 IACA, verifies:
// the curves of the issuer's material are independent of the
// session's.
func TestP256SessionWithNISTCurveMdoc(t *testing.T) {
	fx := issueFixtureOn(t, elliptic.P521(), elliptic.P384(), elliptic.P521())
	f := establish(t, mDL, ageOver18)
	if _, err := f.reader.Verify(context.Background(), f.respond(t, fx, f.req.Elements), fx.roots, time.Now()); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	// MAC device authentication needs the device key on the session's
	// curve (§9.1.3.5): a P-521 device key and P-256 EReaderKey don't
	// agree.
	if _, err := BuildDeviceResponseMAC(f.req, fx.issuerSigned, agreeOnlyKey{fx.deviceKey}, f.holder.EReaderKey(), f.holder.SessionTranscriptBytes(), f.req.Elements); err == nil {
		t.Error("BuildDeviceResponseMAC agreed a P-521 device key with a P-256 EReaderKey")
	}
}

// A reader authenticating with a P-521 or P-384 key is trusted by the
// holder, which verifies readerAuth with ES512 or ES384.
func TestReaderAuthNISTCurves(t *testing.T) {
	for _, curve := range []elliptic.Curve{elliptic.P384(), elliptic.P521()} {
		key, chain, roots := testReaderOn(t, curve, ReaderAuthenticationEKU)
		f := establishReader(t, mDL, ageOver18, WithReaderAuth(key, chain))
		got := f.holder.VerifyReaderAuth(f.req, ReaderTrust{Roots: roots, LeafPolicy: RequireReaderAuthenticationEKU})
		if got.Status != ReaderTrusted {
			t.Errorf("%s: Status = %v (%v)", curve.Params().Name, got.Status, got.Err)
		}
	}
}

// The ephemeral keys must be on one curve: neither side agrees keys
// across two.
func TestSessionCipherRefusesMixedCurves(t *testing.T) {
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if _, err := newSessionCipher(p256, &p384.PublicKey, []byte{0x80}, true); err == nil {
		t.Error("a P-256 key agreed with a P-384 one")
	}
	holder, err := NewDeviceSession(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newReaderSession(p384, holder.DeviceEngagementBytes(), nullHandover); err == nil {
		t.Error("a P-384 EReaderKey was accepted for a P-256 EDeviceKey")
	}
}

// An EDeviceKey on P-384 or P-521 decodes from its compressed form (y
// the sign bit, §9.1.5.2) as from its uncompressed one; an x of
// another curve's length, an unsupported curve or a point off the
// curve is refused.
func TestDecodeEDeviceKeyCompressedNISTCurves(t *testing.T) {
	compressed := func(t *testing.T, crv int64, x []byte, odd bool) []byte {
		t.Helper()
		y, err := cbor.Marshal(odd)
		if err != nil {
			t.Fatal(err)
		}
		b, err := encMode.Marshal(compressedCoseKey{Kty: 2, Crv: crv, X: x, Y: y})
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	for crv, curve := range map[int64]elliptic.Curve{1: elliptic.P256(), 2: elliptic.P384(), 3: elliptic.P521()} {
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := key.PublicKey.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		size := (len(raw) - 1) / 2
		x, odd := raw[1:1+size], raw[len(raw)-1]&1 == 1
		got, err := decodeEDeviceKey(compressed(t, crv, x, odd))
		if err != nil || !got.Equal(&key.PublicKey) {
			t.Errorf("%s: %v", curve.Params().Name, err)
		}
		uncompressed, err := encodeCoseKey(&key.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := decodeEDeviceKey(uncompressed); err != nil || !got.Equal(&key.PublicKey) {
			t.Errorf("%s uncompressed: %v", curve.Params().Name, err)
		}
		other := crv%3 + 1
		if _, err := decodeEDeviceKey(compressed(t, other, x, false)); err == nil {
			t.Errorf("%s: an x marked crv %d decoded", curve.Params().Name, other)
		}
	}
	if _, err := decodeEDeviceKey(compressed(t, 8, make([]byte, 32), false)); err == nil {
		t.Error("a brainpoolP256r1 key decoded")
	}
	offCurve := make([]byte, 48)
	offCurve[47] = 5
	if _, err := decodeEDeviceKey(compressed(t, 2, offCurve, false)); err == nil {
		t.Error("a P-384 x with no point on the curve decoded")
	}
}
