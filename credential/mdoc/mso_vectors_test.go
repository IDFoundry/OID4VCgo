package mdoc

import (
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/idfoundry/oid4vcgo/internal/cose"
)

// resign is f's credential with its MSO changed by mutate and IssuerAuth
// signed again by the issuer, its x5chain in unprotected (ISO/IEC
// 18013-5 §12.3.4's place) unless protected is set. The result is
// signed correctly: a refusal is for what mutate changed, not the
// signature.
func resign(t *testing.T, f fixture, mutate func(*MobileSecurityObject), protected bool) IssuerSigned {
	t.Helper()
	_, _, payload, err := cose.DecodeUnverified(f.signed.IssuerAuth)
	if err != nil {
		t.Fatal(err)
	}
	var mso MobileSecurityObject
	if err := unwrapTag24(payload, &mso); err != nil {
		t.Fatal(err)
	}
	if mutate != nil {
		mutate(&mso)
	}
	if payload, err = wrapTag24(mso); err != nil {
		t.Fatal(err)
	}
	return signMSOPayload(t, f, payload, protected)
}

func signMSOPayload(t *testing.T, f fixture, payload []byte, protected bool) IssuerSigned {
	t.Helper()
	ph, uh := cose.Headers{}, cose.Headers{X5Chain: [][]byte{f.cert}}
	if protected {
		ph, uh = uh, ph
	}
	issuerAuth, err := cose.Sign(cose.ES256, f.issuerKey, ph, uh, payload, []byte{})
	if err != nil {
		t.Fatal(err)
	}
	out := f.signed
	out.IssuerAuth = issuerAuth
	return out
}

// withoutValidityMember is f's credential re-signed with member left out
// of its MSO's validityInfo, as an issuer that never wrote it would.
func withoutValidityMember(t *testing.T, f fixture, member string) IssuerSigned {
	t.Helper()
	_, _, payload, err := cose.DecodeUnverified(f.signed.IssuerAuth)
	if err != nil {
		t.Fatal(err)
	}
	var mso map[string]cbor.RawMessage
	if err := unwrapTag24(payload, &mso); err != nil {
		t.Fatal(err)
	}
	var validity map[string]cbor.RawMessage
	if err := cbor.Unmarshal(mso["validityInfo"], &validity); err != nil {
		t.Fatal(err)
	}
	if _, ok := validity[member]; !ok {
		t.Fatalf("validityInfo has no %q to leave out", member)
	}
	delete(validity, member)
	if mso["validityInfo"], err = cbor.Marshal(validity); err != nil {
		t.Fatal(err)
	}
	if payload, err = wrapTag24(mso); err != nil {
		t.Fatal(err)
	}
	return signMSOPayload(t, f, payload, false)
}

// firstItem is a namespace and digestID f discloses.
func firstItem(f fixture) (string, uint64) {
	for ns, items := range f.signed.NameSpaces {
		return ns, items[0].DigestID
	}
	return "", 0
}

// The MSO-structure negative vectors: each a correctly signed MSO that
// breaks one rule of ISO/IEC 18013-5 §12.3.4 or §12.3.5 a reader can
// check, refused by Verify. The unchanged MSO is the control.
func TestMSONegativeVectors(t *testing.T) {
	f := newFixture(t)
	verify := func(signed IssuerSigned) error {
		_, err := Verify(signed, f.claims.DocType, &f.issuerKey.PublicKey, cose.ES256, VerifyOptions{
			Now: func() time.Time { return f.claims.Signed.Add(time.Hour) },
		})
		return err
	}
	if err := verify(resign(t, f, nil, false)); err != nil {
		t.Fatalf("the control is refused, so no refusal below means anything: %v", err)
	}
	for _, vec := range []struct {
		id, clause, want string
		signed           func() IssuerSigned
	}{
		{"mso-version-unknown", "§12.3.4 (version)", "MSO version",
			func() IssuerSigned { return resign(t, f, func(m *MobileSecurityObject) { m.Version = "2.0" }, false) }},
		{"mso-digest-algorithm-unsupported", "§12.3.5 (SHA-256, SHA-384 or SHA-512)", "unsupported digest algorithm",
			func() IssuerSigned {
				return resign(t, f, func(m *MobileSecurityObject) { m.DigestAlgorithm = "SHA-1" }, false)
			}},
		{"mso-digest-algorithm-not-the-items", "§12.3.5 (one digest algorithm for all)", "digest mismatch",
			func() IssuerSigned {
				return resign(t, f, func(m *MobileSecurityObject) { m.DigestAlgorithm = SHA384 }, false)
			}},
		{"value-digests-namespace-missing", "§12.3.4 (ValueDigests)", "has no entry in valueDigests",
			func() IssuerSigned {
				ns, _ := firstItem(f)
				return resign(t, f, func(m *MobileSecurityObject) { delete(m.ValueDigests, ns) }, false)
			}},
		{"value-digests-digest-id-missing", "§12.3.4 (DigestIDs)", "has no entry in valueDigests",
			func() IssuerSigned {
				ns, id := firstItem(f)
				return resign(t, f, func(m *MobileSecurityObject) { delete(m.ValueDigests[ns], id) }, false)
			}},
		{"mso-payload-not-tag-24", "§12.3.4 (MobileSecurityObjectBytes, #6.24)", "MobileSecurityObject",
			func() IssuerSigned {
				_, _, payload, err := cose.DecodeUnverified(f.signed.IssuerAuth)
				if err != nil {
					t.Fatal(err)
				}
				var mso MobileSecurityObject
				if err := unwrapTag24(payload, &mso); err != nil {
					t.Fatal(err)
				}
				untagged, err := cbor.Marshal(mso)
				if err != nil {
					t.Fatal(err)
				}
				return signMSOPayload(t, f, untagged, false)
			}},
		{"mso-doctype-not-the-documents", "§12.3.4 (DocType identical to the response's)", "docType",
			func() IssuerSigned {
				return resign(t, f, func(m *MobileSecurityObject) { m.DocType = "org.example.other.1" }, false)
			}},
		{"validity-valid-from-missing", "§9.1.2.4, §12.3.4 (validFrom)", "validityInfo must have",
			func() IssuerSigned { return withoutValidityMember(t, f, "validFrom") }},
		{"validity-signed-missing", "§9.1.2.4, §12.3.4 (signed)", "validityInfo must have",
			func() IssuerSigned { return withoutValidityMember(t, f, "signed") }},
		{"validity-valid-until-missing", "§9.1.2.4, §12.3.4 (validUntil)", "validityInfo must have",
			func() IssuerSigned { return withoutValidityMember(t, f, "validUntil") }},
		{"validity-valid-from-zero", "§9.1.2.4, §12.3.4 (validFrom)", "validityInfo must have",
			func() IssuerSigned {
				return resign(t, f, func(m *MobileSecurityObject) { m.ValidityInfo.ValidFrom = time.Time{} }, false)
			}},
		{"validity-valid-until-not-after-valid-from", "§12.3.4 (validUntil later than validFrom)", "not later than validFrom",
			func() IssuerSigned {
				return resign(t, f, func(m *MobileSecurityObject) { m.ValidityInfo.ValidUntil = m.ValidityInfo.ValidFrom }, false)
			}},
		{"validity-misordered", "§12.3.4 (validUntil later than validFrom)", "not later than validFrom",
			func() IssuerSigned {
				return resign(t, f, func(m *MobileSecurityObject) {
					v := &m.ValidityInfo
					v.ValidFrom, v.ValidUntil = v.ValidUntil, v.ValidFrom
				}, false)
			}},
	} {
		t.Run(vec.id, func(t *testing.T) {
			err := verify(vec.signed())
			if err == nil {
				t.Fatalf("accepted (ISO/IEC 18013-5 %s)", vec.clause)
			}
			if vec.want != "" && !strings.Contains(err.Error(), vec.want) {
				t.Errorf("refused for another reason: %v, want %q (%s)", err, vec.want, vec.clause)
			}
		})
	}
}

// An IssuerAuth carrying its x5chain in the protected header is
// accepted, as a reader should (ISO/IEC 18013-5 §12.3.4), and Verify
// reports that chain.
func TestVerifyAcceptsProtectedX5Chain(t *testing.T) {
	f := newFixture(t)
	verified, err := Verify(resign(t, f, nil, true), f.claims.DocType, &f.issuerKey.PublicKey, cose.ES256, VerifyOptions{
		Now: func() time.Time { return f.claims.Signed.Add(time.Hour) },
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(verified.X5Chain) != 1 || string(verified.X5Chain[0]) != string(f.cert) {
		t.Errorf("X5Chain = %d certificates, want the protected one", len(verified.X5Chain))
	}
}
