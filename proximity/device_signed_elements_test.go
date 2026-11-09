package proximity

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/internal/cose"
	"github.com/idfoundry/oid4vcgo/oid4vpmdoc"
)

// A reader refuses device-signed elements the mdoc's KeyAuthorizations
// don't cover (§12.8.2 step 1), and ones it didn't request, though the
// device signature over them verifies: the holder's device key would
// otherwise vouch for claims the issuer never let it make.
func TestVerify_RefusesDeviceSignedElements(t *testing.T) {
	ca, caKey := testIACA(t)
	ds, dsKey := testDocumentSigner(t, ca, caKey, MDLDocumentSignerEKU)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	issue := func(t *testing.T, auth *mdoc.KeyAuthorizations) (mdoc.IssuerSigned, *ecdsa.PrivateKey) {
		t.Helper()
		deviceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		signed := time.Now().Add(-time.Minute)
		issuerSigned, err := mdoc.Issue(dsKey, cose.ES256, mdoc.Claims{
			DocType:    mDL,
			NameSpaces: map[string]map[string]interface{}{mDLNS: {"age_over_18": true, "given_name": "Alice"}},
			DeviceKey:  &deviceKey.PublicKey, KeyAuthorizations: auth,
			Signed: signed, ValidFrom: signed, ValidUntil: signed.Add(time.Hour),
		}, mdoc.IssueOptions{X5Chain: [][]byte{ds.Raw}})
		if err != nil {
			t.Fatal(err)
		}
		return issuerSigned, deviceKey
	}
	authorized := &mdoc.KeyAuthorizations{NameSpaces: []string{mDLNS}}

	for name, tc := range map[string]struct {
		auth      *mdoc.KeyAuthorizations
		requested []string
		device    map[string]interface{}
		want      string // "" accepted
	}{
		"none":                  {nil, []string{"age_over_18"}, nil, ""},
		"authorized, requested": {authorized, []string{"age_over_18", "given_name"}, map[string]interface{}{"given_name": "Alice"}, ""},
		"not authorized":        {nil, []string{"age_over_18", "given_name"}, map[string]interface{}{"given_name": "Mallory"}, "authoriz"},
		"not requested":         {authorized, []string{"age_over_18"}, map[string]interface{}{"given_name": "Mallory"}, "unrequested device-signed"},
	} {
		t.Run(name, func(t *testing.T) {
			issuerSigned, deviceKey := issue(t, tc.auth)
			f := establish(t, mDL, map[string][]string{mDLNS: tc.requested})
			deviceNS := map[string]map[string]interface{}{}
			if tc.device != nil {
				deviceNS[mDLNS] = tc.device
			}
			deviceSigned, err := mdoc.SignDeviceSignature(deviceKey, cose.ES256, f.holder.SessionTranscriptBytes(), mDL, deviceNS)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := MarshalDeviceResponse(oid4vpmdoc.Document{
				DocType: mDL, IssuerSigned: issuerSigned.SelectNameSpaces([][2]string{{mDLNS, "age_over_18"}}), DeviceSigned: deviceSigned,
			})
			if err != nil {
				t.Fatal(err)
			}
			msg, err := f.holder.Encrypt(resp, false)
			if err != nil {
				t.Fatal(err)
			}
			_, err = f.reader.Verify(context.Background(), msg, roots, time.Now())
			switch {
			case tc.want == "" && err != nil:
				t.Errorf("Verify = %v, want accepted", err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Errorf("Verify = %v, want %q", err, tc.want)
			}
		})
	}
}
