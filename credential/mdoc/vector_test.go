package mdoc

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// The vectors below are ISO/IEC 18013-5's own worked example (Annex D.4.1.2,
// "mdoc response" — CD ballot resolution draft, 2025-09-14): real
// IssuerSignedItem field values from the org.iso.18013.5.1 namespace,
// each checked against the digest ISO's own example computed for it
// under SHA-256 (§12.3.5). A mismatch here means this package's CBOR
// encoding of IssuerSignedItem has drifted from a real issuer's — see
// the package doc comment and IssuerSignedItem's own doc comment for
// why field order and encoding mode matter here.
func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode hex: %v", err)
	}
	return b
}

func checkVectorDigest(t *testing.T, item IssuerSignedItem, wantHex string) {
	t.Helper()
	itemBytes, err := issuerSignedItemBytes(item)
	if err != nil {
		t.Fatalf("issuerSignedItemBytes: %v", err)
	}
	got, err := digest(SHA256, itemBytes)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	want := mustHex(t, wantHex)
	if !bytes.Equal(got, want) {
		t.Errorf("digest = %x, want %x", got, want)
	}
}

func TestVectorDigestFamilyName(t *testing.T) {
	checkVectorDigest(t, IssuerSignedItem{
		DigestID:          0,
		Random:            mustHex(t, "8798645B20EA200E19FFABAC92624BEE6AEC63ACEEDECFB1B80077D22BFC20E9"),
		ElementIdentifier: "family_name",
		ElementValue:      "Doe",
	}, "75167333B47B6C2BFB86ECCC1F438CF57AF055371AC55E1E359E20F254ADCEBF")
}

func TestVectorDigestIssueDate(t *testing.T) {
	checkVectorDigest(t, IssuerSignedItem{
		DigestID:          3,
		Random:            mustHex(t, "B23F627E8999C706DF0C0A4ED98AD74AF988AF619B4BB078B89058553F44615D"),
		ElementIdentifier: "issue_date",
		ElementValue:      cbor.Tag{Number: 1004, Content: "2019-10-20"},
	}, "2E35AD3C4E514BB67B1A9DB51CE74E4CB9B7146E41AC52DAC9CE86B8613DB555")
}

func TestVectorDigestExpiryDate(t *testing.T) {
	checkVectorDigest(t, IssuerSignedItem{
		DigestID:          4,
		Random:            mustHex(t, "C7FFA307E5DE921E67BA5878094787E8807AC8E7B5B3932D2CE80F00F3E9ABAF"),
		ElementIdentifier: "expiry_date",
		ElementValue:      cbor.Tag{Number: 1004, Content: "2024-10-20"},
	}, "EA5C3304BB7C4A8DCB51C4C13B65264F845541341342093CCA786E058FAC2D59")
}

func TestVectorDigestDocumentNumber(t *testing.T) {
	checkVectorDigest(t, IssuerSignedItem{
		DigestID:          7,
		Random:            mustHex(t, "26052A42E5880557A806C1459AF3FB7EB505D3781566329D0B604B845B5F9E68"),
		ElementIdentifier: "document_number",
		ElementValue:      "123456789",
	}, "F0549A145F1CF75CBEEFFA881D4857DD438D627CF32174B1731C4C38E12CA936")
}

// drivingPrivilege mirrors D.2.1's own CDDL field order exactly
// (vehicle_category_code, issue_date, expiry_date) — see
// IssuerSignedItem's doc comment on why order matters for a
// byte-identical digest match.
type drivingPrivilege struct {
	VehicleCategoryCode string   `cbor:"vehicle_category_code"`
	IssueDate           cbor.Tag `cbor:"issue_date"`
	ExpiryDate          cbor.Tag `cbor:"expiry_date"`
}

func TestVectorDigestDrivingPrivileges(t *testing.T) {
	checkVectorDigest(t, IssuerSignedItem{
		DigestID:          9,
		Random:            mustHex(t, "4599F81BEAA2B20BD0FFCC9AA03A6F985BEFAB3F6BEAFFA41E6354CDB2AB2CE4"),
		ElementIdentifier: "driving_privileges",
		ElementValue: []drivingPrivilege{
			{
				VehicleCategoryCode: "A",
				IssueDate:           cbor.Tag{Number: 1004, Content: "2018-08-09"},
				ExpiryDate:          cbor.Tag{Number: 1004, Content: "2024-10-20"},
			},
			{
				VehicleCategoryCode: "B",
				IssueDate:           cbor.Tag{Number: 1004, Content: "2017-02-23"},
				ExpiryDate:          cbor.Tag{Number: 1004, Content: "2024-10-20"},
			},
		},
	}, "0B3587D1DD0C2A07A35BFB120D99A0ABFB5DF56865BB7FA15CC8B56A66DF6E0C")
}
