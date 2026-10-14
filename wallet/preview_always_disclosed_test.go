package wallet_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/jwk"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// The preview names the claims the issuer didn't make selectively
// disclosable too: the Verifier receives them whatever the selection.
// Registered members (iss, vct, cnf, iat, exp, ...) aren't among them.
func TestPreviewPresentation_AlwaysDisclosed(t *testing.T) {
	ca, caKey := testcert.CA(t, "preview test CA")
	leaf, leafKey := testcert.Leaf(t, "preview test issuer", ca, caKey)
	holder, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	holderJWK, err := jwk.Marshal(&holder.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	exp := time.Now().Add(time.Hour).Unix()
	credential, _, err := sdjwtvc.Issue(leafKey, jose.ES256, sdjwtvc.Claims{
		VCT: "urn:eudi:pid:1", Exp: &exp, CNF: map[string]any{"jwk": holderJWK},
		Additional: map[string]any{
			"given_name":  sdjwtvc.SD("Alice"),
			"nationality": "SG",
			"address":     map[string]any{"country": "SG", "street_address": sdjwtvc.SD("1 Main St")},
		},
	}, sdjwtvc.IssueOptions{IssuerCertificate: leaf})
	if err != nil {
		t.Fatalf("sdjwtvc.Issue: %v", err)
	}
	held := []wallet.HeldCredential{{Format: sdjwtvc.CredentialFormat, Credential: credential, HolderKey: holder, HolderKeyAlg: jose.ES256}}
	meta, err := dcql.NewSDJWTVCMeta(dcql.SDJWTVCMeta{VCTValues: []string{"urn:eudi:pid:1"}})
	if err != nil {
		t.Fatal(err)
	}
	query := dcql.Query{Credentials: []dcql.CredentialQuery{{
		ID: "pid", Format: sdjwtvc.CredentialFormat, Meta: meta,
		Claims: []dcql.ClaimsQuery{{Path: dcql.Path{dcql.PathKey("given_name")}}},
	}}}
	// Both previews — of the default choice, and of a selection the
	// holder made — name them.
	ctx := context.Background()
	for name, preview := range map[string]func() ([]wallet.PreviewedCredential, error){
		"PreviewPresentation": func() ([]wallet.PreviewedCredential, error) {
			return wallet.PreviewPresentation(ctx, query, held, nil)
		},
		"PreviewSelection": func() ([]wallet.PreviewedCredential, error) {
			return wallet.PreviewSelection(ctx, query, map[string][]wallet.HeldCredential{"pid": held}, nil)
		},
	} {
		got, err := preview()
		if err != nil || len(got) != 1 {
			t.Fatalf("%s = %+v, %v", name, got, err)
		}
		always, _ := json.Marshal(got[0].AlwaysDisclosed)
		if want := `[["address","country"],["nationality"]]`; string(always) != want {
			t.Errorf("%s: AlwaysDisclosed = %s, want %s", name, always, want)
		}
	}
}
