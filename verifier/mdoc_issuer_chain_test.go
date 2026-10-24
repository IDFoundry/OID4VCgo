package verifier_test

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/internal/conformancecert"
	"github.com/idfoundry/oid4vcgo/verifier"
)

// keyOnlyResolver resolves an mdoc's issuer key without verifying a
// certificate chain.
type keyOnlyResolver struct{ verifier.MdocIssuerKeyResolver }

// An mdoc's x5chain is an unprotected header, which the holder can
// edit: CheckMdocIssuer returns the path the resolver verified, not the
// presented chain, and no chain when the resolver verifies none.
func TestCheckMdocIssuer_ReturnsTheVerifiedPath(t *testing.T) {
	iaca, iacaKey, _, _, err := conformancecert.GenerateMdocIACA("chain test IACA", "US", "https://iaca.example")
	if err != nil {
		t.Fatal(err)
	}
	dsKey, _, dsPEM, err := conformancecert.GenerateMdocDocumentSigner("chain test DS", "US", "https://iaca.example", "https://iaca.example/crl", iaca, iacaKey)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(dsPEM))
	ds, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	// A CA the holder would like a trusted_authorities check to see.
	wanted, _, _, _, err := conformancecert.GenerateMdocIACA("the CA a query asks for", "US", "https://other.example")
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(iaca)
	resolver := verifier.X5ChainIssuerKeyResolver{Roots: roots, Revocation: certrevocation.NoCheck{}}
	verified := mdoc.VerifiedMSO{ValidityInfo: mdoc.ValidityInfo{Signed: time.Now()}}
	edited := [][]byte{ds.Raw, wanted.Raw}

	chain, err := verifier.CheckMdocIssuer(context.Background(), resolver, edited, "org.iso.18013.5.1.mDL", &dsKey.PublicKey, verified)
	if err != nil {
		t.Fatalf("CheckMdocIssuer: %v", err)
	}
	if len(chain) != 1 || string(chain[0]) != string(ds.Raw) {
		t.Errorf("chain has %d certificates, want only the verified document signer", len(chain))
	}

	chain, err = verifier.CheckMdocIssuer(context.Background(), keyOnlyResolver{resolver}, edited, "org.iso.18013.5.1.mDL", &dsKey.PublicKey, verified)
	if err != nil || chain != nil {
		t.Errorf("a resolver that verifies no chain: %d certificates, %v; want none", len(chain), err)
	}
}
