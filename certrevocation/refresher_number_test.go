package certrevocation_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
)

// An issuer whose lists carried a CRL number keeps carrying one (RFC
// 5280 §5.2.3 makes it mandatory): an unnumbered list, even with the
// same thisUpdate as the numbered one held, which the thisUpdate floor
// alone lets through, is refused, so an attacker on plain http can't
// swap it back in. Without a numbered list before it, one is accepted.
func TestRefresher_UnnumberedAfterNumbered(t *testing.T) {
	p := newPKI(t)
	srv := newCRLServer(t)
	r := newRefresher(t, certrevocation.RefresherConfig{URLs: []string{srv.URL + "/ca.crl"}, Issuers: []*x509.Certificate{p.inter}})
	thisUpdate := time.Now().Add(-time.Minute).Truncate(time.Second)
	unnumbered := withoutNumber(t, testcert.CRLFromTemplate(t, &x509.RevocationList{
		Number: big.NewInt(1), ThisUpdate: thisUpdate, NextUpdate: thisUpdate.Add(2 * time.Hour),
	}, p.inter, p.interKey), p.interKey)
	if unnumbered.Number != nil {
		t.Fatalf("the unnumbered list has number %s", unnumbered.Number)
	}
	srv.serveCRL("/ca.crl", unnumbered)
	if err := r.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh, an unnumbered list first: %v", err)
	}
	revoking := testcert.CRLFromTemplate(t, &x509.RevocationList{
		Number: big.NewInt(3), ThisUpdate: thisUpdate, NextUpdate: thisUpdate.Add(2 * time.Hour),
		RevokedCertificateEntries: []x509.RevocationListEntry{{SerialNumber: p.leaf.SerialNumber, RevocationTime: thisUpdate}},
	}, p.inter, p.interKey)
	srv.serveCRL("/ca.crl", revoking)
	if err := r.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh, a numbered list after it: %v", err)
	}
	srv.serveCRL("/ca.crl", unnumbered)
	if err := r.Refresh(context.Background()); err == nil || !strings.Contains(err.Error(), "carries no CRL number") {
		t.Fatalf("Refresh, the unnumbered list again = %v, want it refused", err)
	}
	if held := heldList(t, r); held.Number == nil || held.Number.Cmp(big.NewInt(3)) != 0 {
		t.Errorf("held list number = %v, want the numbered list kept", held.Number)
	}
}

// withoutNumber is list re-signed by key with its CRL number extension
// removed, which x509.CreateRevocationList can't produce.
func withoutNumber(t *testing.T, list *x509.RevocationList, key *ecdsa.PrivateKey) *x509.RevocationList {
	t.Helper()
	var cl pkix.CertificateList
	if _, err := asn1.Unmarshal(list.Raw, &cl); err != nil {
		t.Fatal(err)
	}
	crlNumber := asn1.ObjectIdentifier{2, 5, 29, 20}
	cl.TBSCertList.Raw = nil
	cl.TBSCertList.Extensions = slices.DeleteFunc(cl.TBSCertList.Extensions, func(e pkix.Extension) bool { return e.Id.Equal(crlNumber) })
	tbs, err := asn1.Marshal(cl.TBSCertList)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(tbs)
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	der, err := asn1.Marshal(struct {
		TBS       asn1.RawValue
		Algorithm pkix.AlgorithmIdentifier
		Signature asn1.BitString
	}{asn1.RawValue{FullBytes: tbs}, cl.SignatureAlgorithm, asn1.BitString{Bytes: sig, BitLength: 8 * len(sig)}})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseRevocationList(der)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}
