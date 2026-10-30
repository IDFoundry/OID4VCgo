package proximity

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
)

// WithIssuerRevocation refuses a document whose document signer
// certificate is revoked, and is required: a nil checker is refused.
func TestVerify_IssuerRevocation(t *testing.T) {
	fx := issueFixture(t, mDL)
	for _, c := range testcert.RevocationCases(t, fx.ca, fx.caKey, fx.signer) {
		t.Run(c.Name, func(t *testing.T) {
			if c.Checker == nil {
				if _, err := NewReaderSession(mustQR(t), devReader(WithIssuerRevocation(nil))...); err == nil || !strings.Contains(err.Error(), "WithIssuerRevocation is required") {
					t.Fatalf("no revocation choice: %v, want it refused", err)
				}
				return
			}
			f := establishReader(t, mDL, ageOver18, WithIssuerRevocation(c.Checker))
			_, err := f.reader.Verify(context.Background(), f.respond(t, fx, f.req.Elements), fx.roots, time.Now())
			c.Check(t, err)
		})
	}
	if _, err := NewReaderSession(mustQR(t), devReader(WithIssuerRevocation(certrevocation.CRLs{}))...); err == nil {
		t.Error("NewReaderSession accepted CRLs without Lists")
	}
}

// ReaderTrust.Revocation leaves a reader whose certificate is revoked
// untrusted.
func TestVerifyReaderAuth_Revocation(t *testing.T) {
	ca, caKey := testcert.CA(t, "proximity revocation test reader CA")
	cert, key := testcert.Issue(t, &x509.Certificate{
		Subject: pkix.Name{CommonName: "proximity revocation test reader"}, KeyUsage: x509.KeyUsageDigitalSignature,
	}, ca, caKey)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	f := establishReader(t, mDL, ageOver18, WithReaderAuth(key, []*x509.Certificate{cert}))
	testcert.RunRevocationCases(t, ca, caKey, cert, func(t *testing.T, revocation certrevocation.Checker) error {
		got := f.holder.VerifyReaderAuth(f.req, ReaderTrust{Roots: roots, Revocation: revocation})
		if (got.Status == ReaderTrusted) != (got.Err == nil) {
			t.Errorf("Status %v with Err %v", got.Status, got.Err)
		}
		return got.Err
	})
}

// mustQR is a fresh holder's QR code.
func mustQR(t *testing.T) string {
	t.Helper()
	holder, err := NewDeviceSession(nil)
	if err != nil {
		t.Fatal(err)
	}
	return holder.QRCode()
}
