package verifier_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/internal/cose"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/statuslist"
	"github.com/idfoundry/oid4vcgo/verifier"
)

// An mdoc's revocation list must be signed under the IACA that signed
// its document signer (ISO/IEC 18013-5 §12.3.6), not under another IACA
// the verifier also trusts; or under the Certificate its MSO's status
// names; or by a Status Issuer the policy accepts.
func TestRequireValidStatus_MdocSignerUnderTheDocumentSignersIACA(t *testing.T) {
	iaca, iacaKey := testcert.CA(t, "IACA")
	other, otherKey := testcert.CA(t, "another IACA")
	named, namedKey := testcert.CA(t, "the MSO's status certificate")
	ds, _ := testcert.Leaf(t, "document signer", iaca, iacaKey)
	roots := x509.NewCertPool()
	roots.AddCert(iaca)
	roots.AddCert(other)

	signers := map[string]struct {
		cert *x509.Certificate
		key  *ecdsa.PrivateKey
	}{}
	for path, ca := range map[string]struct {
		cert *x509.Certificate
		key  *ecdsa.PrivateKey
	}{"/same": {iaca, iacaKey}, "/other": {other, otherKey}, "/named": {named, namedKey}, "/no-exp": {iaca, iacaKey}, "/unprotected": {iaca, iacaKey}} {
		cert, key := testcert.Leaf(t, "status signer "+path, ca.cert, ca.key)
		signers[path] = struct {
			cert *x509.Certificate
			key  *ecdsa.PrivateKey
		}{cert, key}
	}
	var base string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		signer, ok := signers[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		sl, err := statuslist.New(statuslist.Bits1, []uint8{0}, "")
		if err != nil {
			t.Error(err)
			return
		}
		exp := time.Now().Add(time.Hour).Unix()
		claims := statuslist.TokenClaims{Sub: base + r.URL.Path, Iat: time.Now().Unix(), Exp: &exp, StatusList: sl}
		if r.URL.Path == "/no-exp" {
			claims.Exp = nil
		}
		token, err := statuslist.IssueTokenCWTX5Chain(signer.key, cose.ES256, claims, []*x509.Certificate{signer.cert})
		if err != nil {
			t.Error(err)
		}
		if r.URL.Path == "/unprotected" {
			// The same token with its x5chain moved to the unprotected header.
			_, _, payload, err := cose.DecodeUnverifiedTagged(token)
			if err != nil {
				t.Error(err)
			}
			token, err = cose.SignTagged(cose.ES256, signer.key, cose.Headers{Typ: statuslist.CWTTokenMediaType}, cose.Headers{X5Chain: [][]byte{signer.cert.Raw}}, payload, nil)
			if err != nil {
				t.Error(err)
			}
		}
		w.Header().Set("Content-Type", statuslist.CWTTokenMediaType)
		_, _ = w.Write(token)
	}))
	defer srv.Close()
	base = srv.URL
	credential := func(path string, certificate []byte) verifier.VerifyResponseResult {
		return verifier.VerifyResponseResult{Credentials: []verifier.VerifiedCredential{{
			MdocStatus:  &mdoc.Status{StatusList: &mdoc.StatusListRef{Idx: 0, URI: base + path, Certificate: certificate}},
			IssuerChain: [][]byte{ds.Raw},
		}}}
	}
	checker := statuslist.Checker{Fetcher: statuslist.Fetcher{HTTP: srv.Client(), AllowLoopback: true}, Roots: roots}
	ctx := context.Background()
	strict := verifier.RequireValidStatus(checker)

	if err := strict(ctx, "id", credential("/same", nil)); err != nil {
		t.Errorf("signed under the document signer's IACA: %v", err)
	}
	if err := strict(ctx, "id", credential("/other", nil)); err == nil {
		t.Error("accepted a list signed under another trusted IACA")
	}
	// ISO/IEC 18013-5 §12.3.6.3: exp present, x5chain protected.
	if err := strict(ctx, "id", credential("/no-exp", nil)); err == nil || !strings.Contains(err.Error(), "missing the required exp") {
		t.Errorf("a list without exp: %v", err)
	}
	if err := strict(ctx, "id", credential("/unprotected", nil)); err == nil || !strings.Contains(err.Error(), "token signer") {
		t.Errorf("a list with an unprotected x5chain: %v", err)
	}
	if err := strict(ctx, "id", credential("/named", named.Raw)); err != nil {
		t.Errorf("signed under the Certificate the MSO's status names: %v", err)
	}
	if err := strict(ctx, "id", credential("/same", named.Raw)); err == nil {
		t.Error("accepted a list not under the Certificate the MSO's status names")
	}
	delegated := verifier.RequireValidStatusFrom(checker, func(issuer string, leaf *x509.Certificate, _ [][]*x509.Certificate) error {
		if issuer == "" && leaf.Equal(signers["/other"].cert) {
			return nil
		}
		return errors.New("not a Status Issuer")
	})
	// ISO/IEC 18013-5 §12.3.6.2 binds the list of an mdoc whose issuer
	// chain is known to its own IACA: a Status Issuer the policy
	// accepts, for other credentials, doesn't decide it.
	if err := delegated(ctx, "id", credential("/other", nil)); err == nil || !strings.Contains(err.Error(), "12.3.6.2") {
		t.Errorf("a Status Issuer the policy accepts, for an mdoc whose chain is known: %v, want refused", err)
	}
	// One verified with no issuer chain, and whose MSO names no
	// Certificate, has nothing else to bind its list's signer: the
	// policy decides it.
	unchained := credential("/other", nil)
	unchained.Credentials[0].IssuerChain = nil
	if err := delegated(ctx, "id", unchained); err != nil {
		t.Errorf("a Status Issuer the policy accepts, for an mdoc with no chain: %v", err)
	}
}

// Under a root with an intermediate per issuer, the list's signer is
// bound to the intermediate that signed the document signer: another
// issuer's, under the same root, can't decide this mdoc's status.
func TestRequireValidStatus_MdocSignerUnderTheDocumentSignersIntermediate(t *testing.T) {
	root, rootKey := testcert.CA(t, "national root")
	caA, caAKey := testcert.Intermediate(t, "issuer A CA", root, rootKey)
	caB, caBKey := testcert.Intermediate(t, "issuer B CA", root, rootKey)
	dsA, _ := testcert.Leaf(t, "issuer A document signer", caA, caAKey)
	signerA, signerAKey := testcert.Leaf(t, "issuer A status signer", caA, caAKey)
	signerB, signerBKey := testcert.Leaf(t, "issuer B status signer", caB, caBKey)
	roots := x509.NewCertPool()
	roots.AddCert(root)

	var base string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key, chain := signerAKey, []*x509.Certificate{signerA, caA}
		if r.URL.Path == "/b" {
			key, chain = signerBKey, []*x509.Certificate{signerB, caB}
		}
		sl, err := statuslist.New(statuslist.Bits1, []uint8{0}, "")
		if err != nil {
			t.Error(err)
			return
		}
		exp := time.Now().Add(time.Hour).Unix()
		token, err := statuslist.IssueTokenCWTX5Chain(key, cose.ES256, statuslist.TokenClaims{Sub: base + r.URL.Path, Iat: time.Now().Unix(), Exp: &exp, StatusList: sl}, chain)
		if err != nil {
			t.Error(err)
		}
		w.Header().Set("Content-Type", statuslist.CWTTokenMediaType)
		_, _ = w.Write(token)
	}))
	defer srv.Close()
	base = srv.URL
	// IssuerChain as VerifyResponse reports it: the document signer
	// first, without the anchor.
	credential := func(path string) verifier.VerifyResponseResult {
		return verifier.VerifyResponseResult{Credentials: []verifier.VerifiedCredential{{
			MdocStatus:  &mdoc.Status{StatusList: &mdoc.StatusListRef{Idx: 0, URI: base + path}},
			IssuerChain: [][]byte{dsA.Raw, caA.Raw},
		}}}
	}
	strict := verifier.RequireValidStatus(statuslist.Checker{Fetcher: statuslist.Fetcher{HTTP: srv.Client(), AllowLoopback: true}, Roots: roots})
	if err := strict(context.Background(), "id", credential("/a")); err != nil {
		t.Errorf("signed under the document signer's own CA: %v", err)
	}
	if err := strict(context.Background(), "id", credential("/b")); err == nil {
		t.Error("accepted a list signed under another issuer's CA of the same root")
	}
}
