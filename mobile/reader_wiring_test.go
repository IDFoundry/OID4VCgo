//go:build mobiletest

package mobile

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/internal/teststatuslist"
	"github.com/idfoundry/oid4vcgo/proximity"
	"github.com/idfoundry/oid4vcgo/walletflow/walletflowtest"
)

// readerVerdict runs an in-person presentation of h's mdoc, mdocID, to a
// reader configured by cfg, and returns the reader's last event.
func readerVerdict(t *testing.T, h harness, mdocID, cfg string) readerEvent {
	t.Helper()
	rd, err := NewProximityReader(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	holder, err := h.w.StartProximityPresentation()
	if err != nil {
		t.Fatal(err)
	}
	s, err := rd.Start(decode[struct {
		QRCode string `json:"qr_code"`
	}](t, holder.Engagement()).QRCode)
	if err != nil {
		t.Fatal(err)
	}
	req, err := s.Request(walletflowtest.DocType, `{"`+walletflowtest.NameSpace+`": ["family_name"]}`)
	if err != nil {
		t.Fatal(err)
	}
	if ev := decode[proximityEvent](t, holder.HandleMessage(NewOperation(0), sent(t, decode[struct{ Send string }](t, req).Send))); ev.Event != "request" {
		t.Fatalf("holder: %+v", ev)
	}
	out, err := holder.Respond(NewOperation(0), 0, mdocID, `[["`+walletflowtest.NameSpace+`","family_name"]]`)
	if err != nil {
		t.Fatal(err)
	}
	return decode[readerEvent](t, s.HandleMessage(sent(t, decode[struct{ Send string }](t, out).Send)))
}

// issuer_roots_by_doctype holds a document type to its own IACAs, in
// place of issuer_roots: an mdoc of the type its IACA under issuer_roots
// signed, but not that type's, isn't verified.
func TestSessions_ProximityReaderRootsByDocTypeWin(t *testing.T) {
	h := newHarness(t, false)
	var mdocID string
	for _, c := range h.receive(t) {
		if c.Format == "mso_mdoc" {
			mdocID = c.ID
		}
	}
	other, _ := testcert.CA(t, "another IACA")
	for name, tc := range map[string]struct {
		roots    string
		verified bool
	}{
		"the type's IACA":   {issuerRootsPEM(t, h), true},
		"another IACA only": {pemOf("CERTIFICATE", other.Raw), false},
	} {
		cfg, _ := readerConfig(t, h, nil, map[string]any{"issuer_roots_by_doctype": map[string]string{walletflowtest.DocType: tc.roots}})
		got := readerVerdict(t, h, mdocID, cfg)
		switch {
		case tc.verified && got.Event != "verified":
			t.Errorf("%s: %+v, want verified", name, got)
		case !tc.verified && (got.Event != "ended" || got.Reason != "error"):
			t.Errorf("%s: %+v, want an error", name, got)
		}
	}
}

// Naming no Certificate, a status list's signer must be under the CA
// that signed the document signer, not only under the root: a signer
// under a sibling intermediate of the same IACA is refused.
func TestProximityReader_CheckStatusUnderDocumentSignersCA(t *testing.T) {
	iaca, iacaKey := testcert.CA(t, "IACA")
	dsCA, dsCAKey := testcert.Intermediate(t, "Document signer CA", iaca, iacaKey)
	sibling, siblingKey := testcert.Intermediate(t, "Sibling CA", iaca, iacaKey)
	ds, _ := testcert.Leaf(t, "Document signer", dsCA, dsCAKey)
	saved := testHTTP.Load()
	defer testHTTP.Store(saved)
	r := &ProximityReader{clock: time.Now}
	for name, tc := range map[string]struct {
		ca       *x509.Certificate
		key      *ecdsa.PrivateKey
		verified bool
	}{
		"under the document signer's CA": {dsCA, dsCAKey, true},
		"under a sibling CA":             {sibling, siblingKey, false},
	} {
		t.Run(name, func(t *testing.T) {
			leaf, leafKey := testcert.Leaf(t, "List signer", tc.ca, tc.key)
			signer := teststatuslist.Signer{CA: iaca, Key: leafKey, Chain: []*x509.Certificate{leaf, tc.ca}}
			statusURI, client := signer.Serve(t, teststatuslist.WellFormed)
			testHTTP.Store(client)
			got, err := r.checkStatus(context.Background(), proximity.Verified{
				Status:      &mdoc.Status{StatusList: &mdoc.StatusListRef{Idx: 3, URI: statusURI}},
				IssuerChain: []*x509.Certificate{ds, dsCA, iaca},
			})
			switch {
			case tc.verified && (err != nil || got != "valid"):
				t.Errorf("checkStatus = %q, %v; want valid", got, err)
			case !tc.verified && err == nil:
				t.Errorf("checkStatus = %q, want it refused", got)
			}
		})
	}
}

// With "status" in "revocation", a status list's and an identifier
// list's signer are checked against the CRLs: a signer the IACA's list
// revokes fails the check.
func TestProximityReader_StatusListSignerRevocation(t *testing.T) {
	iaca, iacaKey := testcert.CA(t, "IACA")
	ds, _ := testcert.Leaf(t, "Document signer", iaca, iacaKey)
	leaf, leafKey := testcert.Leaf(t, "List signer", iaca, iacaKey)
	signer := teststatuslist.Signer{CA: iaca, Key: leafKey, Chain: []*x509.Certificate{leaf}}
	saved := testHTTP.Load()
	defer testHTTP.Store(saved)
	for name, tc := range map[string]struct {
		statusList bool
		revoked    bool
	}{
		"status list, signer current":     {true, false},
		"status list, signer revoked":     {true, true},
		"identifier list, signer current": {false, false},
		"identifier list, signer revoked": {false, true},
	} {
		t.Run(name, func(t *testing.T) {
			var revoked []*x509.Certificate
			if tc.revoked {
				revoked = append(revoked, leaf)
			}
			r := &ProximityReader{clock: time.Now, statusRevocation: testcert.CRLs(t, iaca, iacaKey, revoked...)}
			statusURI, idsURI, client := signer.ServeLists(t, teststatuslist.WellFormed)
			testHTTP.Store(client)
			status := &mdoc.Status{IdentifierList: &mdoc.IdentifierListRef{ID: []byte{2}, URI: idsURI}}
			if tc.statusList {
				status = &mdoc.Status{StatusList: &mdoc.StatusListRef{Idx: 3, URI: statusURI}}
			}
			got, err := r.checkStatus(context.Background(), proximity.Verified{Status: status, IssuerChain: []*x509.Certificate{ds, iaca}})
			switch {
			case !tc.revoked && (err != nil || got != "valid"):
				t.Errorf("checkStatus = %q, %v; want valid", got, err)
			case tc.revoked && !errors.Is(err, certrevocation.ErrRevoked):
				t.Errorf("checkStatus = %q, %v; want the signer revoked", got, err)
			}
		})
	}
}
