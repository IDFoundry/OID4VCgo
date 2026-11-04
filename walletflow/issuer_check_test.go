package walletflow_test

import (
	"context"
	"crypto/x509"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/statuslist"
	"github.com/idfoundry/oid4vcgo/walletflow"
	"github.com/idfoundry/oid4vcgo/walletflow/walletflowtest"
)

// swappableCRLs is an IssuerRevocation whose lists a test replaces.
type swappableCRLs struct {
	lists atomic.Pointer[[]*x509.RevocationList]
}

func (s *swappableCRLs) set(lists ...*x509.RevocationList) { s.lists.Store(&lists) }

func (s *swappableCRLs) checker() certrevocation.CRLs {
	return certrevocation.CRLs{Lists: func(context.Context) ([]*x509.RevocationList, error) {
		if p := s.lists.Load(); p != nil {
			return *p, nil
		}
		return nil, nil
	}}
}

// revocationWallet is a wallet over f's issuer checking its issuer
// certificates against crls, with clock.
func revocationWallet(t *testing.T, f fixture, crls *swappableCRLs, clock func() time.Time) *walletflow.Wallet {
	t.Helper()
	w, err := walletflow.New(walletflow.Config{
		ClientID: walletflowtest.ClientID, RedirectURI: walletflowtest.RedirectURI, Development: true,
		IssuerRoots: f.env.IssuerRoots, IssuerRevocation: crls.checker(),
	}, walletflow.Dependencies{Keys: f.keys, Credentials: f.store, Provider: f.env.Provider, HTTP: f.env.HTTP, Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	return w
}

// issuerCRL is f's issuer CA's CRL, listing its credentials' signer when
// revoked.
func issuerCRL(t *testing.T, f fixture, revoked bool) *x509.RevocationList {
	t.Helper()
	list, err := f.env.IssuerCRL(revoked)
	if err != nil {
		t.Fatal(err)
	}
	return list
}

// CheckStatus checks a credential's issuer certificate again: once a
// CRL lists its signer, every copy is unusable and the credential
// invalid, for that reason; it isn't final, so a later CRL without it
// makes it valid again; and with no current CRL it's unknown, not an
// error.
func TestCheckStatus_IssuerCertificateRevoked(t *testing.T) {
	f := newFixture(t, walletflowtest.Options{})
	crls := &swappableCRLs{}
	crls.set(issuerCRL(t, f, false))
	w := revocationWallet(t, f, crls, nil)
	held := receive(t, f, w, walletflowtest.SDJWTConfigurationID, walletflowtest.MdocConfigurationID)
	ctx := context.Background()
	check := func(step string, c walletflow.StoredCredential, value, reason string) walletflow.StoredCredential {
		t.Helper()
		checked, err := w.CheckStatus(ctx, c.ID)
		if err != nil || checked.Status.Value != value || checked.Status.Reason != reason || checked.Status.CheckedAt.IsZero() {
			t.Fatalf("%s: %s: CheckStatus = %+v, %v; want %s (%q)", step, c.Format, checked.Status, err, value, reason)
		}
		return checked
	}
	for _, c := range held {
		check("clean CRL", c, walletflow.StatusValid, "")
	}

	crls.set(issuerCRL(t, f, true))
	for _, c := range held {
		checked := check("signer revoked", c, walletflow.StatusInvalid, walletflow.ReasonIssuerCertificateRevoked)
		for i, cp := range checked.Copies {
			if !cp.IssuerUntrusted || cp.Revoked {
				t.Errorf("%s: copy %d: IssuerUntrusted %v, Revoked %v; want untrusted, not revoked", c.Format, i, cp.IssuerUntrusted, cp.Revoked)
			}
		}
		if checked.Presentable(time.Now()) {
			t.Errorf("%s: presentable with its signer revoked", c.Format)
		}
	}

	// No current CRL: unknown, and the copies stay as they were.
	crls.set()
	for _, c := range held {
		checked := check("no CRL", c, walletflow.StatusUnknown, walletflow.ReasonNoCurrentCRL)
		for i, cp := range checked.Copies {
			if !cp.IssuerUntrusted {
				t.Errorf("%s: copy %d trusted again without a CRL", c.Format, i)
			}
		}
	}

	// A newer CRL no longer listing it (a certificateHold lifted).
	crls.set(issuerCRL(t, f, false))
	for _, c := range held {
		checked := check("hold lifted", c, walletflow.StatusValid, "")
		for i, cp := range checked.Copies {
			if cp.IssuerUntrusted {
				t.Errorf("%s: copy %d still untrusted", c.Format, i)
			}
		}
		if !checked.Presentable(time.Now()) {
			t.Errorf("%s: not presentable once its signer passes again", c.Format)
		}
	}

	// A status list's revocation stays final: a clean CRL after it
	// doesn't make it valid.
	f.env.Revoke()
	var mu sync.Mutex
	now := time.Now().Add(statuslist.DefaultCacheMaxAge)
	later := revocationWallet(t, f, crls, func() time.Time { mu.Lock(); defer mu.Unlock(); return now })
	for _, c := range held {
		if checked, err := later.CheckStatus(ctx, c.ID); err != nil || checked.Status.Value != walletflow.StatusInvalid || checked.Status.Reason != walletflow.ReasonStatusList {
			t.Fatalf("%s: revoked on its list: %+v, %v", c.Format, checked.Status, err)
		}
		crls.set(issuerCRL(t, f, false))
		if checked, err := later.CheckStatus(ctx, c.ID); err != nil || checked.Status.Value != walletflow.StatusInvalid || checked.Status.Reason != walletflow.ReasonStatusList {
			t.Errorf("%s: a status list revocation undone: %+v, %v", c.Format, checked.Status, err)
		}
	}
}

// A credential with neither a status nor an identifier list is checked
// too, now that its issuer certificate is: it was returned unchecked.
func TestCheckStatus_IssuerCertificateWithoutStatusList(t *testing.T) {
	iaca, iacaKey := testcert.CA(t, "IACA")
	ds, dsKey := testcert.DocumentSigner(t, "Document signer", iaca, iacaKey)
	roots := x509.NewCertPool()
	roots.AddCert(iaca)
	c := mdocCredential(t, time.Now().Add(time.Hour), issueUnder(t, ds, dsKey, func(*mdoc.Claims) {}))
	ctx := context.Background()
	for name, tc := range map[string]struct {
		revocation    certrevocation.Checker
		value, reason string
	}{
		"clean":               {testcert.CRLs(t, iaca, iacaKey), walletflow.StatusValid, ""},
		"revoked":             {testcert.CRLs(t, iaca, iacaKey, ds), walletflow.StatusInvalid, walletflow.ReasonIssuerCertificateRevoked},
		"no CRL":              {testcert.ListsOf(), walletflow.StatusUnknown, walletflow.ReasonNoCurrentCRL},
		"no revocation check": {nil, walletflow.StatusValid, ""},
	} {
		w := walletHoldingWith(t, walletflow.Config{Development: true, MdocIssuerRoots: roots, IssuerRevocation: tc.revocation}, nil, c)
		checked, err := w.CheckStatus(ctx, c.ID)
		if err != nil || checked.Status.Value != tc.value || checked.Status.Reason != tc.reason || checked.Status.CheckedAt.IsZero() {
			t.Errorf("%s: CheckStatus = %+v, %v; want %s (%q)", name, checked.Status, err, tc.value, tc.reason)
		}
	}

	// Its issuer removed from the roots: untrusted, not final either.
	other, _ := testcert.CA(t, "Other IACA")
	otherRoots := x509.NewCertPool()
	otherRoots.AddCert(other)
	w := walletHoldingWith(t, walletflow.Config{Development: true, MdocIssuerRoots: otherRoots}, nil, c)
	if checked, err := w.CheckStatus(ctx, c.ID); err != nil || checked.Status.Value != walletflow.StatusInvalid || checked.Status.Reason != walletflow.ReasonIssuerUntrusted {
		t.Errorf("issuer no longer trusted: CheckStatus = %+v, %v", checked.Status, err)
	}

	// A wallet with no roots for it has nothing to check, as before.
	w = walletHoldingWith(t, walletflow.Config{Development: true}, nil, c)
	if checked, err := w.CheckStatus(ctx, c.ID); err != nil || checked.Status.Value != "" {
		t.Errorf("no roots: CheckStatus = %+v, %v; want it unchecked", checked.Status, err)
	}
}
