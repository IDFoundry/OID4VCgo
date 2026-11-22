package verifier_test

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/verifier"
	"github.com/idfoundry/oid4vcgo/verifier/verifiertest"
)

// certPool is a pool of certs.
func certPool(certs ...*x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, c := range certs {
		pool.AddCert(c)
	}
	return pool
}

// RootsByVCT holds each credential type to its own anchors, as
// X5ChainIssuerKeyResolver.RootsByDocType holds each document type: an
// issuer trusted for loyalty cards can't sign a PID, a type it doesn't
// name falls back to Roots, or is refused without Roots, and a type
// named with nil anchors is refused. A credential's aka_vcts are held
// to their types' anchors too: a loyalty card can't answer a PID query
// by listing the PID type there.
func TestX5CIssuerKeyResolver_RootsByVCT(t *testing.T) {
	const pid, loyalty, other = "urn:pid:1", "urn:loyalty:1", "urn:other:1"
	pidCA, pidCAKey := verifiertest.ContractCA(t, "PID CA")
	loyaltyCA, loyaltyCAKey := verifiertest.ContractCA(t, "Loyalty CA")
	pidLeaf, _ := verifiertest.ContractLeaf(t, "PID signer", pidCA, pidCAKey)
	loyaltyLeaf, _ := verifiertest.ContractLeaf(t, "Loyalty signer", loyaltyCA, loyaltyCAKey)
	both := certPool(pidCA, loyaltyCA)
	byType := verifier.X5CIssuerKeyResolver{Revocation: certrevocation.NoCheck{}, RootsByVCT: map[string]*x509.CertPool{pid: certPool(pidCA), loyalty: certPool(loyaltyCA)}}
	withRoots := byType
	withRoots.Roots = certPool(loyaltyCA)
	withBoth := byType
	withBoth.RootsByVCT = map[string]*x509.CertPool{pid: both, loyalty: certPool(loyaltyCA)}
	payload := func(vct any, aka ...any) map[string]any {
		p := map[string]any{"vct": vct}
		if aka != nil {
			p["aka_vcts"] = aka
		}
		return p
	}
	ctx := context.Background()
	for name, tc := range map[string]struct {
		r       verifier.X5CIssuerKeyResolver
		leaf    *x509.Certificate
		payload map[string]any
		ok      bool
	}{
		"PID signer, PID":                     {byType, pidLeaf, payload(pid), true},
		"loyalty signer, loyalty":             {byType, loyaltyLeaf, payload(loyalty), true},
		"loyalty signer, PID":                 {byType, loyaltyLeaf, payload(pid), false},
		"PID signer, loyalty":                 {byType, pidLeaf, payload(loyalty), false},
		"unnamed type, no Roots":              {byType, pidLeaf, payload(other), false},
		"unnamed type, Roots":                 {withRoots, loyaltyLeaf, payload(other), true},
		"named type ignores Roots":            {withRoots, loyaltyLeaf, payload(pid), false},
		"type named with nil anchors":         {verifier.X5CIssuerKeyResolver{Roots: both, RootsByVCT: map[string]*x509.CertPool{pid: nil}, Revocation: certrevocation.NoCheck{}}, pidLeaf, payload(pid), false},
		"neither":                             {verifier.X5CIssuerKeyResolver{Revocation: certrevocation.NoCheck{}}, pidLeaf, payload(pid), false},
		"no vct":                              {byType, pidLeaf, map[string]any{}, false},
		"vct not a string":                    {byType, pidLeaf, payload(1), false},
		"loyalty card claiming PID (aka)":     {byType, loyaltyLeaf, payload(loyalty, pid), false},
		"loyalty card, unnamed aka, no Roots": {byType, loyaltyLeaf, payload(loyalty, other), false},
		"loyalty card, unnamed aka, Roots":    {withRoots, loyaltyLeaf, payload(loyalty, other), true},
		"loyalty card, its own type as aka":   {byType, loyaltyLeaf, payload(loyalty, loyalty), true},
		"aka trusted for both types":          {withBoth, loyaltyLeaf, payload(loyalty, pid), true},
		"aka not an array":                    {byType, loyaltyLeaf, map[string]any{"vct": loyalty, "aka_vcts": pid}, false},
		"aka entry not a string":              {byType, loyaltyLeaf, payload(loyalty, 1), false},
	} {
		if _, _, err := tc.r.ResolveIssuerKey(ctx, x5cHeader(tc.leaf), tc.payload); (err == nil) != tc.ok {
			t.Errorf("%s: %v; want ok=%v", name, err, tc.ok)
		}
	}

	// Its chains can't be resolved from the header alone: the vct
	// chooses the anchors.
	if _, err := byType.ResolveIssuerChains(ctx, x5cHeader(pidLeaf)); err == nil {
		t.Error("ResolveIssuerChains resolved without the credential's vct")
	}
	if chains, err := (verifier.X5CIssuerKeyResolver{Roots: both, Revocation: certrevocation.NoCheck{}}).ResolveIssuerChains(ctx, x5cHeader(pidLeaf)); err != nil || len(chains) == 0 {
		t.Errorf("ResolveIssuerChains without RootsByVCT: %v", err)
	}
}

// FallbackTypes reports, by credential query ID, the types a query asks
// for that RootsByVCT doesn't name while Roots is set: those every
// anchor in Roots may sign. A type it names, even with nil anchors, and
// an mdoc query aren't; nothing is without both RootsByVCT and Roots,
// where no type falls back.
func TestX5CIssuerKeyResolver_FallbackTypes(t *testing.T) {
	roots := x509.NewCertPool()
	byType := map[string]*x509.CertPool{"urn:pid:1": x509.NewCertPool(), "urn:loyalty:1": nil}
	query := dcql.Query{Credentials: []dcql.CredentialQuery{
		{ID: "pid", Format: "dc+sd-jwt", Meta: json.RawMessage(`{"vct_values":["urn:pid:1","urn:pid:legacy"]}`)},
		{ID: "loyalty", Format: "dc+sd-jwt", Meta: json.RawMessage(`{"vct_values":["urn:loyalty:1"]}`)},
		{ID: "other", Format: "dc+sd-jwt", Meta: json.RawMessage(`{"vct_values":["urn:other:1","urn:other:2"]}`)},
		{ID: "mdl", Format: "mso_mdoc", Meta: json.RawMessage(`{"doctype_value":"org.iso.18013.5.1.mDL"}`)},
	}}
	for name, tc := range map[string]struct {
		r    verifier.X5CIssuerKeyResolver
		want map[string][]string
	}{
		"RootsByVCT and Roots": {verifier.X5CIssuerKeyResolver{Roots: roots, RootsByVCT: byType}, map[string][]string{"pid": {"urn:pid:legacy"}, "other": {"urn:other:1", "urn:other:2"}}},
		"RootsByVCT alone":     {verifier.X5CIssuerKeyResolver{RootsByVCT: byType}, map[string][]string{}},
		"Roots alone":          {verifier.X5CIssuerKeyResolver{Roots: roots}, map[string][]string{}},
	} {
		if got := tc.r.FallbackTypes(query); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: FallbackTypes = %v, want %v", name, got, tc.want)
		}
	}
}
