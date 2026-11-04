package walletflow

import (
	"testing"
	"time"
)

// A copy whose issuer certificate CheckStatus last refused
// (IssuerUntrusted) is passed over like a revoked one, even for the
// Verifier that saw it; with no other copy left the credential isn't
// presentable, and once a check clears it, it's chosen again.
func TestNextCopy_PassesOverIssuerUntrustedCopies(t *testing.T) {
	now := time.Now()
	c := StoredCredential{Copies: []CredentialCopy{
		{HolderKeyID: "untrusted", IssuerUntrusted: true, ShownTo: []string{"v"}, ValidUntil: now.Add(time.Hour)},
		{HolderKeyID: "shown", Presented: true, ShownTo: []string{"x"}, ValidUntil: now.Add(time.Hour)},
	}}
	if _, cp := c.nextCopy("v", now); cp.HolderKeyID != "shown" {
		t.Errorf("nextCopy = %q, want the copy whose issuer is trusted", cp.HolderKeyID)
	}
	if _, cp, reused := c.copyFor(CopyPerVerifier, "v", now); reused || cp.HolderKeyID != "shown" {
		t.Errorf("copyFor = %q (reused %v), want the trusted copy instead of the one it saw", cp.HolderKeyID, reused)
	}
	c.Copies[1].IssuerUntrusted = true
	if c.Presentable(now) {
		t.Error("Presentable = true with every copy's issuer refused")
	}
	c.Copies[0].IssuerUntrusted = false
	if _, cp, reused := c.copyFor(CopyPerVerifier, "v", now); !reused || cp.HolderKeyID != "untrusted" {
		t.Errorf("copyFor = %q (reused %v), want the copy it saw, trusted again", cp.HolderKeyID, reused)
	}
}

// combineStatus: a list's revocation wins and is kept; then a refused
// issuer; then a list's other statuses; then unknown for want of a CRL.
func TestCombineStatus(t *testing.T) {
	for _, tc := range []struct {
		value, reason, issuer string
		want, wantReason      string
	}{
		{StatusInvalid, ReasonStatusList, ReasonIssuerCertificateRevoked, StatusInvalid, ReasonStatusList},
		{StatusValid, "", ReasonIssuerCertificateRevoked, StatusInvalid, ReasonIssuerCertificateRevoked},
		{StatusSuspended, ReasonStatusList, ReasonIssuerUntrusted, StatusInvalid, ReasonIssuerUntrusted},
		{StatusSuspended, ReasonStatusList, ReasonNoCurrentCRL, StatusSuspended, ReasonStatusList},
		{StatusValid, "", ReasonNoCurrentCRL, StatusUnknown, ReasonNoCurrentCRL},
		{StatusUnknown, ReasonUnrecognizedStatus, ReasonNoCurrentCRL, StatusUnknown, ReasonNoCurrentCRL},
		{StatusUnknown, ReasonUnrecognizedStatus, "", StatusUnknown, ReasonUnrecognizedStatus},
		{StatusUnknown, ReasonNoCurrentCRL, "", StatusUnknown, ReasonNoCurrentCRL},
		{StatusValid, "", "", StatusValid, ""},
	} {
		if v, r := combineStatus(tc.value, tc.reason, tc.issuer); v != tc.want || r != tc.wantReason {
			t.Errorf("combineStatus(%s, %q, %q) = %s, %q; want %s, %q", tc.value, tc.reason, tc.issuer, v, r, tc.want, tc.wantReason)
		}
	}
}

// issuerStatus: invalid only once no live copy is left that a list or
// the check doesn't refuse; undecided is unknown, and a copy refused
// before and undecided now stays refused.
func TestIssuerStatus(t *testing.T) {
	now := time.Now()
	live := now.Add(time.Hour)
	c := StoredCredential{Copies: []CredentialCopy{
		{Credential: "a", ValidUntil: live},
		{Credential: "b", ValidUntil: live},
		{Credential: "expired", ValidUntil: now.Add(-time.Hour)},
	}}
	for _, tc := range []struct {
		name    string
		checks  issuerChecks
		revoked map[string]bool
		want    string
	}{
		{"all trusted", issuerChecks{"a": issuerTrusted, "b": issuerTrusted}, nil, ""},
		{"one revoked", issuerChecks{"a": issuerRevoked, "b": issuerTrusted}, nil, ""},
		{"both revoked", issuerChecks{"a": issuerRevoked, "b": issuerRevoked}, nil, ReasonIssuerCertificateRevoked},
		{"revoked and untrusted", issuerChecks{"a": issuerRevoked, "b": issuerUntrusted}, nil, ReasonIssuerCertificateRevoked},
		{"untrusted", issuerChecks{"a": issuerUntrusted, "b": issuerUntrusted}, nil, ReasonIssuerUntrusted},
		{"revoked, the other on a list", issuerChecks{"a": issuerRevoked, "b": issuerTrusted}, map[string]bool{"b": true}, ReasonIssuerCertificateRevoked},
		{"undecided", issuerChecks{"a": issuerUndecided, "b": issuerTrusted}, nil, ReasonNoCurrentCRL},
		{"revoked and undecided", issuerChecks{"a": issuerRevoked, "b": issuerUndecided}, nil, ReasonNoCurrentCRL},
		{"nothing checked", issuerChecks{}, nil, ""},
	} {
		if got := tc.checks.issuerStatus(c, now, tc.revoked); got != tc.want {
			t.Errorf("%s: issuerStatus = %q, want %q", tc.name, got, tc.want)
		}
	}
	checks := issuerChecks{"a": issuerUndecided}
	if !checks.untrusted(CredentialCopy{Credential: "a", IssuerUntrusted: true}) || checks.untrusted(CredentialCopy{Credential: "a"}) {
		t.Error("an undecided check doesn't leave the copy as it was")
	}
}
