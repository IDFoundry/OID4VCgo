package sdjwtvc_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/statuslist"
)

// Wiring test: statuslist.StatusListRef.Claim's map[string]any shape
// must be exactly what sdjwtvc.Claims.Status expects, and what a
// Verifier reads back out of Verify's returned payload — this is the
// integration draft-11 §3.2.2.2's status claim and draft-12 §6.2 both
// describe, exercised across both packages rather than asserted in
// either one's own tests alone.
func TestSDJWTVC_StatusClaim_WiresIntoStatuslist(t *testing.T) {
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	ref := statuslist.StatusListRef{Idx: 3, URI: "https://example.com/statuslists/1"}
	claims := sdjwtvc.Claims{
		VCT:    "https://credentials.example.com/identity_credential",
		Status: ref.Claim(),
	}

	sdjwt, _, err := sdjwtvc.Issue(issuerKey, jose.ES256, claims, sdjwtvc.IssueOptions{})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	payload, _, err := sdjwtvc.Verify(sdjwt, &issuerKey.PublicKey, jose.ES256, sdjwtvc.VerifyOptions{})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	status, ok := payload["status"].(map[string]any)
	if !ok {
		t.Fatalf("payload[\"status\"] is not an object: %#v", payload["status"])
	}
	got, err := statuslist.ParseStatusClaim(status)
	if err != nil {
		t.Fatalf("ParseStatusClaim: %v", err)
	}
	if got != ref {
		t.Errorf("ParseStatusClaim = %+v, want %+v", got, ref)
	}
}
