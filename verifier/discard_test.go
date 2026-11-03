package verifier_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/testverify"
	"github.com/idfoundry/oid4vcgo/verifier"
)

// A presentation that fails verification is discarded, and the rest
// stands while it still answers the query (OpenID4VP §8.6): one of two
// under multiple, or an optional credential set's. A required one that
// fails still fails the response.
func TestVerifyResponse_DiscardsFailedPresentations(t *testing.T) {
	falseVal := false
	for name, tc := range map[string]struct {
		query         dcql.Query
		vpToken       func(good, bad string) map[string][]string
		wantErr       bool
		wantVerified  int
		wantDiscarded string
	}{
		"one of two under multiple": {
			query: dcql.Query{Credentials: []dcql.CredentialQuery{{
				ID: "pid", Format: sdjwtvc.CredentialFormat, Meta: testverify.MustSDJWTVCMeta(t, testVCT), Multiple: true,
			}}},
			vpToken:      func(good, bad string) map[string][]string { return map[string][]string{"pid": {good, bad}} },
			wantVerified: 1, wantDiscarded: "pid",
		},
		"an optional set's": {
			query: dcql.Query{
				Credentials: twoCredentialQueries(t, "required_cq", "optional_cq"),
				CredentialSets: []dcql.CredentialSetQuery{
					{Options: [][]string{{"required_cq"}}},
					{Required: &falseVal, Options: [][]string{{"optional_cq"}}},
				},
			},
			vpToken: func(good, bad string) map[string][]string {
				return map[string][]string{"required_cq": {good}, "optional_cq": {bad}}
			},
			wantVerified: 1, wantDiscarded: "optional_cq",
		},
		"a required one": {
			query:   dcql.Query{Credentials: []dcql.CredentialQuery{vctCredentialQuery(t, "pid")}},
			vpToken: func(_, bad string) map[string][]string { return map[string][]string{"pid": {bad}} },
			wantErr: true,
		},
	} {
		cfg, deps := validConfig(t)
		v, err := verifier.New(cfg, deps)
		if err != nil {
			t.Fatal(err)
		}
		built, err := v.BuildAuthorizationRequest(verifier.BuildAuthorizationRequestRequest{Query: tc.query})
		if err != nil {
			t.Fatal(err)
		}
		issuerKey := testP256Key(t)
		good := newSDJWTVCPresentationWithIssuer(t, issuerKey, v.ClientID(), built.Nonce)
		bad := newSDJWTVCPresentationWithIssuer(t, testP256Key(t), v.ClientID(), built.Nonce)
		result, err := v.VerifyResponse(context.Background(), verifier.VerifyResponseRequest{
			Query:            tc.query,
			Response:         verifier.ParsedResponse{VPToken: tc.vpToken(good.compact, bad.compact)},
			ExpectedNonce:    built.Nonce,
			IssuerKeys:       fixedSDJWTVCIssuerKeyResolver{pub: &issuerKey.PublicKey, alg: jose.ES256},
			MaxKeyBindingAge: time.Hour,
		})
		if tc.wantErr {
			if err == nil {
				t.Errorf("%s: verified, want refused", name)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if len(result.Credentials) != tc.wantVerified || len(result.Discarded) != 1 || result.Discarded[0].CredentialQueryID != tc.wantDiscarded || result.Discarded[0].Reason == "" {
			t.Errorf("%s: %d verified, discarded %+v", name, len(result.Credentials), result.Discarded)
			continue
		}
		// The stored Reason is fixed text for its Code; the error, with
		// what the sender wrote, is kept apart.
		d := result.Discarded[0]
		var verr *verifier.Error
		if !errors.As(d.Err, &verr) || verr.Reason() != d.Code || !strings.HasSuffix(d.Reason, "("+string(d.Code)+")") || strings.Contains(d.Reason, "verifier:") {
			t.Errorf("%s: discarded %+v, want a fixed Reason for its Code and the error apart", name, d)
		}
	}
}

// One presentation of an optional set's option failing leaves the
// option unanswered: the option's other presentation is discarded with
// it, and the required set's answer stands (OpenID4VP §8.6).
func TestVerifyResponse_DiscardsTheRestOfAnIncompleteOption(t *testing.T) {
	falseVal := false
	query := dcql.Query{
		Credentials: []dcql.CredentialQuery{vctCredentialQuery(t, "a"), vctCredentialQuery(t, "b"), vctCredentialQuery(t, "c")},
		CredentialSets: []dcql.CredentialSetQuery{
			{Required: &falseVal, Options: [][]string{{"a", "b"}}},
			{Options: [][]string{{"c"}}},
		},
	}
	cfg, deps := validConfig(t)
	v, err := verifier.New(cfg, deps)
	if err != nil {
		t.Fatal(err)
	}
	built, err := v.BuildAuthorizationRequest(verifier.BuildAuthorizationRequestRequest{Query: query})
	if err != nil {
		t.Fatal(err)
	}
	issuerKey := testP256Key(t)
	good := func() string {
		return newSDJWTVCPresentationWithIssuer(t, issuerKey, v.ClientID(), built.Nonce).compact
	}
	bad := newSDJWTVCPresentationWithIssuer(t, testP256Key(t), v.ClientID(), built.Nonce).compact
	result, err := v.VerifyResponse(context.Background(), verifier.VerifyResponseRequest{
		Query:            query,
		Response:         verifier.ParsedResponse{VPToken: map[string][]string{"a": {good()}, "b": {bad}, "c": {good()}}},
		ExpectedNonce:    built.Nonce,
		IssuerKeys:       fixedSDJWTVCIssuerKeyResolver{pub: &issuerKey.PublicKey, alg: jose.ES256},
		MaxKeyBindingAge: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Credentials) != 1 || result.Credentials[0].CredentialQueryID != "c" {
		t.Errorf("verified %+v, want c alone", result.Credentials)
	}
	discarded := map[string]verifier.Reason{}
	for _, d := range result.Discarded {
		discarded[d.CredentialQueryID] = d.Code
	}
	if len(discarded) != 2 || discarded["a"] != verifier.ReasonNotAnswered || discarded["b"] == "" {
		t.Errorf("discarded %+v, want a (not answered) and b", result.Discarded)
	}
}

// A presentation bound to another request's nonce or audience isn't
// just discarded: the whole response is refused (OpenID4VP §14.1.2),
// even when the rest would answer the query.
func TestVerifyResponse_RefusesTheResponseForAnotherRequestsPresentation(t *testing.T) {
	query := dcql.Query{Credentials: []dcql.CredentialQuery{{
		ID: "pid", Format: sdjwtvc.CredentialFormat, Meta: testverify.MustSDJWTVCMeta(t, testVCT), Multiple: true,
	}}}
	cfg, deps := validConfig(t)
	v, err := verifier.New(cfg, deps)
	if err != nil {
		t.Fatal(err)
	}
	built, err := v.BuildAuthorizationRequest(verifier.BuildAuthorizationRequestRequest{Query: query})
	if err != nil {
		t.Fatal(err)
	}
	issuerKey := testP256Key(t)
	good := newSDJWTVCPresentationWithIssuer(t, issuerKey, v.ClientID(), built.Nonce)
	for name, bad := range map[string]string{
		"another nonce":    newSDJWTVCPresentationWithIssuer(t, issuerKey, v.ClientID(), "another-nonce").compact,
		"another audience": newSDJWTVCPresentationWithIssuer(t, issuerKey, "x509_hash:another-verifier", built.Nonce).compact,
	} {
		_, err := v.VerifyResponse(context.Background(), verifier.VerifyResponseRequest{
			Query:            query,
			Response:         verifier.ParsedResponse{VPToken: map[string][]string{"pid": {good.compact, bad}}},
			ExpectedNonce:    built.Nonce,
			IssuerKeys:       fixedSDJWTVCIssuerKeyResolver{pub: &issuerKey.PublicKey, alg: jose.ES256},
			MaxKeyBindingAge: time.Hour,
		})
		var verr *verifier.Error
		if !errors.As(err, &verr) || verr.Reason() != verifier.ReasonHolderBinding {
			t.Errorf("%s: %v, want the whole response refused as holder_binding", name, err)
		}
	}
}
