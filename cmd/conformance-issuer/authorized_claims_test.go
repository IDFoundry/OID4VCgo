package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/credential/mdoc"
)

// A token whose authorization_details name claims (§5.1.1) gets a
// credential with only those, in either format, issued at once or on
// the Deferred Credential Endpoint's poll, rather than everything
// Config.Claims or Config.Mdoc.Claims has.
func TestCredential_IssuesOnlyAuthorizedClaims(t *testing.T) {
	for _, deferred := range []bool{false, true} {
		e := startOffersTestServer(t, func(c *Config) {
			c.Claims = map[string]string{"given_name": "Jean", "family_name": "Dupont"}
			c.Mdoc = mdocTestConfig(t).Mdoc
			c.Deferred = deferred
		})
		for configID, path := range map[string][]any{
			e.cfg.CredentialConfigurationID:      {"given_name"},
			e.cfg.Mdoc.CredentialConfigurationID: {e.cfg.Mdoc.Namespace, "given_name"},
		} {
			t.Run(fmt.Sprintf("%s/deferred=%t", configID, deferred), func(t *testing.T) {
				credential := e.credentialAskingFor(t, configID, path)
				if got := issuedClaimNames(t, credential); !slices.Equal(got, []string{"given_name"}) {
					t.Errorf("issued claims = %v, want only given_name", got)
				}
			})
		}
	}
}

// An mdoc whose authorized claims are none it has can't be issued, so
// the request is refused with credential_request_denied, at once or on
// the poll.
func TestCredential_RefusesAnMdocWithNoAuthorizedClaim(t *testing.T) {
	for _, deferred := range []bool{false, true} {
		t.Run(fmt.Sprintf("deferred=%t", deferred), func(t *testing.T) {
			e := startOffersTestServer(t, func(c *Config) {
				c.Mdoc = mdocTestConfig(t).Mdoc
				c.Deferred = deferred
			})
			response := e.responseAskingFor(t, e.cfg.Mdoc.CredentialConfigurationID, []any{e.cfg.Mdoc.Namespace, "no_such_element"}, http.StatusBadRequest)
			if response["error"] != "credential_request_denied" {
				t.Errorf("response = %v, want credential_request_denied", response)
			}
		})
	}
}

// credentialAskingFor is the credential e issues for configID to a
// pre-authorized code whose Token Request asks for configID's claim at
// path, collected from the Deferred Credential Endpoint when e defers.
func (e offersTestEnv) credentialAskingFor(t *testing.T, configID string, path []any) string {
	t.Helper()
	response := e.responseAskingFor(t, configID, path, http.StatusOK)
	credentials, _ := response["credentials"].([]any)
	if len(credentials) != 1 {
		t.Fatalf("credential response = %v, want one credential", response)
	}
	credential, _ := credentials[0].(map[string]any)["credential"].(string)
	return credential
}

// responseAskingFor is e's answer, of status, to a Credential Request
// for configID by a pre-authorized code whose Token Request asks for
// configID's claim at path, or, when e defers, to its poll.
func (e offersTestEnv) responseAskingFor(t *testing.T, configID string, path []any, status int) map[string]any {
	t.Helper()
	offer, _ := e.offer(t, `{"grant":"pre-authorized_code","credential_configuration_ids":["`+configID+`"]}`)
	details, err := json.Marshal([]oid4vci.AuthorizationDetail{{
		Type: oid4vci.AuthorizationDetailsTypeOpenIDCredential, CredentialConfigurationID: configID,
		Claims: []oid4vci.ClaimsDescription{{Path: path}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	tokenStatus, token := e.do(t, e.preAuthorizedTokenRequest(t, offer.Grants.PreAuthorizedCode.PreAuthorizedCode, url.Values{"authorization_details": {string(details)}}, true))
	granted, _ := token["authorization_details"].([]any)
	if tokenStatus != http.StatusOK || len(granted) != 1 {
		t.Fatalf("token: %d %v, want 200 with one authorization_details entry", status, token)
	}
	ids, _ := granted[0].(map[string]any)["credential_identifiers"].([]any)
	if len(ids) != 1 {
		t.Fatalf("authorization_details[0] = %v, want one credential_identifier", granted[0])
	}
	now := time.Now()
	nonceResp := doJSON(t, e.client, mustRequest(t, http.MethodPost, e.cfg.Issuer+"/nonce"))
	holderKey, _ := newKeyPair(t)
	proof, err := buildCredentialProofJWT(holderKey, e.cfg.Client.ID, e.cfg.Issuer, nonceResp["c_nonce"].(string), now)
	if err != nil {
		t.Fatal(err)
	}
	accessToken, _ := token["access_token"].(string)
	body, err := json.Marshal(map[string]any{"credential_identifier": ids[0], "proofs": map[string][]string{"jwt": {proof}}})
	if err != nil {
		t.Fatal(err)
	}
	if !e.cfg.Deferred {
		return postProtected(t, e.client, e.cfg.Issuer+"/credential", e.clientKey, accessToken, body, now, status)
	}
	response := postProtected(t, e.client, e.cfg.Issuer+"/credential", e.clientKey, accessToken, body, now, http.StatusAccepted)
	poll, err := json.Marshal(map[string]any{"transaction_id": response["transaction_id"]})
	if err != nil {
		t.Fatal(err)
	}
	return postProtected(t, e.client, e.cfg.Issuer+deferredPath, e.clientKey, accessToken, poll, now, status)
}

// issuedClaimNames is the names of credential's claims about the
// holder: an SD-JWT VC's disclosures (this binary discloses each of
// Config.Claims selectively), or an mdoc's data elements.
func issuedClaimNames(t *testing.T, credential string) []string {
	t.Helper()
	var names []string
	if issuerJWT, disclosures, isSDJWT := strings.Cut(credential, "~"); isSDJWT && strings.Count(issuerJWT, ".") == 2 {
		for _, d := range strings.Split(disclosures, "~") {
			if d == "" {
				continue
			}
			var disclosure []any
			raw, err := base64.RawURLEncoding.DecodeString(d)
			if err == nil {
				err = json.Unmarshal(raw, &disclosure)
			}
			if err != nil || len(disclosure) != 3 {
				t.Fatalf("disclosure %q: %v", d, err)
			}
			names = append(names, fmt.Sprint(disclosure[1]))
		}
	} else {
		raw, err := base64.RawURLEncoding.DecodeString(credential)
		if err != nil {
			t.Fatal(err)
		}
		signed, err := mdoc.UnmarshalIssuerSigned(raw)
		if err != nil {
			t.Fatal(err)
		}
		for _, items := range signed.NameSpaces {
			for _, item := range items {
				names = append(names, item.ElementIdentifier)
			}
		}
	}
	slices.Sort(names)
	return names
}
