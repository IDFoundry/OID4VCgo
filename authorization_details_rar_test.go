package oid4vci_test

import (
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"testing"

	"github.com/idfoundry/fapigo/extension"

	oid4vci "github.com/idfoundry/oid4vcgo"
)

func credentialRARRegistry(t *testing.T) *extension.RARRegistry {
	t.Helper()
	registry, err := extension.NewRARRegistry(8<<10, 6, oid4vci.AuthorizationDetailRARDefinition(2, 4<<10))
	if err != nil {
		t.Fatal(err)
	}
	return registry
}

// A client starting a grant may not choose credential_identifiers
// (OpenID4VCI 1.0 §6.2): they're the Authorization Server's to mint.
// The same object granted by the server is accepted.
func TestAuthorizationDetailRARDefinition_RefusesClientCredentialIdentifiers(t *testing.T) {
	registry := credentialRARRegistry(t)
	withIDs := json.RawMessage(`[{"type":"openid_credential","credential_configuration_id":"pid","credential_identifiers":["victim-dataset"]}]`)
	if _, err := registry.ParseRequest(withIDs); !errors.Is(err, oid4vci.ErrClientCredentialIdentifiers) {
		t.Fatalf("ParseRequest = %v, want ErrClientCredentialIdentifiers", err)
	}
	if _, err := registry.Parse(withIDs); err != nil {
		t.Fatalf("Parse of a granted object with identifiers: %v", err)
	}
	if _, err := registry.ParseRequest(json.RawMessage(`[{"type":"openid_credential","credential_configuration_id":"pid"}]`)); err != nil {
		t.Fatalf("ParseRequest without identifiers: %v", err)
	}
	if _, err := registry.ParseRequest(json.RawMessage(`[{"type":"openid_credential","credential_configuration_id":"pid",` +
		`"claims":[{"path":["nationalities",null]},{"path":["nationalities",0]}]}]`)); err != nil {
		t.Fatalf("ParseRequest with null and index path elements: %v", err)
	}
	for name, raw := range map[string]string{
		"no configuration":     `[{"type":"openid_credential"}]`,
		"an empty identifier":  `[{"type":"openid_credential","credential_configuration_id":"pid","credential_identifiers":[""]}]`,
		"an identifier twice":  `[{"type":"openid_credential","credential_configuration_id":"pid","credential_identifiers":["a","a"]}]`,
		"a member not defined": `[{"type":"openid_credential","credential_configuration_id":"pid","dataset":"x"}]`,
		"no identifiers":       `[{"type":"openid_credential","credential_configuration_id":"pid","credential_identifiers":[]}]`,
		"no locations":         `[{"type":"openid_credential","credential_configuration_id":"pid","locations":[]}]`,
		"an empty location":    `[{"type":"openid_credential","credential_configuration_id":"pid","locations":[""]}]`,
		"no claims":            `[{"type":"openid_credential","credential_configuration_id":"pid","claims":[]}]`,
		"an empty path":        `[{"type":"openid_credential","credential_configuration_id":"pid","claims":[{"path":[]}]}]`,
		"a negative index":     `[{"type":"openid_credential","credential_configuration_id":"pid","claims":[{"path":["a",-1]}]}]`,
		"a fractional index":   `[{"type":"openid_credential","credential_configuration_id":"pid","claims":[{"path":["a",1.5]}]}]`,
		"an object in a path":  `[{"type":"openid_credential","credential_configuration_id":"pid","claims":[{"path":[{"a":1}]}]}]`,
		"a path twice": `[{"type":"openid_credential","credential_configuration_id":"pid",` +
			`"claims":[{"path":["given_name"]},{"path":["given_name"],"mandatory":true}]}]`,
	} {
		if _, err := registry.Parse(json.RawMessage(raw)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// parseCredentialDetails parses raw with registry, failing t.
func parseCredentialDetails(t *testing.T, registry *extension.RARRegistry, raw string) extension.RARValues {
	t.Helper()
	v, err := registry.Parse(json.RawMessage(raw))
	if err != nil {
		t.Fatalf("Parse(%s): %v", raw, err)
	}
	return v
}

// A grant may add credential_identifiers to what was requested, and
// otherwise only narrow it: it keeps some of the requested locations
// and claims, never none of them, since an object without them is good
// at any Credential Issuer and for every claim.
func TestAuthorizationDetailRARDefinition_ValidateGrant(t *testing.T) {
	registry := credentialRARRegistry(t)
	parse := func(raw string) extension.RARValues { t.Helper(); return parseCredentialDetails(t, registry, raw) }
	requested := `[{"type":"openid_credential","credential_configuration_id":"pid","locations":["https://issuer.example"],` +
		`"claims":[{"path":["given_name"]},{"path":["family_name"]}]}]`
	minted := `[{"type":"openid_credential","credential_configuration_id":"pid","credential_identifiers":["a","b"],` +
		`"locations":["https://issuer.example"],"claims":[{"path":["given_name"]},{"path":["family_name"]}]}]`
	for name, tc := range map[string]struct {
		requested, granted string
		ok                 bool
	}{
		"identifiers added": {requested, minted, true},
		"claims narrowed": {requested, `[{"type":"openid_credential","credential_configuration_id":"pid","credential_identifiers":["a"],` +
			`"locations":["https://issuer.example"],"claims":[{"path":["given_name"]}]}]`, true},
		"identifiers narrowed": {minted, `[{"type":"openid_credential","credential_configuration_id":"pid",` +
			`"credential_identifiers":["b"],"locations":["https://issuer.example"],"claims":[{"path":["given_name"]}]}]`, true},
		"another configuration": {requested, `[{"type":"openid_credential","credential_configuration_id":"mdl"}]`, false},
		"another location": {requested, `[{"type":"openid_credential","credential_configuration_id":"pid",` +
			`"locations":["https://other.example"],"claims":[{"path":["given_name"]}]}]`, false},
		"another claim": {requested, `[{"type":"openid_credential","credential_configuration_id":"pid",` +
			`"locations":["https://issuer.example"],"claims":[{"path":["birth_date"]}]}]`, false},
		"claims where none were requested": {`[{"type":"openid_credential","credential_configuration_id":"pid"}]`,
			`[{"type":"openid_credential","credential_configuration_id":"pid","claims":[{"path":["given_name"]}]}]`, false},
		"locations dropped": {requested, `[{"type":"openid_credential","credential_configuration_id":"pid",` +
			`"claims":[{"path":["given_name"]}]}]`, false},
		"claims dropped": {requested, `[{"type":"openid_credential","credential_configuration_id":"pid",` +
			`"locations":["https://issuer.example"]}]`, false},
		"locations kept in part": {`[{"type":"openid_credential","credential_configuration_id":"pid",` +
			`"locations":["https://issuer.example","https://other.example"]}]`,
			`[{"type":"openid_credential","credential_configuration_id":"pid","locations":["https://other.example"]}]`, true},
		"no locations or claims": {`[{"type":"openid_credential","credential_configuration_id":"pid"}]`,
			`[{"type":"openid_credential","credential_configuration_id":"pid","credential_identifiers":["a"]}]`, true},
		"an identifier the grant doesn't hold": {minted, `[{"type":"openid_credential","credential_configuration_id":"pid",` +
			`"credential_identifiers":["victim-dataset"]}]`, false},
	} {
		err := registry.ValidateGrant(parse(tc.requested), parse(tc.granted))
		if (err == nil) != tc.ok {
			t.Errorf("%s: ValidateGrant = %v, want ok %v", name, err, tc.ok)
		}
	}
}

// A token request narrowing its grant (S-31) keeps some of the grant's
// credential_identifiers, locations and claims, never none of them, and
// may add neither an identifier nor any member the grant lacks — even
// where the grant holds no identifiers, which consent may add to.
// Dropping the identifiers would let the Wallet ask for the
// configuration by credential_configuration_id, for any dataset.
func TestAuthorizationDetailRARDefinition_ValidateNarrowing(t *testing.T) {
	registry := credentialRARRegistry(t)
	const (
		bare   = `[{"type":"openid_credential","credential_configuration_id":"pid"}]`
		minted = `[{"type":"openid_credential","credential_configuration_id":"pid","credential_identifiers":["a","b"],` +
			`"locations":["https://issuer.example"],"claims":[{"path":["given_name"]},{"path":["family_name"]}]}]`
	)
	for name, tc := range map[string]struct {
		granted, narrowed string
		ok                bool
	}{
		"unchanged":      {minted, minted, true},
		"bare unchanged": {bare, bare, true},
		"identifiers kept in part": {minted, `[{"type":"openid_credential","credential_configuration_id":"pid","credential_identifiers":["b"],` +
			`"locations":["https://issuer.example"],"claims":[{"path":["given_name"]},{"path":["family_name"]}]}]`, true},
		"identifiers dropped": {minted, `[{"type":"openid_credential","credential_configuration_id":"pid",` +
			`"locations":["https://issuer.example"],"claims":[{"path":["given_name"]}]}]`, false},
		"identifiers added to a bare": {bare, `[{"type":"openid_credential","credential_configuration_id":"pid","credential_identifiers":["victim-dataset"]}]`, false},
		"an identifier the grant doesn't hold": {minted, `[{"type":"openid_credential","credential_configuration_id":"pid",` +
			`"credential_identifiers":["a","victim-dataset"]}]`, false},
		"claims added to a bare":    {bare, `[{"type":"openid_credential","credential_configuration_id":"pid","claims":[{"path":["given_name"]}]}]`, false},
		"locations added to a bare": {bare, `[{"type":"openid_credential","credential_configuration_id":"pid","locations":["https://issuer.example"]}]`, false},
		"another claim": {minted, `[{"type":"openid_credential","credential_configuration_id":"pid",` +
			`"locations":["https://issuer.example"],"claims":[{"path":["birth_date"]}]}]`, false},
		"another configuration": {minted, `[{"type":"openid_credential","credential_configuration_id":"mdl"}]`, false},
		"locations dropped": {minted, `[{"type":"openid_credential","credential_configuration_id":"pid","credential_identifiers":["a"],` +
			`"claims":[{"path":["given_name"]}]}]`, false},
		"claims dropped": {minted, `[{"type":"openid_credential","credential_configuration_id":"pid","credential_identifiers":["a"],` +
			`"locations":["https://issuer.example"]}]`, false},
		"locations kept in part": {`[{"type":"openid_credential","credential_configuration_id":"pid",` +
			`"locations":["https://issuer.example","https://other.example"]}]`,
			`[{"type":"openid_credential","credential_configuration_id":"pid","locations":["https://other.example"]}]`, true},
		"another location": {minted, `[{"type":"openid_credential","credential_configuration_id":"pid",` +
			`"locations":["https://other.example"],"claims":[{"path":["given_name"]}]}]`, false},
	} {
		err := registry.ValidateNarrowing(parseCredentialDetails(t, registry, tc.granted), parseCredentialDetails(t, registry, tc.narrowed))
		if (err == nil) != tc.ok {
			t.Errorf("%s: ValidateNarrowing = %v, want ok %v", name, err, tc.ok)
		}
	}
}

// credentialClaims are n distinct claims descriptions.
func credentialClaims(n int) []oid4vci.ClaimsDescription {
	claims := make([]oid4vci.ClaimsDescription, n)
	for i := range claims {
		claims[i] = oid4vci.ClaimsDescription{Path: []any{"claim_" + strconv.Itoa(i)}}
	}
	return claims
}

// One object carries at most MaxAuthorizationDetailClaims claims,
// whatever size the registry allows it; a registry 5 deep takes them.
func TestAuthorizationDetailRARDefinition_ClaimsCap(t *testing.T) {
	registry, err := extension.NewRARRegistry(64<<10, 5, oid4vci.AuthorizationDetailRARDefinition(1, 64<<10))
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{1, oid4vci.MaxAuthorizationDetailClaims, oid4vci.MaxAuthorizationDetailClaims + 1} {
		raw, err := json.Marshal([]oid4vci.AuthorizationDetail{{
			Type: oid4vci.AuthorizationDetailsTypeOpenIDCredential, CredentialConfigurationID: "pid", Claims: credentialClaims(n),
		}})
		if err != nil {
			t.Fatal(err)
		}
		_, err = registry.ParseRequest(raw)
		if ok := n <= oid4vci.MaxAuthorizationDetailClaims; (err == nil) != ok {
			t.Errorf("%d claims: ParseRequest = %v, want ok %v", n, err, ok)
		}
	}
}

// Checking a token request's narrowing of its grant, which a Wallet can
// repeat at every refresh (RFC 9396 §6.1), takes work linear in the
// claims, counted by allocations: the scan it replaces, a
// reflect.DeepEqual per pair of claims, allocated for each pair.
func TestAuthorizationDetailRARDefinition_ValidateNarrowingIsLinear(t *testing.T) {
	def := oid4vci.AuthorizationDetailRARDefinition(1, 64<<10)
	n := oid4vci.MaxAuthorizationDetailClaims
	granted := oid4vci.AuthorizationDetail{
		Type: oid4vci.AuthorizationDetailsTypeOpenIDCredential, CredentialConfigurationID: "pid",
		CredentialIdentifiers: []string{"a"}, Claims: credentialClaims(n),
	}
	reversed := granted
	reversed.Claims = slices.Clone(granted.Claims)
	slices.Reverse(reversed.Claims)
	refused := reversed
	refused.Claims = slices.Clone(reversed.Claims)
	refused.Claims[n-1] = oid4vci.ClaimsDescription{Path: []any{"not_granted"}}
	if err := def.ValidateNarrowing(granted, reversed); err != nil {
		t.Fatalf("ValidateNarrowing to the same claims reversed: %v", err)
	}
	if err := def.ValidateNarrowing(granted, refused); err == nil {
		t.Fatal("ValidateNarrowing accepted a claim the grant doesn't hold")
	}
	for name, narrowed := range map[string]oid4vci.AuthorizationDetail{"accepted": reversed, "refused": refused} {
		if allocs := testing.AllocsPerRun(3, func() { _ = def.ValidateNarrowing(granted, narrowed) }); allocs > float64(4*n) {
			t.Errorf("%s: ValidateNarrowing of %d claims made %.0f allocations, more than %d", name, n, allocs, 4*n)
		}
	}
}
