package wallet_test

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// withClaims sets an unsigned request's query to one SD-JWT VC
// credential query asking for paths, one claims query each.
func withClaims(paths []string) func(map[string]any) {
	return func(c map[string]any) {
		claims := make([]any, len(paths))
		for i, p := range paths {
			claims[i] = map[string]any{"path": []any{p}}
		}
		c["dcql_query"] = map[string]any{"credentials": []any{map[string]any{
			"id": "q", "format": "dc+sd-jwt", "meta": map[string]any{"vct_values": []any{"urn:x"}}, "claims": claims,
		}}}
	}
}

func repeatPath(path string, n int) []string {
	paths := make([]string, n)
	for i := range paths {
		paths[i] = path
	}
	return paths
}

// An unsigned DC API request is anyone's to send, up to
// MaxDCAPIRequestBytes: its claims queries are counted, duplicates
// included, before any are de-duplicated, so a request too big to
// answer costs only its own size to refuse.
func TestParseDCAPIRequestData_BoundsClaimsBeforeDeduplicating(t *testing.T) {
	f := newDCAPIForms(t)
	parse := func(paths []string) (wallet.AuthorizationRequest, error) {
		return wallet.ParseDCAPIRequestData(wallet.ParseDCAPIRequestDataParams{
			Protocol: wallet.DCAPIProtocolUnsigned, Data: f.unsigned(t, withClaims(paths)), Origin: testDCAPIOrigin,
		})
	}
	refused := func(name string, paths []string) {
		t.Helper()
		_, err := parse(paths)
		var rejected *wallet.RequestRejectedError
		if !errors.As(err, &rejected) || !strings.Contains(err.Error(), "claims, more than "+strconv.Itoa(dcql.MaxClaimsPerCredential)) {
			t.Errorf("%s: err = %v, want the query refused for its claims count", name, err)
		}
	}
	// One claims query repeated: one once de-duplicated, but refused for
	// its count first.
	refused("one claim repeated", repeatPath("a", dcql.MaxClaimsPerCredential+1))
	// The attack's shape, smaller: many distinct claims queries.
	distinct := make([]string, 16*dcql.MaxClaimsPerCredential)
	for i := range distinct {
		distinct[i] = strconv.FormatInt(int64(i), 36)
	}
	refused("many distinct claims", distinct)

	// Within the bound, duplicates are still dropped (OpenID4VP 1.0
	// §6.1), keeping the first of each in order.
	paths := append(repeatPath("a", dcql.MaxClaimsPerCredential-2), "b", "a")
	req, err := parse(paths)
	if err != nil {
		t.Fatalf("duplicates within the bound: %v", err)
	}
	got := req.Query.Credentials[0].Claims
	if len(got) != 2 || got[0].Path[0].Key() != "a" || got[1].Path[0].Key() != "b" {
		t.Errorf("de-duplicated claims = %v, want paths a then b", got)
	}
}

// withMeta sets an unsigned request's query to one credential query of
// format whose meta is meta.
func withMeta(format string, meta map[string]any) func(map[string]any) {
	return func(c map[string]any) {
		claims := []any{map[string]any{"path": []any{"a"}}}
		if format == "mso_mdoc" {
			claims = []any{map[string]any{"path": []any{"ns", "e"}}}
		}
		c["dcql_query"] = map[string]any{"credentials": []any{map[string]any{"id": "q", "format": format, "meta": meta, "claims": claims}}}
	}
}

// A credential query's meta is read for every held credential of its
// format, so its size is bounded, and only the members its format
// defines are kept: the members a Wallet ignores are read once, when
// the request is parsed, however many credentials it holds.
func TestParseDCAPIRequestData_BoundsMeta(t *testing.T) {
	f := newDCAPIForms(t)
	parse := func(format string, meta map[string]any) (wallet.AuthorizationRequest, error) {
		return wallet.ParseDCAPIRequestData(wallet.ParseDCAPIRequestDataParams{
			Protocol: wallet.DCAPIProtocolUnsigned, Data: f.unsigned(t, withMeta(format, meta)), Origin: testDCAPIOrigin,
		})
	}
	_, err := parse("dc+sd-jwt", map[string]any{"vct_values": []any{"urn:x"}, "x": strings.Repeat("a", dcql.MaxMetaBytes)})
	var rejected *wallet.RequestRejectedError
	if !errors.As(err, &rejected) || !strings.Contains(err.Error(), "more than "+strconv.Itoa(dcql.MaxMetaBytes)) {
		t.Errorf("a meta past the bound: err = %v, want the query refused for its meta's size", err)
	}

	pad := strings.Repeat("a", dcql.MaxMetaBytes-128)
	for format, tc := range map[string]struct {
		meta map[string]any
		want string
	}{
		"dc+sd-jwt": {meta: map[string]any{"vct_values": []any{"urn:x", "urn:y"}, "x": pad}, want: `{"vct_values":["urn:x","urn:y"]}`},
		"mso_mdoc":  {meta: map[string]any{"doctype_value": "org.iso.18013.5.1.mDL", "x": pad}, want: `{"doctype_value":"org.iso.18013.5.1.mDL"}`},
	} {
		req, err := parse(format, tc.meta)
		if err != nil {
			t.Errorf("%s, a meta within the bound: %v", format, err)
			continue
		}
		if got := string(req.Query.Credentials[0].Meta); got != tc.want {
			t.Errorf("%s: meta = %.80s, want %s", format, got, tc.want)
		}
	}
}

// Only a claims query equal to an earlier one in every member is
// dropped: path elements of each kind, values (1 and 1.0 are one JSON
// number) and intent_to_retain all count.
func TestParseDCAPIRequestData_DedupComparesWholeQueries(t *testing.T) {
	f := newDCAPIForms(t)
	data := []byte(`{"response_type":"vp_token","response_mode":"dc_api.jwt","nonce":"n-0123456789",` +
		`"client_metadata":` + string(mustJSON(t, f.claims["client_metadata"])) + `,"dcql_query":{"credentials":[` +
		`{"id":"q","format":"dc+sd-jwt","meta":{"vct_values":["urn:x"]},"claims":[` +
		`{"path":["a",0]},{"path":["a",0]},` +
		`{"path":["b",null]},{"path":["b",null]},` +
		`{"path":["c"],"values":[1,"x",true]},{"path":["c"],"values":[1.0,"x",true]}` +
		`]},` +
		`{"id":"m","format":"mso_mdoc","meta":{"doctype_value":"org.iso.18013.5.1.mDL"},"claims":[` +
		`{"path":["ns","e"],"intent_to_retain":false},{"path":["ns","e"],"intent_to_retain":false}` +
		`]}]}}`)
	req, err := wallet.ParseDCAPIRequestData(wallet.ParseDCAPIRequestDataParams{
		Protocol: wallet.DCAPIProtocolUnsigned, Data: data, Origin: testDCAPIOrigin,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := len(req.Query.Credentials[0].Claims); got != 3 {
		t.Errorf("SD-JWT VC query kept %d claims queries, want 3: %v", got, req.Query.Credentials[0].Claims)
	}
	if got := len(req.Query.Credentials[1].Claims); got != 1 {
		t.Errorf("mdoc query kept %d claims queries, want 1: %v", got, req.Query.Credentials[1].Claims)
	}

	// Differing only in intent_to_retain: not a duplicate, so the two
	// reach Validate, which refuses a repeated path.
	data = []byte(strings.Replace(string(data), `"intent_to_retain":false}]`, `"intent_to_retain":true}]`, 1))
	if _, err := wallet.ParseDCAPIRequestData(wallet.ParseDCAPIRequestDataParams{
		Protocol: wallet.DCAPIProtocolUnsigned, Data: data, Origin: testDCAPIOrigin,
	}); err == nil || !strings.Contains(err.Error(), "same claim") {
		t.Errorf("claims queries differing in intent_to_retain: err = %v, want them kept apart", err)
	}
}

// A done context ends the parse with its error, which isn't an answer
// for the Verifier.
func TestParseDCAPIRequestData_HonoursContext(t *testing.T) {
	f := newDCAPIForms(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for name, params := range map[string]wallet.ParseDCAPIRequestDataParams{
		"unsigned":     {Protocol: wallet.DCAPIProtocolUnsigned, Data: f.unsigned(t, nil)},
		"multi-signed": {Protocol: wallet.DCAPIProtocolMultiSigned, Data: f.multiSigned(t, nil, signer{key: f.key, cert: f.cert}), VerifierTrust: f.trust},
	} {
		params.Origin = testDCAPIOrigin
		_, err := wallet.ParseDCAPIRequestDataContext(ctx, params)
		var rejected *wallet.RequestRejectedError
		if !errors.Is(err, context.Canceled) || errors.As(err, &rejected) {
			t.Errorf("%s: err = %v, want context.Canceled", name, err)
		}
		if _, err := wallet.ParseDCAPIRequestData(params); err != nil {
			t.Errorf("%s, no context: %v", name, err)
		}
	}
}
