package verifiertest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/verifier"
)

// testTxStoreCreateKeepsEveryField: a created transaction with every
// field set comes back from Get as it was saved.
func testTxStoreCreateKeepsEveryField(t *testing.T, store verifier.TransactionStore) {
	ctx := context.Background()
	want := populatedTransaction(t, "tx-1")
	mustCreate(t, store, want)
	got, err := store.Get(ctx, want.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if lost := differingFields(want, got); len(lost) > 0 {
		t.Errorf("Get after Create changed %v: a store must keep every Transaction field as it was saved", lost)
	}
}

// testTxStoreUpdateKeepsEveryField: an Update that sets every field
// saves each as it was set, and indexes the new response_code.
func testTxStoreUpdateKeepsEveryField(t *testing.T, store verifier.TransactionStore) {
	ctx := context.Background()
	want := populatedTransaction(t, "tx-1")
	created := contractTransaction(want.ID)
	created.KeyID = want.KeyID
	mustCreate(t, store, created)
	if err := store.Update(ctx, want.ID, func(cur *verifier.Transaction) error {
		*cur = want
		return nil
	}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	got, err := store.Get(ctx, want.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if lost := differingFields(want, got); len(lost) > 0 {
		t.Errorf("Get after Update changed %v: a store must keep every Transaction field as it was saved", lost)
	}
	if id, err := store.IDByResponseCode(ctx, want.ResponseCodeHash); err != nil || id != want.ID {
		t.Errorf("IDByResponseCode = %q, %v; want %q", id, err, want.ID)
	}
}

// populatedTransaction is a transaction with id and every field set —
// a same-device one, awaiting its redirect, with an SD-JWT VC's and an
// mdoc's claims in its result, each in the types its format decodes to
// — so a store that drops or changes any of them shows. It fails t if
// Transaction has a field it leaves unset: a field added to Transaction
// is added here too, so the contract keeps checking every one.
func populatedTransaction(t *testing.T, id string) verifier.Transaction {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	required := true
	expires := time.Now().UTC().Truncate(time.Second).Add(time.Hour)
	tx := verifier.Transaction{
		ID: id, KeyID: "kid-" + id, State: id + ".state", Nonce: "nonce-" + id,
		Query: dcql.Query{
			Credentials: []dcql.CredentialQuery{{
				ID: "pid", Format: sdjwtvc.CredentialFormat, Meta: json.RawMessage(`{"vct_values":["urn:example:pid"]}`),
				Claims: []dcql.ClaimsQuery{
					{ID: "name", Path: dcql.Path{dcql.PathKey("given_name")}, Values: []any{"Jean"}, IntentToRetain: &required},
					{ID: "nat", Path: dcql.Path{dcql.PathKey("nationalities"), dcql.Wildcard}},
				},
				ClaimSets:                         [][]string{{"name", "nat"}, {"name"}},
				RequireCryptographicHolderBinding: &required,
				TrustedAuthorities:                []dcql.TrustedAuthoritiesQuery{{Type: dcql.TrustedAuthorityAKI, Values: []string{"s9tIpPmhxdiuNkHMEWNpYim8S8Y"}}},
			}, {
				ID: "mdl", Format: mdoc.CredentialFormat, Meta: json.RawMessage(`{"doctype_value":"org.iso.18013.5.1.mDL"}`),
				Claims: []dcql.ClaimsQuery{{Path: dcql.Path{dcql.PathKey("org.iso.18013.5.1"), dcql.PathKey("age_in_years")}}},
			}},
			CredentialSets: []dcql.CredentialSetQuery{{Options: [][]string{{"pid"}, {"mdl"}}, Required: &required}},
		},
		ResponseDecryptionKey: key, RequestObject: "request-object-" + id, Origin: "https://verifier.example.com",
		Owner: "owner-" + id, BrowserBindingHash: []byte("binding-hash-" + id), SameDevice: true,
		ExpiresAt: expires, RetainUntil: expires.Add(time.Hour), Status: verifier.TransactionAwaitingRedirect,
		ResponseCodeHash: "code-hash-" + id, LastError: "the answer was refused",
		Result: &verifier.VerifyResponseResult{
			Credentials: []verifier.VerifiedCredential{{
				CredentialQueryID: "pid",
				Claims: map[string]any{
					"vct": "urn:example:pid", "given_name": "Jean", "age": float64(42), "over_18": true, "middle_name": nil,
					"nationalities": []any{"FR", "DE"}, "address": map[string]any{"country": "FR", "number": float64(1.5)},
					"status": map[string]any{"status_list": map[string]any{"idx": float64(3), "uri": "https://issuer.example.com/sl"}},
				},
				IssuerChain: [][]byte{[]byte("leaf"), []byte("intermediate")},
			}, {
				CredentialQueryID: "mdl",
				Claims: map[string]any{"org.iso.18013.5.1": map[string]any{
					"age_in_years": uint64(42), "offset": int64(-1), "portrait": []byte{0xff, 0xd8}, "given_name": "Alice",
					"driving_privileges": []any{map[any]any{"vehicle_category_code": "B"}},
				}},
				MdocStatus:  &mdoc.Status{StatusList: &mdoc.StatusListRef{Idx: 7, URI: "https://issuer.example.com/sl"}},
				IssuerChain: [][]byte{[]byte("document-signer")},
			}},
			Discarded: []verifier.DiscardedPresentation{{CredentialQueryID: "pid", Reason: "holder binding failed"}},
		},
	}
	v := reflect.ValueOf(tx)
	for i := range v.NumField() {
		if v.Field(i).IsZero() {
			t.Fatalf("verifiertest: populatedTransaction leaves Transaction.%s unset: set it, so the contract checks a store keeps it", v.Type().Field(i).Name)
		}
	}
	return tx
}

// differingFields names the fields of got that aren't as in want: times
// compared as instants, the key by its value, the rest deeply.
func differingFields(want, got verifier.Transaction) []string {
	var differ []string
	w, g := reflect.ValueOf(want), reflect.ValueOf(got)
	for i := range w.NumField() {
		var same bool
		switch a := w.Field(i).Interface().(type) {
		case time.Time:
			same = a.Equal(g.Field(i).Interface().(time.Time))
		case *ecdsa.PrivateKey:
			b := g.Field(i).Interface().(*ecdsa.PrivateKey)
			same = b != nil && a.Equal(b)
		default:
			same = reflect.DeepEqual(a, g.Field(i).Interface())
		}
		if !same {
			differ = append(differ, w.Type().Field(i).Name)
		}
	}
	return differ
}
