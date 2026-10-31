package verifier_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/verifier"
)

// FuzzTransactionCodecUnmarshal reads arbitrary records with
// TransactionCodec, sealed and unsealed: a store's rows may be damaged
// or written by something else. Unmarshal never panics, and whatever it
// accepts writes back (Marshal) to a record it reads again as the same
// transaction.
func FuzzTransactionCodecUnmarshal(f *testing.F) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		f.Fatal(err)
	}
	sealer, err := verifier.AESGCMSealer(key)
	if err != nil {
		f.Fatal(err)
	}
	plain, sealed := verifier.TransactionCodec{}, verifier.TransactionCodec{Sealer: sealer}
	tx := fuzzSeedTransaction(f)
	for _, codec := range []verifier.TransactionCodec{plain, sealed} {
		row, err := codec.Marshal(tx)
		if err != nil {
			f.Fatalf("Marshal: %v", err)
		}
		f.Add(row)
	}
	pending := tx
	pending.Result, pending.ResponseDecryptionKey, pending.Status = nil, nil, verifier.TransactionPending
	row, err := plain.Marshal(pending)
	if err != nil {
		f.Fatalf("Marshal: %v", err)
	}
	f.Add(row)
	f.Add([]byte(`{"v":1,"id":"x","query":{},"status":1,"expires_at":"2026-10-01T00:00:00+02:00","retain_until":"0001-01-01T00:00:00Z"}`))
	f.Add([]byte(`{"v":1,"id":"x","query":{"credentials":[{"id":"m","format":"mso_mdoc"}]},"status":2,` +
		`"expires_at":"2026-10-01T00:00:00Z","retain_until":"2026-10-01T00:00:00Z",` +
		`"result":{"credentials":[{"credential_query_id":"m","mdoc_claims":"oWFhoWFi+X4A","mdoc_status":"oA=="}]}}`))
	f.Add([]byte(`{"v":1,"id":"x","sealed":true,"status":1}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, codec := range []verifier.TransactionCodec{plain, sealed} {
			tx, err := codec.Unmarshal(data)
			if err != nil {
				continue
			}
			row, err := codec.Marshal(tx)
			if err != nil {
				t.Fatalf("Unmarshal accepted %q, which Marshal can't write: %v", data, err)
			}
			again, err := codec.Unmarshal(row)
			if err != nil {
				t.Fatalf("Unmarshal refused %q, which Marshal wrote for %q: %v", row, data, err)
			}
			if a, b := canonicalTransaction(t, tx), canonicalTransaction(t, again); !bytes.Equal(a, b) {
				t.Fatalf("a transaction read from %q came back from its own record as another:\n%s\n%s", data, a, b)
			}
		}
	})
}

// fuzzSeedTransaction is a completed transaction with an SD-JWT VC's
// claims and an mdoc's, its status reference included.
func fuzzSeedTransaction(f *testing.F) verifier.Transaction {
	responseKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	expires := time.Date(2026, 10, 1, 12, 0, 0, 5, time.FixedZone("", 2*3600))
	return verifier.Transaction{
		ID: "tx-1", KeyID: "kid-1", State: "state", Nonce: "nonce", RequestObject: "a.b.c", Owner: "owner",
		Query: dcql.Query{Credentials: []dcql.CredentialQuery{
			{ID: "sd", Format: sdjwtvc.CredentialFormat, Claims: []dcql.ClaimsQuery{{Path: dcql.Path{dcql.PathKey("given_name"), dcql.PathIndex(0), dcql.Wildcard}}}},
			{ID: "m", Format: mdoc.CredentialFormat},
		}},
		ResponseDecryptionKey: responseKey, BrowserBindingHash: []byte{1, 2, 3}, SameDevice: true,
		ExpiresAt: expires, RetainUntil: expires.Add(time.Hour), Status: verifier.TransactionDone,
		ResponseCodeHash: "hash", LastError: "earlier refusal",
		Result: &verifier.VerifyResponseResult{
			Credentials: []verifier.VerifiedCredential{
				{CredentialQueryID: "sd", Claims: map[string]any{"given_name": "Jean", "age": 42.5, "nested": map[string]any{"a": []any{true, nil}}}},
				{
					CredentialQueryID: "m",
					Claims: map[string]any{"org.iso.18013.5.1": map[string]any{
						"given_name": "Alice", "age_over_18": true, "portrait": []byte{0xff, 0xd8},
						"birth_date": cbor.Tag{Number: 1004, Content: "1990-01-01"}, "issue_date": expires,
					}},
					MdocStatus:  &mdoc.Status{StatusList: &mdoc.StatusListRef{Idx: 7, URI: "https://status.example/1"}},
					IssuerChain: [][]byte{{0x30, 0x00}},
				},
			},
			Discarded: []verifier.DiscardedPresentation{{CredentialQueryID: "sd", Reason: "unrequested claims"}},
		},
	}
}

// canonicalCBOR re-encodes CBOR deterministically, so two encodings of
// one mdoc's claims (its maps in any order) compare equal as bytes.
var canonicalCBOR = func() cbor.EncMode {
	mode, err := cbor.EncOptions{Sort: cbor.SortCoreDeterministic, Time: cbor.TimeRFC3339Nano, TimeTag: cbor.EncTagRequired}.EncMode()
	if err != nil {
		panic(err)
	}
	return mode
}()

// canonicalTransaction is tx as an unsealed record, with each mdoc's
// claims and status re-encoded deterministically: equal for two
// transactions holding the same values.
func canonicalTransaction(t *testing.T, tx verifier.Transaction) []byte {
	t.Helper()
	row, err := verifier.TransactionCodec{}.Marshal(tx)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var record map[string]json.RawMessage
	if err := json.Unmarshal(row, &record); err != nil {
		t.Fatalf("a record isn't JSON: %v", err)
	}
	if raw, ok := record["result"]; ok {
		var result struct {
			Credentials []map[string]json.RawMessage `json:"credentials"`
			Discarded   json.RawMessage              `json:"discarded,omitempty"`
		}
		if err := json.Unmarshal(raw, &result); err != nil {
			t.Fatalf("a record's result isn't JSON: %v", err)
		}
		for _, cred := range result.Credentials {
			for _, field := range []string{"mdoc_claims", "mdoc_status"} {
				if encoded, ok := cred[field]; ok {
					cred[field] = canonicalField(t, encoded)
				}
			}
		}
		if record["result"], err = json.Marshal(result); err != nil {
			t.Fatal(err)
		}
	}
	out, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// canonicalField is a record's base64 CBOR field, re-encoded
// deterministically.
func canonicalField(t *testing.T, encoded json.RawMessage) json.RawMessage {
	t.Helper()
	var data []byte
	if err := json.Unmarshal(encoded, &data); err != nil {
		t.Fatalf("a record's CBOR field isn't base64: %v", err)
	}
	var v any
	if err := cbor.Unmarshal(data, &v); err != nil {
		t.Fatalf("a record's CBOR field %x doesn't decode: %v", data, err)
	}
	canonical, err := canonicalCBOR.Marshal(v)
	if err != nil {
		t.Fatalf("re-encode %x: %v", data, err)
	}
	out, err := json.Marshal(canonical)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
