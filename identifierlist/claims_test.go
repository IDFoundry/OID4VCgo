package identifierlist

import (
	"bytes"
	"context"
	"runtime"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

func marshalClaims(t testing.TB, claims map[int]any) []byte {
	t.Helper()
	raw, err := encMode.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// TestParseClaims_Refuses: a claims set whose times aren't
// NumericDates, or whose identifiers map isn't ISO/IEC 18013-5
// §12.3.6.4's — a non-empty bstr to an IdentifierInfo map — is refused.
func TestParseClaims_Refuses(t *testing.T) {
	now := time.Now().Unix()
	exp := now + 3600
	ids := func(m any) map[string]any { return map[string]any{"identifiers": m} }
	empty := ids(map[cbor.ByteString]any{})
	for name, tc := range map[string]struct {
		claims map[int]any
		want   string
	}{
		"iat a string":           {map[int]any{cwtClaimSub: testURI, cwtClaimIat: "now", cwtClaimExp: exp, cwtClaimIdentifierList: empty}, "iat claim"},
		"iat negative":           {map[int]any{cwtClaimSub: testURI, cwtClaimIat: -5, cwtClaimExp: exp, cwtClaimIdentifierList: empty}, "iat claim"},
		"exp a map":              {map[int]any{cwtClaimSub: testURI, cwtClaimIat: now, cwtClaimExp: map[string]any{}, cwtClaimIdentifierList: empty}, "exp claim"},
		"nbf a byte string":      {map[int]any{cwtClaimSub: testURI, cwtClaimIat: now, cwtClaimExp: exp, cwtClaimNbf: []byte{1}, cwtClaimIdentifierList: empty}, "nbf claim"},
		"ttl a string":           {map[int]any{cwtClaimSub: testURI, cwtClaimIat: now, cwtClaimExp: exp, cwtClaimTTL: "5", cwtClaimIdentifierList: empty}, "ttl claim"},
		"sub an integer":         {map[int]any{cwtClaimSub: 1, cwtClaimIat: now, cwtClaimExp: exp, cwtClaimIdentifierList: empty}, "missing the required sub"},
		"list an array":          {map[int]any{cwtClaimSub: testURI, cwtClaimIat: now, cwtClaimExp: exp, cwtClaimIdentifierList: []any{1}}, "identifier_list claim"},
		"identifiers null":       {map[int]any{cwtClaimSub: testURI, cwtClaimIat: now, cwtClaimExp: exp, cwtClaimIdentifierList: ids(nil)}, "has no identifiers map"},
		"identifiers an array":   {map[int]any{cwtClaimSub: testURI, cwtClaimIat: now, cwtClaimExp: exp, cwtClaimIdentifierList: ids([]any{})}, "has no identifiers map"},
		"a text identifier":      {map[int]any{cwtClaimSub: testURI, cwtClaimIat: now, cwtClaimExp: exp, cwtClaimIdentifierList: ids(map[string]any{"abc": map[string]any{}})}, "isn't a byte string"},
		"an empty identifier":    {map[int]any{cwtClaimSub: testURI, cwtClaimIat: now, cwtClaimExp: exp, cwtClaimIdentifierList: ids(map[cbor.ByteString]any{"": map[string]any{}})}, "empty identifier"},
		"IdentifierInfo an int":  {map[int]any{cwtClaimSub: testURI, cwtClaimIat: now, cwtClaimExp: exp, cwtClaimIdentifierList: ids(map[cbor.ByteString]any{"\x01": 5})}, "IdentifierInfo isn't a map"},
		"IdentifierInfo a array": {map[int]any{cwtClaimSub: testURI, cwtClaimIat: now, cwtClaimExp: exp, cwtClaimIdentifierList: ids(map[cbor.ByteString]any{"\x01": []int{1}})}, "IdentifierInfo isn't a map"},
	} {
		_, _, err := parseClaims(marshalClaims(t, tc.claims))
		wantErr(t, name, err, tc.want)
	}

	// A text key that isn't an int claim, and a duplicate identifier
	// written by hand.
	for name, raw := range map[string][]byte{
		"a text claim key":       {0xa1, 0x61, 'x', 0x00},
		"a duplicate identifier": dupIdentifier(t, now, exp),
	} {
		if _, _, err := parseClaims(raw); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// dupIdentifier is a claims set listing identifier 0x01 twice.
func dupIdentifier(t *testing.T, iat, exp int64) []byte {
	raw := marshalClaims(t, map[int]any{cwtClaimSub: testURI, cwtClaimIat: iat, cwtClaimExp: exp,
		cwtClaimIdentifierList: map[string]any{"identifiers": map[cbor.ByteString]any{"\x01": map[string]any{}, "\x02": map[string]any{}}}})
	// {h'01': {}, h'02': {}} → {h'01': {}, h'01': {}}
	i := bytes.Index(raw, []byte{0xa2, 0x41, 0x01, 0xa0, 0x41, 0x02, 0xa0})
	if i < 0 {
		t.Fatal("identifiers map not found")
	}
	raw[i+5] = 0x01
	return raw
}

// TestParseClaims_IdentifierShapes: an identifier is read whatever its
// byte string's encoding, an IdentifierInfo may carry entries, and an
// identifier_list's other members are ignored.
func TestParseClaims_IdentifierShapes(t *testing.T) {
	now := time.Now().Unix()
	raw := marshalClaims(t, map[int]any{cwtClaimSub: testURI, cwtClaimIat: now, cwtClaimExp: now + 60,
		cwtClaimIdentifierList: map[string]any{"identifiers": map[cbor.ByteString]any{"\x02": map[string]any{"x": 1}, "\x01": map[string]any{}}, "aggregation_uri": "https://example.com"}})
	claims, _, err := parseClaims(raw)
	if err != nil || len(claims.Identifiers) != 2 || !bytes.Equal(claims.Identifiers[0], []byte{1}) {
		t.Fatalf("parseClaims = %x, %v", claims.Identifiers, err)
	}
	// An identifier aliases the token's bytes, but appending to one
	// doesn't overwrite the next.
	claims.Identifiers[0] = append(claims.Identifiers[0], 0xff)
	if !bytes.Equal(claims.Identifiers[1], []byte{2}) {
		t.Errorf("appending to an identifier changed the next: %x", claims.Identifiers[1])
	}

	// {h'0102' as indefinite-length chunks: {}}
	indefinite := marshalClaims(t, map[int]any{cwtClaimSub: testURI, cwtClaimIat: now, cwtClaimExp: now + 60,
		cwtClaimIdentifierList: map[string]any{"identifiers": map[cbor.ByteString]any{"\x01\x02": map[string]any{}}}})
	i := bytes.Index(indefinite, []byte{0xa1, 0x42, 0x01, 0x02, 0xa0})
	if i < 0 {
		t.Fatal("identifiers map not found")
	}
	indefinite = append(indefinite[:i+1:i+1], append([]byte{0x5f, 0x41, 0x01, 0x41, 0x02, 0xff, 0xa0}, indefinite[i+5:]...)...)
	claims, _, err = parseClaims(indefinite)
	if err != nil || len(claims.Identifiers) != 1 || !bytes.Equal(claims.Identifiers[0], []byte{1, 2}) {
		t.Errorf("indefinite-length identifier: %x, %v", claims.Identifiers, err)
	}
}

// TestVerifyToken_ExpNotAfterIat: a token that expires as it's issued
// was never valid, even while a verifier's clock lags its issuer's.
func TestVerifyToken_ExpNotAfterIat(t *testing.T) {
	pki := newPKI(t)
	now := time.Now()
	iat := now.Add(30 * time.Second).Unix()
	token := signRaw(t, pki, MediaType, map[int]any{cwtClaimSub: testURI, cwtClaimIat: iat, cwtClaimExp: iat,
		cwtClaimIdentifierList: map[string]any{"identifiers": map[cbor.ByteString]any{}}})
	_, err := VerifyToken(context.Background(), token, pki.roots, VerifyOptions{Now: func() time.Time { return now }})
	wantErr(t, "exp at iat", err, "exp isn't after its iat")
}

// largeClaims is a claims set of about DefaultMaxTokenBytes listing n
// identifiers of three bytes each.
func largeClaims(t testing.TB, n int) []byte {
	ids := make(map[cbor.ByteString]any, n)
	for i := range n {
		ids[cbor.ByteString([]byte{byte(i >> 16), byte(i >> 8), byte(i)})] = map[string]any{}
	}
	now := time.Now()
	return marshalClaims(t, map[int]any{cwtClaimSub: testURI, cwtClaimIat: now.Unix(), cwtClaimExp: now.Add(time.Hour).Unix(),
		cwtClaimIdentifierList: map[string]any{"identifiers": ids}})
}

// largeListIdentifiers fills a claims set to just under DefaultMaxTokenBytes.
const largeListIdentifiers = 830_000

// TestParseClaims_LargeListMemory: reading a list near DefaultMaxTokenBytes
// allocates a small multiple of its size — the identifiers' slice
// headers, mostly — not a decoded map of every entry.
func TestParseClaims_LargeListMemory(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a 4 MB list")
	}
	raw := largeClaims(t, largeListIdentifiers)
	if len(raw) > DefaultMaxTokenBytes {
		t.Fatalf("the claims set is %d bytes, over DefaultMaxTokenBytes", len(raw))
	}
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	claims, _, err := parseClaims(raw)
	runtime.ReadMemStats(&after)
	if err != nil || len(claims.Identifiers) != largeListIdentifiers {
		t.Fatalf("parseClaims: %d identifiers, %v", len(claims.Identifiers), err)
	}
	if alloc := after.TotalAlloc - before.TotalAlloc; alloc > 10*uint64(len(raw)) {
		t.Errorf("parseClaims of %d bytes allocated %d bytes, over 10 times its size", len(raw), alloc)
	}
	if mallocs := after.Mallocs - before.Mallocs; mallocs > 1000 {
		t.Errorf("parseClaims of %d identifiers made %d allocations", largeListIdentifiers, mallocs)
	}
}

// BenchmarkParseClaims_MaxTokenBytes reads a list near DefaultMaxTokenBytes,
// as every Check of one does.
func BenchmarkParseClaims_MaxTokenBytes(b *testing.B) {
	raw := largeClaims(b, largeListIdentifiers)
	b.SetBytes(int64(len(raw)))
	b.ReportAllocs()
	for b.Loop() {
		if _, _, err := parseClaims(raw); err != nil {
			b.Fatal(err)
		}
	}
}

// FuzzParseClaims fuzzes the claims decoder directly: FuzzVerifyToken's
// inputs rarely get past the signature to reach it.
func FuzzParseClaims(f *testing.F) {
	now := time.Now()
	f.Add(marshalClaims(f, map[int]any{cwtClaimSub: testURI, cwtClaimIat: now.Unix(), cwtClaimExp: now.Add(time.Hour).Unix(), cwtClaimTTL: 5, cwtClaimNbf: now.Unix(),
		cwtClaimIdentifierList: map[string]any{"identifiers": map[cbor.ByteString]any{"\x01": map[string]any{}, "\x02\x03": map[string]any{"x": 1}}}}))
	f.Add([]byte{0xa0})
	f.Fuzz(func(t *testing.T, raw []byte) {
		claims, _, err := parseClaims(raw)
		if err != nil {
			return
		}
		if claims.Sub == "" || claims.Iat <= 0 {
			t.Fatalf("accepted claims without sub or iat: %+v", claims)
		}
		for i, id := range claims.Identifiers {
			if len(id) == 0 {
				t.Fatal("accepted an empty identifier")
			}
			if i > 0 && bytes.Compare(claims.Identifiers[i-1], id) >= 0 {
				t.Fatalf("identifiers not sorted and distinct: %x", claims.Identifiers)
			}
		}
		// What the list says must be what a plain decode of it says.
		var plain map[int]cbor.RawMessage
		if err := cbor.Unmarshal(raw, &plain); err != nil {
			t.Fatalf("parseClaims accepted what cbor.Unmarshal refuses: %v", err)
		}
		var list struct {
			Identifiers map[cbor.ByteString]cbor.RawMessage `cbor:"identifiers"`
		}
		if err := cbor.Unmarshal(plain[cwtClaimIdentifierList], &list); err != nil {
			t.Fatalf("parseClaims accepted an identifier_list cbor.Unmarshal refuses: %v", err)
		}
		if len(list.Identifiers) != len(claims.Identifiers) {
			t.Fatalf("%d identifiers, a plain decode reads %d", len(claims.Identifiers), len(list.Identifiers))
		}
	})
}
