package statuslist

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/cose"
)

// A list whose compressed stream is cut short, or whose checksum is
// wrong, is refused, even at an index whose byte inflated before the
// damage: it isn't a valid list (draft-14 §8.3 step 5). An intact list
// still answers, and an index past its end is out of bounds.
func TestStatus_RefusesTruncatedOrCorruptList(t *testing.T) {
	statuses := make([]uint8, 4096)
	for i := range statuses {
		statuses[i] = uint8(i % 2)
	}
	sl, err := New(Bits1, statuses, "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(sl.Lst)
	if err != nil {
		t.Fatal(err)
	}
	with := func(b []byte) StatusList {
		out := sl
		out.Lst = base64.RawURLEncoding.EncodeToString(b)
		return out
	}

	if got, err := sl.Status(1); err != nil || got != 1 {
		t.Fatalf("intact list: Status(1) = %d, %v; want 1", got, err)
	}
	if _, err := sl.Status(len(statuses) + 8); err == nil || !strings.Contains(err.Error(), "out of bounds") {
		t.Errorf("intact list, past its end: %v, want out of bounds", err)
	}

	corrupt := append([]byte{}, raw...)
	corrupt[len(corrupt)-1] ^= 0xff // the Adler-32 checksum's last byte
	for name, list := range map[string]StatusList{
		"checksum missing":   with(raw[:len(raw)-4]),
		"checksum cut short": with(raw[:len(raw)-2]),
		"deflate cut short":  with(raw[:len(raw)/2]),
		"checksum wrong":     with(corrupt),
	} {
		if _, err := list.Status(1); err == nil {
			t.Errorf("%s: Status(1) answered from an incomplete list", name)
		}
	}
}

// lst is DEFLATE in the ZLIB data format (draft-14 §4.1 step 4): the
// same list as raw DEFLATE, without the ZLIB header and checksum, is
// refused by Decode and Status, and in a signed CWT Status List Token.
func TestStatusList_RefusesRawDeflate(t *testing.T) {
	statuses := []uint8{0, 1, 0, 1}
	sl, err := New(Bits1, statuses, "")
	if err != nil {
		t.Fatal(err)
	}
	packed, err := Pack(Bits1, statuses)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.BestCompression)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(packed); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	raw := StatusList{Bits: Bits1, Lst: base64.RawURLEncoding.EncodeToString(buf.Bytes())}

	if _, err := raw.Decode(); err == nil || !strings.Contains(err.Error(), "zlib") {
		t.Errorf("Decode = %v, want the zlib stream refused", err)
	}
	if _, err := raw.Status(1); err == nil || !strings.Contains(err.Error(), "zlib") {
		t.Errorf("Status(1) = %v, want the zlib stream refused", err)
	}

	key := testKey(t)
	const uri = "https://example.com/statuslists/1"
	for name, tc := range map[string]struct {
		list StatusList
		ok   bool
	}{"zlib": {sl, true}, "raw DEFLATE": {raw, false}} {
		token, err := IssueTokenCWT(key, cose.ES256, TokenClaims{Sub: uri, Iat: time.Now().Unix(), StatusList: tc.list}, nil)
		if err != nil {
			t.Fatalf("%s: IssueTokenCWT: %v", name, err)
		}
		status, _, err := CheckCWT(token, &key.PublicKey, cose.ES256, StatusListRef{Idx: 1, URI: uri}, VerifyOptions{UnboundSigner: AnyListSigner})
		if tc.ok && (err != nil || status != StatusInvalid) {
			t.Errorf("%s: CheckCWT = %v, %v; want INVALID", name, status, err)
		}
		if !tc.ok && (err == nil || !strings.Contains(err.Error(), "zlib")) {
			t.Errorf("%s: CheckCWT = %v, %v; want the zlib stream refused", name, status, err)
		}
	}
}
