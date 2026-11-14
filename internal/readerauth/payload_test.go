package readerauth

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// The expected encodings below are assembled byte by byte from RFC
// 8949's head rules, not by the builders' own CBOR encoder.

// cat joins hex fragments.
func cat(t *testing.T, parts ...string) []byte {
	t.Helper()
	var out []byte
	for _, p := range parts {
		b, err := hex.DecodeString(p)
		if err != nil {
			t.Fatalf("bad hex %q: %v", p, err)
		}
		out = append(out, b...)
	}
	return out
}

// tagged wraps inner, shorter than 256 bytes, as #6.24(bstr).
func tagged(t *testing.T, inner []byte) []byte {
	t.Helper()
	if len(inner) > 255 {
		t.Fatal("fixture too long for this helper")
	}
	head := []byte{0xd8, 0x18}
	if len(inner) < 24 {
		head = append(head, 0x40|byte(len(inner)))
	} else {
		head = append(head, 0x58, byte(len(inner)))
	}
	return append(head, inner...)
}

const (
	// transcriptHex is [null, null, ["dcapi", h'01']], an arbitrary
	// unwrapped SessionTranscript.
	transcriptHex = "83f6f682656463617069" + "4101"
	// readerAuthenticationHex is the text "ReaderAuthentication".
	readerAuthenticationHex = "74" + "526561646572417574686" + "56e7469636174696f6e"
	// readerAuthenticationAllHex is the text "ReaderAuthenticationAll".
	readerAuthenticationAllHex = "77" + "526561646572417574686" + "56e7469636174696f6e416c6c"
	// itemsAHex is #6.24(<<{"docType": "a"}>>), itemsBHex
	// #6.24(<<{"docType": "b"}>>).
	itemsAHex = "d8184b" + "a167646f6354797065" + "6161"
	itemsBHex = "d8184b" + "a167646f6354797065" + "6162"
)

func TestAuthenticationBytes(t *testing.T) {
	got, err := AuthenticationBytes(cat(t, transcriptHex), cat(t, itemsAHex))
	if err != nil {
		t.Fatal(err)
	}
	want := tagged(t, cat(t, "83", readerAuthenticationHex, transcriptHex, itemsAHex))
	if !bytes.Equal(got, want) {
		t.Errorf("AuthenticationBytes =\n%x\nwant\n%x", got, want)
	}
}

func TestAuthenticationAllBytes(t *testing.T) {
	transcript := cat(t, transcriptHex)
	items := [][]byte{cat(t, itemsAHex), cat(t, itemsBHex)}
	for name, tc := range map[string]struct {
		items [][]byte
		info  []byte
		want  []byte
	}{
		// No DeviceRequestInfo: the tuple's last member is null.
		"absent information": {
			items: items,
			want:  tagged(t, cat(t, "84", readerAuthenticationAllHex, transcriptHex, "82", itemsAHex, itemsBHex, "f6")),
		},
		// Present but empty: #6.24(<<{}>>), not null.
		"present empty information": {
			items: items,
			info:  cat(t, "d81841a0"),
			want:  tagged(t, cat(t, "84", readerAuthenticationAllHex, transcriptHex, "82", itemsAHex, itemsBHex, "d81841a0")),
		},
		// The document order is the request's, not sorted.
		"document order kept": {
			items: [][]byte{items[1], items[0]},
			want:  tagged(t, cat(t, "84", readerAuthenticationAllHex, transcriptHex, "82", itemsBHex, itemsAHex, "f6")),
		},
		// {"z": 1, "a": 2}: not in any deterministic order, kept as
		// the reader encoded it.
		"noncanonical information map order kept": {
			items: items[:1],
			info:  cat(t, "d81847", "a2617a01616102"),
			want:  tagged(t, cat(t, "84", readerAuthenticationAllHex, transcriptHex, "81", itemsAHex, "d81847a2617a01616102")),
		},
		// No document requests: an empty array, still followed by the
		// information member.
		"no documents": {
			items: nil,
			want:  tagged(t, cat(t, "84", readerAuthenticationAllHex, transcriptHex, "80", "f6")),
		},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := AuthenticationAllBytes(transcript, tc.items, tc.info)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, tc.want) {
				t.Errorf("AuthenticationAllBytes =\n%x\nwant\n%x", got, tc.want)
			}
		})
	}
}

func TestAuthenticationBytes_RefusesMissingInputs(t *testing.T) {
	transcript, items := cat(t, transcriptHex), cat(t, itemsAHex)
	if _, err := AuthenticationBytes(nil, items); err == nil {
		t.Error("AuthenticationBytes without a transcript: no error")
	}
	if _, err := AuthenticationBytes(transcript, nil); err == nil {
		t.Error("AuthenticationBytes without ItemsRequestBytes: no error")
	}
	if _, err := AuthenticationAllBytes(nil, [][]byte{items}, nil); err == nil {
		t.Error("AuthenticationAllBytes without a transcript: no error")
	}
	if _, err := AuthenticationAllBytes(transcript, [][]byte{items, nil}, nil); err == nil {
		t.Error("AuthenticationAllBytes with an empty ItemsRequestBytes: no error")
	}
	if _, err := AuthenticationAllBytes(transcript, [][]byte{items}, []byte{}); err == nil {
		t.Error("AuthenticationAllBytes with empty, non-nil DeviceRequestInfoBytes: no error")
	}
}
