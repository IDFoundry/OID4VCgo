package statuslist

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	mrand "math/rand/v2"
	"reflect"
	"testing"
)

// Known-answer tests reproducing draft-ietf-oauth-status-list-14 §4.1's
// own worked examples.

func TestPack_Draft14_Bits1Example(t *testing.T) {
	statuses := []uint8{1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1}
	got, err := Pack(Bits1, statuses)
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	want := []byte{0xB9, 0xA3}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Pack = %#v, want %#v", got, want)
	}

	for idx, s := range statuses {
		got, err := Unpack(Bits1, want, idx)
		if err != nil {
			t.Fatalf("Unpack(%d): %v", idx, err)
		}
		if got != s {
			t.Errorf("Unpack(%d) = %d, want %d", idx, got, s)
		}
	}
}

func TestPack_Draft14_Bits2Example(t *testing.T) {
	statuses := []uint8{1, 2, 0, 3, 0, 1, 0, 1, 1, 2, 3, 3}
	got, err := Pack(Bits2, statuses)
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	want := []byte{0xC9, 0x44, 0xF9}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Pack = %#v, want %#v", got, want)
	}

	for idx, s := range statuses {
		got, err := Unpack(Bits2, want, idx)
		if err != nil {
			t.Fatalf("Unpack(%d): %v", idx, err)
		}
		if got != s {
			t.Errorf("Unpack(%d) = %d, want %d", idx, got, s)
		}
	}
}

func TestPack_RejectsOutOfRangeStatus(t *testing.T) {
	if _, err := Pack(Bits1, []uint8{2}); err == nil {
		t.Errorf("Pack accepted status 2 for a 1-bit list")
	}
}

func TestUnpack_RejectsOutOfBounds(t *testing.T) {
	packed := []byte{0xFF}
	if _, err := Unpack(Bits1, packed, 8); err == nil {
		t.Errorf("Unpack accepted an index beyond the array's capacity")
	}
	if _, err := Unpack(Bits1, packed, -1); err == nil {
		t.Errorf("Unpack accepted a negative index")
	}
}

func TestCompressDecompress_RoundTrip(t *testing.T) {
	original := []byte{0xB9, 0xA3, 0x00, 0xFF, 0x10}
	compressed, err := compress(original)
	if err != nil {
		t.Fatalf("compress: %v", err)
	}
	got, err := decompress(compressed)
	if err != nil {
		t.Fatalf("decompress: %v", err)
	}
	if !reflect.DeepEqual(got, original) {
		t.Errorf("round trip = %#v, want %#v", got, original)
	}
}

// sparseStatuses is a 1-bit list of n statuses with share of them set,
// scattered at random, as revocations are.
func sparseStatuses(n int, share float64) []uint8 {
	r := mrand.New(mrand.NewPCG(1, 2))
	statuses := make([]uint8, n)
	for i := range statuses {
		if r.Float64() < share {
			statuses[i] = 1
		}
	}
	return statuses
}

// TestCompress_KeepsTheSmallerStream: compress returns the default
// level's stream or Huffman-only's, whichever is smaller — the first
// for a list of runs, the second for scattered bits — and either
// decodes to the list.
func TestCompress_KeepsTheSmallerStream(t *testing.T) {
	scattered, err := Pack(Bits1, sparseStatuses(1<<20, 0.025))
	if err != nil {
		t.Fatal(err)
	}
	runs := make([]byte, 1<<17)
	for i := range len(runs) / 2 {
		runs[i] = 0xff
	}
	for name, tc := range map[string]struct {
		packed []byte
		level  int
	}{"runs": {runs, zlib.DefaultCompression}, "scattered": {scattered, zlib.HuffmanOnly}} {
		got, err := compress(tc.packed)
		if err != nil {
			t.Fatal(err)
		}
		want, err := compressLevel(tc.packed, tc.level)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s: compressed to %d bytes, want the level %d stream's %d", name, len(got), tc.level, len(want))
		}
		if decoded, err := decompress(got); err != nil || !bytes.Equal(decoded, tc.packed) {
			t.Errorf("%s: decompress: %v", name, err)
		}
	}
}

// BenchmarkCompress_Sparse compresses a 2^24-entry list with 2.5% of
// it set, which zlib's highest level takes seconds over.
func BenchmarkCompress_Sparse(b *testing.B) {
	packed, err := Pack(Bits1, sparseStatuses(1<<24, 0.025))
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(packed)))
	for b.Loop() {
		if _, err := compress(packed); err != nil {
			b.Fatal(err)
		}
	}
}

func TestDecompress_Draft14_KnownVector(t *testing.T) {
	// draft-14 §4.2: the compressed+base64url "lst" value for the
	// bits=1 example above ([0xb9, 0xa3]).
	const lst = "eNrbuRgAAhcBXQ"
	raw, err := base64.RawURLEncoding.DecodeString(lst)
	if err != nil {
		t.Fatalf("decode base64: %v", err)
	}
	got, err := decompress(raw)
	if err != nil {
		t.Fatalf("decompress: %v", err)
	}
	want := []byte{0xB9, 0xA3}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("decompress = %#v, want %#v", got, want)
	}
}

// TestDecompress_RejectsBomb proves decompress bounds its own output
// rather than exhausting memory: a tiny, highly-repetitive compressed
// input (~200 MiB of zeros compresses to a few hundred bytes) must be
// rejected, not decompressed in full.
func TestDecompress_RejectsBomb(t *testing.T) {
	var buf bytes.Buffer
	w, err := zlib.NewWriterLevel(&buf, zlib.BestCompression)
	if err != nil {
		t.Fatalf("create zlib writer: %v", err)
	}
	chunk := make([]byte, 1<<20) // 1 MiB of zeros, reused each write
	const chunks = 32            // 32 MiB total, over maxDecompressedSize (16 MiB)
	for range chunks {
		if _, err := w.Write(chunk); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	t.Logf("compressed %d MiB of zeros down to %d bytes", chunks, buf.Len())

	if _, err := decompress(buf.Bytes()); err == nil {
		t.Fatal("decompress did not reject an oversized (decompression-bomb) input")
	}
}

func TestDecompress_Draft14_LargeAppendixVector(t *testing.T) {
	// draft-14 Appendix "Test vectors for Status List encoding", the
	// "1 bit Status List" example: a 2^20-entry list with a handful of
	// set bits. Exercises decompression at real scale, not just the
	// small inline examples above.
	const lst = "eNrt3AENwCAMAEGogklACtKQPg9LugC9k_ACvreiogEAAKkeCQAAAAAAAAAAAAAAAAAAAIBylgQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAXG9IAAAAAAAAAPwsJAAAAAAAAAAAAAAAvhsSAAAAAAAAAAAA7KpLAAAAAAAAAAAAAAAAAAAAAJsLCQAAAAAAAAAAADjelAAAAAAAAAAAKjDMAQAAAACAZC8L2AEb"
	raw, err := base64.RawURLEncoding.DecodeString(lst)
	if err != nil {
		t.Fatalf("decode base64: %v", err)
	}
	packed, err := decompress(raw)
	if err != nil {
		t.Fatalf("decompress: %v", err)
	}
	if len(packed) != 1<<20/8 {
		t.Fatalf("decompressed length = %d, want %d", len(packed), 1<<20/8)
	}

	set := map[int]bool{
		0: true, 1993: true, 25460: true, 159495: true, 495669: true,
		554353: true, 645645: true, 723232: true, 854545: true,
		934534: true, 1000345: true,
	}
	for _, idx := range []int{0, 1, 2, 1993, 1994, 25460, 159495, 1000345, 1000346} {
		got, err := Unpack(Bits1, packed, idx)
		if err != nil {
			t.Fatalf("Unpack(%d): %v", idx, err)
		}
		want := uint8(0)
		if set[idx] {
			want = 1
		}
		if got != want {
			t.Errorf("status[%d] = %d, want %d", idx, got, want)
		}
	}
}
