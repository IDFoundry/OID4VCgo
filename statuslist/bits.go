package statuslist

import (
	"bytes"
	"compress/zlib"
	"errors"
	"fmt"
	"io"
)

// Bits is the number of bits used per Referenced Token in a Status
// List's compressed byte array (draft-14 §4.1, step 1). The only
// allowed values are 1, 2, 4 and 8.
type Bits int

const (
	Bits1 Bits = 1
	Bits2 Bits = 2
	Bits4 Bits = 4
	Bits8 Bits = 8
)

func (b Bits) valid() bool {
	switch b {
	case Bits1, Bits2, Bits4, Bits8:
		return true
	default:
		return false
	}
}

func (b Bits) perByte() int { return 8 / int(b) }

func (b Bits) mask() uint8 { return uint8(1<<uint(b)) - 1 }

// Pack builds the uncompressed byte array for statuses (draft-14 §4.1
// steps 1-3): statuses[i] is the status of the Referenced Token at
// index i, and must fit within bits (i.e. be less than 2^bits).
func Pack(bits Bits, statuses []uint8) ([]byte, error) {
	if !bits.valid() {
		return nil, fmt.Errorf("statuslist: invalid bits value %d (must be 1, 2, 4 or 8)", bits)
	}
	perByte := bits.perByte()
	byteLen := (len(statuses) + perByte - 1) / perByte
	packed := make([]byte, byteLen)

	mask := bits.mask()
	for idx, status := range statuses {
		if status > mask {
			return nil, fmt.Errorf("statuslist: status %d at index %d does not fit in %d bits", status, idx, bits)
		}
		byteIdx := idx / perByte
		bitOffset := uint((idx % perByte)) * uint(bits)
		packed[byteIdx] |= (status & mask) << bitOffset
	}
	return packed, nil
}

// Unpack extracts the status value at idx from a decompressed byte
// array (the inverse of Pack, per draft-14 §4). It fails if idx falls
// outside the array's capacity (draft-14 §8.3 step 6: "Fail if the
// provided index is out of bounds of the Status List").
func Unpack(bits Bits, packed []byte, idx int) (uint8, error) {
	if !bits.valid() {
		return 0, fmt.Errorf("statuslist: invalid bits value %d (must be 1, 2, 4 or 8)", bits)
	}
	if idx < 0 {
		return 0, fmt.Errorf("statuslist: negative index %d", idx)
	}
	perByte := bits.perByte()
	byteIdx := idx / perByte
	if byteIdx >= len(packed) {
		return 0, fmt.Errorf("statuslist: index %d is out of bounds (list has capacity for %d entries)", idx, len(packed)*perByte)
	}
	bitOffset := uint((idx % perByte)) * uint(bits)
	return (packed[byteIdx] >> bitOffset) & bits.mask(), nil
}

// compress DEFLATE-compresses b using the ZLIB data format (draft-14
// §4.1 step 4), and returns the smaller of two streams: the default
// level's and Huffman-only's. The draft recommends the highest level,
// but on a large, sparse list that takes seconds (3 s for a 2^24-entry
// list with 2.5% set), for a stream little smaller than the better of
// these two (an eighth at most, with 0.5% set or more), which together
// take tens of milliseconds:
// the default level wins on a list of runs, Huffman-only on one of
// scattered bits. Any DEFLATE stream decodes the same.
func compress(b []byte) ([]byte, error) {
	best, err := compressLevel(b, zlib.DefaultCompression)
	if err != nil {
		return nil, err
	}
	huffman, err := compressLevel(b, zlib.HuffmanOnly)
	if err != nil {
		return nil, err
	}
	if len(huffman) < len(best) {
		best = huffman
	}
	return best, nil
}

// compressLevel is compress at one zlib level.
func compressLevel(b []byte, level int) ([]byte, error) {
	var buf bytes.Buffer
	w, err := zlib.NewWriterLevel(&buf, level)
	if err != nil {
		return nil, fmt.Errorf("statuslist: create zlib writer: %w", err)
	}
	if _, err := w.Write(b); err != nil {
		return nil, fmt.Errorf("statuslist: compress: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("statuslist: compress: %w", err)
	}
	return buf.Bytes(), nil
}

// maxDecompressedSize bounds decompress's own output — without a
// limit, a small malicious (or compromised-issuer) "lst" value can
// exploit zlib's own compression ratio (approaching 1000:1 for
// degenerate input) to exhaust a caller's memory, a classic
// decompression-bomb DoS. 16 MiB holds 134 million one-bit statuses,
// far beyond any known deployment (draft-14's Appendix example, the
// largest in this package's tests, decompresses to 128 KiB for a
// 2^20-entry list), while bounding the CPU a signer's degenerate list
// costs each check: 128 MiB took about 250 ms.
const maxDecompressedSize = 16 << 20

// decompress reverses compress (draft-14 §8.3 step 5), rejecting
// output larger than maxDecompressedSize rather than exhausting
// memory on a decompression bomb.
func decompress(b []byte) ([]byte, error) {
	r, err := zlib.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, fmt.Errorf("statuslist: create zlib reader: %w", err)
	}
	// Read one byte past the limit so exceeding it is distinguishable
	// from landing exactly on it. r.Close() is deliberately skipped
	// once the limit is exceeded — the underlying reader is always an
	// in-memory bytes.Reader (no OS resource to leak), and Close()
	// would otherwise keep decompressing internally to reach and
	// verify the trailing checksum, undoing the whole point of
	// bailing out early on oversized input.
	out, err := io.ReadAll(io.LimitReader(r, maxDecompressedSize+1))
	if err != nil {
		_ = r.Close()
		return nil, fmt.Errorf("statuslist: decompress: %w", err)
	}
	if len(out) > maxDecompressedSize {
		return nil, fmt.Errorf("statuslist: decompress: decompressed size exceeds %d bytes", maxDecompressedSize)
	}
	if err := r.Close(); err != nil {
		return nil, fmt.Errorf("statuslist: decompress: checksum: %w", err)
	}
	return out, nil
}

// decompressedByte is the byte at offset idx of b's decompressed form,
// read in constant memory: the rest of the stream is inflated and
// discarded. ok is false when the stream ends before idx. The whole
// stream is read, to its checksum, even past idx: a truncated or
// corrupt list isn't a valid one (draft-14 §8.3 step 5), and its
// signature doesn't make it one, since the Issuer signed the bytes it
// sent. Like decompress, it refuses a list that inflates past
// maxDecompressedSize.
func decompressedByte(b []byte, idx int) (value byte, ok bool, err error) {
	r, err := zlib.NewReader(bytes.NewReader(b))
	if err != nil {
		return 0, false, fmt.Errorf("statuslist: create zlib reader: %w", err)
	}
	bounded := io.LimitReader(r, maxDecompressedSize+1)
	if _, err := io.CopyN(io.Discard, bounded, int64(idx)); err != nil {
		if errors.Is(err, io.EOF) {
			// The stream ended, and was complete: idx is past its end.
			return 0, false, nil
		}
		return 0, false, fmt.Errorf("statuslist: decompress: %w", err)
	}
	var one [1]byte
	if _, err := io.ReadFull(bounded, one[:]); err != nil {
		if errors.Is(err, io.EOF) {
			return 0, false, nil
		}
		return 0, false, fmt.Errorf("statuslist: decompress: %w", err)
	}
	rest, err := io.Copy(io.Discard, bounded)
	if err != nil {
		return 0, false, fmt.Errorf("statuslist: decompress: %w", err)
	}
	if int64(idx)+1+rest > maxDecompressedSize {
		return 0, false, fmt.Errorf("statuslist: decompress: decompressed size exceeds %d bytes", maxDecompressedSize)
	}
	return one[0], true, nil
}
