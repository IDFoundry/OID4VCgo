package statuslist

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"io"
)

// Bits is the number of bits used per Referenced Token in a Status
// List's compressed byte array (draft-12 §4.1, step 1). The only
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

// Pack builds the uncompressed byte array for statuses (draft-12 §4.1
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
// array (the inverse of Pack, per draft-12 §4). It fails if idx falls
// outside the array's capacity (draft-12 §8.3 step 6: "Fail if the
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

// compress DEFLATE-compresses b using the ZLIB data format (draft-12
// §4.1 step 4), at the highest compression level as the draft
// recommends.
func compress(b []byte) ([]byte, error) {
	var buf bytes.Buffer
	w, err := zlib.NewWriterLevel(&buf, zlib.BestCompression)
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
// decompression-bomb DoS. 128 MiB comfortably exceeds any known real
// deployment (draft-12's own Appendix worked example, the largest
// checked into this package's own tests, decompresses to only 128 KiB
// for a 2^20-entry list — a thousand times smaller) while still
// bounding the worst case to a fixed, sane amount regardless of how
// small the compressed input is.
const maxDecompressedSize = 128 << 20 // 128 MiB

// decompress reverses compress (draft-12 §8.3 step 5), rejecting
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
