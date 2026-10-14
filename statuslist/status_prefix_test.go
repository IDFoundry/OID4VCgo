package statuslist

import (
	"encoding/base64"
	"runtime"
	"testing"
)

// One status lookup inflates only as far as its byte, in constant
// memory: a 128 MiB list (a ~130 KB zlib stream of zeros) costs one
// Status call far less than the list, and every index agrees with the
// full Decode.
func TestStatus_ReadsOnlyItsByte(t *testing.T) {
	big, err := compress(make([]byte, maxDecompressedSize))
	if err != nil {
		t.Fatal(err)
	}
	sl := StatusList{Bits: Bits1, Lst: base64.RawURLEncoding.EncodeToString(big)}
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	if status, err := sl.Status(5); err != nil || status != 0 {
		t.Fatalf("Status(5) = %d, %v", status, err)
	}
	runtime.ReadMemStats(&after)
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 8<<20 {
		t.Errorf("Status(5) allocated %d bytes, want well under the list's %d", allocated, maxDecompressedSize)
	}

	small, err := New(Bits2, []uint8{0, 1, 2, 3, 1, 0, 2}, "")
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := small.Decode()
	if err != nil {
		t.Fatal(err)
	}
	for idx := 0; idx < len(decoded.Packed)*Bits2.perByte(); idx++ {
		want, _ := decoded.Status(idx)
		if got, err := small.Status(idx); err != nil || got != want {
			t.Errorf("Status(%d) = %d, %v; Decode says %d", idx, got, err, want)
		}
	}
	if _, err := small.Status(len(decoded.Packed) * Bits2.perByte()); err == nil {
		t.Error("an index past the list's end was read")
	}
}
