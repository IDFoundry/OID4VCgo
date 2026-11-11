package nfcapdu

import (
	"strings"
	"testing"
	"time"
)

// However long a tag's TNEP service asks the reader to wait, a reader
// polling a tag that never answers gives up after MaxTNEPWait in all,
// polling at most as often as the service allows, never sooner than it
// asks.
func TestTNEPWaitIsBounded(t *testing.T) {
	for name, tc := range map[string]struct {
		timing    tnepTiming
		wantPolls int
		wantTotal time.Duration
	}{
		// This package's own holder: 16 waits of 8 ms.
		"WT 16, N_wait 15": {tnepTiming{wt: 16, waits: 15, maxMessage: 1024}, 16, 16 * 8 * time.Millisecond},
		// 16 waits of 512 ms would be 8.2 s: the tenth is cut short.
		"WT 40, N_wait 15": {tnepTiming{wt: 40, waits: 15, maxMessage: 1024}, 10, MaxTNEPWait},
		// The most TNEP allows: 16 waits of 27.5 s, over 7 minutes.
		"WT 63, N_wait 15": {tnepTiming{wt: 63, waits: 15, maxMessage: 1024}, 1, MaxTNEPWait},
		"WT 63, N_wait 0":  {tnepTiming{wt: 63, waits: 0, maxMessage: 1024}, 1, MaxTNEPWait},
	} {
		t.Run(name, func(t *testing.T) {
			var waits []time.Duration
			reader := &type4Reader{
				maxTransceive: 261, writeChunk: 250, maxSize: 1024, writable: true,
				transceive: func(c []byte, wait time.Duration) ([]byte, error) {
					if c[1] == insReadBinary {
						waits = append(waits, wait)
						return []byte{0, 0, 0x90, 0x00}, nil // NLEN 0: no answer yet
					}
					return []byte{0x90, 0x00}, nil
				},
			}
			_, err := reader.transact(tnepSelect, tc.timing)
			if err == nil || !strings.Contains(err.Error(), "timed out") {
				t.Fatalf("transact = %v, want a timeout", err)
			}
			var total time.Duration
			for _, w := range waits {
				if w <= 0 || w > tc.timing.wait() {
					t.Errorf("waited %v, want (0, %v]", w, tc.timing.wait())
				}
				total += w
			}
			if len(waits) != tc.wantPolls || total != tc.wantTotal {
				t.Errorf("%d polls waiting %v in all, want %d waiting %v", len(waits), total, tc.wantPolls, tc.wantTotal)
			}
		})
	}
}
