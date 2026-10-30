package mobile

import (
	"sync"
	"testing"
)

// An NFCExchange's methods may be called from several threads at once,
// as a native NFC callback and a cancel button do, and Close ends it
// from any of them.
func TestNFCExchange_Concurrent(t *testing.T) {
	x := NewNFCTransact(261, 255, 256, []byte("a session message"))
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 100 {
				if !x.Done() {
					_ = x.Command()
					_ = x.WaitMillis()
				}
				_ = x.Negotiated()
			}
		})
	}
	wg.Go(func() { _ = x.Next([]byte{0x90, 0x00}) })
	wg.Go(x.Close)
	wg.Wait()
	x.Close()
	if err := x.Next([]byte{0x90, 0x00}); err == nil && !x.Done() {
		t.Error("Next after Close went on with the exchange")
	}
}
