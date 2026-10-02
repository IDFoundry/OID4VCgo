package mobile

import "crypto/rand"

// randReader is crypto/rand as an io.Reader value.
type randReader struct{}

func (randReader) Read(p []byte) (int, error) { return rand.Read(p) }
