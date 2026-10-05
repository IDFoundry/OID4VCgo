package proximity

import (
	"errors"
)

// SessionData status codes (ISO/IEC 18013-5 §9.1.1.4 Table 20). Each
// one terminates the session.
const (
	StatusSessionEncryptionError uint64 = 10
	StatusCBORDecodingError      uint64 = 11
	StatusSessionTermination     uint64 = 20
)

var (
	// ErrSessionEncryption is a message that failed to decrypt: a
	// tampered ciphertext, the wrong key, or a replayed or reordered
	// message (the counter is implicit). Reply with
	// StatusSessionEncryptionError.
	ErrSessionEncryption = errors.New("proximity: session encryption error")

	// ErrCBORDecoding is a message that isn't the CBOR structure its
	// step expects, or is larger than MaxMessageBytes. Reply with
	// StatusCBORDecodingError.
	ErrCBORDecoding = errors.New("proximity: CBOR decoding error")

	// ErrSessionClosed is a call on a session that has terminated — by
	// either side's status message, or by an earlier error.
	ErrSessionClosed = errors.New("proximity: session closed")

	// ErrDeclined is ReaderSession.Verify's result when the mdoc ends
	// the session (status 20) instead of responding: the user declined,
	// or the holder had nothing matching the request.
	ErrDeclined = errors.New("proximity: mdoc terminated the session without a response")
)

// StatusFor maps an error from this package to the status code the
// caller sends back with StatusMessage before closing the transport;
// ok is false for an error with no status reply, such as one from
// ErrSessionClosed or a verification failure.
func StatusFor(err error) (status uint64, ok bool) {
	switch {
	case errors.Is(err, ErrSessionEncryption):
		return StatusSessionEncryptionError, true
	case errors.Is(err, ErrCBORDecoding):
		return StatusCBORDecodingError, true
	default:
		return 0, false
	}
}

// StatusMessage builds a SessionData carrying only status (§9.1.1.4),
// unencrypted. Use it for the 10/11 reply StatusFor returns; for a
// normal session end, the sessions' own Termination does the same and
// also closes the session.
func StatusMessage(status uint64) []byte {
	b, err := encMode.Marshal(sessionData{Status: &status})
	if err != nil {
		panic("proximity: encode status message: " + err.Error())
	}
	return b
}
