package proximity

import (
	"errors"
	"fmt"
)

// SessionData status codes (ISO/IEC 18013-5 §9.1.1.4 Table 20). Each
// one terminates the session.
const (
	StatusSessionEncryptionError uint64 = 10
	StatusCBORDecodingError      uint64 = 11
	StatusSessionTermination     uint64 = 20
)

// DeviceResponse status codes (§8.3.2.1.2.3 Table 8): an mdoc's answer,
// encrypted, to a DeviceRequest it decrypted but can't process. A
// DeviceResponse with a status other than 0 carries no documents.
const (
	DeviceResponseStatusOK             uint64 = 0
	DeviceResponseStatusGeneralError   uint64 = 10
	DeviceResponseStatusCBORDecoding   uint64 = 11
	DeviceResponseStatusCBORValidation uint64 = 12
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

	// ErrCBORValidation is a DeviceRequest that is well-formed CBOR but
	// not a valid DeviceRequest: a missing or mistyped field, a version
	// other than 1.x, or a request for nothing. ParseDeviceRequest
	// returns it; answer with DeviceSession.ErrorResponse (status 12).
	ErrCBORValidation = errors.New("proximity: CBOR validation error")

	// ErrSessionClosed is a call on a session that has terminated — by
	// either side's status message, or by an earlier error.
	ErrSessionClosed = errors.New("proximity: session closed")

	// ErrDeclined is ReaderSession.Verify's result when the mdoc ends
	// the session (status 20) instead of responding: the user declined,
	// or the holder had nothing matching the request. A status message
	// isn't encrypted (§9.1.1.4), so anyone within radio range can send
	// one: don't treat it as the holder's authenticated decision.
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
	case errors.Is(err, ErrCBORDecoding), errors.Is(err, ErrCBORValidation):
		return StatusCBORDecodingError, true
	default:
		return 0, false
	}
}

// DeviceResponseStatusFor maps an error from ParseDeviceRequest, or the
// holder's own failure to process a request, to the DeviceResponse
// status DeviceSession.ErrorResponse sends: 11 for ErrCBORDecoding, 12
// for ErrCBORValidation, and 10 for anything else.
func DeviceResponseStatusFor(err error) uint64 {
	switch {
	case errors.Is(err, ErrCBORDecoding):
		return DeviceResponseStatusCBORDecoding
	case errors.Is(err, ErrCBORValidation):
		return DeviceResponseStatusCBORValidation
	default:
		return DeviceResponseStatusGeneralError
	}
}

// DeviceResponseStatusError is ReaderSession.Verify's result for a
// DeviceResponse with a status other than 0: the mdoc couldn't process
// the request (§8.3.2.1.2.3).
type DeviceResponseStatusError struct {
	// Status is the DeviceResponse's status (§8.3.2.1.2.3 Table 8):
	// DeviceResponseStatusGeneralError, DeviceResponseStatusCBORDecoding
	// or DeviceResponseStatusCBORValidation.
	Status uint64
}

func (e *DeviceResponseStatusError) Error() string {
	switch e.Status {
	case DeviceResponseStatusGeneralError:
		return "proximity: DeviceResponse status 10 (general error)"
	case DeviceResponseStatusCBORDecoding:
		return "proximity: DeviceResponse status 11 (CBOR decoding error)"
	case DeviceResponseStatusCBORValidation:
		return "proximity: DeviceResponse status 12 (CBOR validation error)"
	default:
		return fmt.Sprintf("proximity: DeviceResponse status %d", e.Status)
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
