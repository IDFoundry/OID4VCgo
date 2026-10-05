package proximity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"io"

	"github.com/fxamacker/cbor/v2"
)

// DeviceSession is the mdoc (holder) side of one proximity session:
// it engages by QR code, then decrypts the reader's requests and
// encrypts the responses. It isn't safe for concurrent use.
type DeviceSession struct {
	eDeviceKey       *ecdsa.PrivateKey
	uuid             []byte
	deviceEngagement []byte
	handover         cbor.RawMessage

	sessionTranscriptBytes []byte
	cipher                 *cipherState
	closed                 bool
}

type deviceConfig struct {
	bleMode BLEMode
}

// DeviceOption configures NewDeviceSession.
type DeviceOption func(*deviceConfig)

// WithBLEMode sets the BLE mode the engagement offers. The default is
// PeripheralServer.
func WithBLEMode(mode BLEMode) DeviceOption {
	return func(c *deviceConfig) { c.bleMode = mode }
}

// NewDeviceSession generates the mdoc's ephemeral key (EDeviceKey) and a
// random BLE service UUID, and builds the DeviceEngagement for QRCode
// (§8.2.1.1, §9.1.5.1). random supplies the UUID; nil means
// crypto/rand. Key generation always uses the crypto package's own
// source.
func NewDeviceSession(random io.Reader, opts ...DeviceOption) (*DeviceSession, error) {
	cfg := deviceConfig{bleMode: PeripheralServer}
	for _, opt := range opts {
		opt(&cfg)
	}
	if random == nil {
		random = rand.Reader
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("proximity: generate EDeviceKey: %w", err)
	}
	uuid := make([]byte, 16)
	if _, err := io.ReadFull(random, uuid); err != nil {
		return nil, fmt.Errorf("proximity: generate service UUID: %w", err)
	}
	// RFC 9562 §5.4: a random (version 4, variant 10) UUID.
	uuid[6] = uuid[6]&0x0f | 0x40
	uuid[8] = uuid[8]&0x3f | 0x80

	de, err := encodeDeviceEngagement(&key.PublicKey, cfg.bleMode, uuid)
	if err != nil {
		return nil, err
	}
	return newDeviceSession(key, uuid, de, nullHandover), nil
}

// newDeviceSession is the engagement-independent constructor: Annex D's
// vectors use an NFC engagement, with its own DeviceEngagement bytes
// and Handover.
func newDeviceSession(key *ecdsa.PrivateKey, uuid, deviceEngagement []byte, handover cbor.RawMessage) *DeviceSession {
	return &DeviceSession{eDeviceKey: key, uuid: uuid, deviceEngagement: deviceEngagement, handover: handover}
}

// QRCode is the QR code payload (§8.2.2.3): "mdoc:" followed by the
// DeviceEngagement, base64url without padding.
func (s *DeviceSession) QRCode() string { return encodeQR(s.deviceEngagement) }

// ServiceUUID is the BLE service UUID the engagement offers, in
// 8-4-4-4-12 form.
func (s *DeviceSession) ServiceUUID() string { return formatUUID(s.uuid) }

// DeviceEngagementBytes is the encoded DeviceEngagement QRCode carries.
func (s *DeviceSession) DeviceEngagementBytes() []byte { return s.deviceEngagement }

// SessionTranscriptBytes is §9.1.5.1's SessionTranscriptBytes, which
// BuildDeviceResponse's device authentication signs over; nil until
// HandleSessionEstablishment succeeds.
func (s *DeviceSession) SessionTranscriptBytes() []byte { return s.sessionTranscriptBytes }

// HandleSessionEstablishment processes the reader's first message
// (§9.1.1.4): it takes EReaderKey, builds the SessionTranscript,
// derives the session keys (§9.1.5.2) and returns the decrypted
// DeviceRequest. On an error the session is closed; reply with
// StatusMessage(StatusFor(err)) where StatusFor reports one.
func (s *DeviceSession) HandleSessionEstablishment(msg []byte) (deviceRequest []byte, err error) {
	if s.closed {
		return nil, ErrSessionClosed
	}
	if s.cipher != nil {
		return nil, fmt.Errorf("proximity: session already established")
	}
	defer func() {
		if err != nil {
			s.closed = true
		}
	}()

	if len(msg) > MaxMessageBytes {
		return nil, fmt.Errorf("proximity: SessionEstablishment is %d bytes, over %d: %w", len(msg), MaxMessageBytes, ErrCBORDecoding)
	}
	var se sessionEstablishment
	if err := decMode.Unmarshal(msg, &se); err != nil {
		return nil, fmt.Errorf("proximity: decode SessionEstablishment: %w: %w", ErrCBORDecoding, err)
	}
	if se.EReaderKey == nil || se.Data == nil {
		return nil, fmt.Errorf("proximity: SessionEstablishment needs eReaderKey and data: %w", ErrCBORDecoding)
	}
	eReaderKeyBytes, err := unwrapTag24(se.EReaderKey)
	if err != nil {
		return nil, fmt.Errorf("proximity: decode EReaderKeyBytes: %w: %w", ErrCBORDecoding, err)
	}
	eReaderKey, err := decodeCoseKey(eReaderKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("proximity: EReaderKey: %w", err)
	}

	transcript, err := buildSessionTranscriptBytes(s.deviceEngagement, eReaderKeyBytes, s.handover)
	if err != nil {
		return nil, err
	}
	cs, err := newSessionCipher(s.eDeviceKey, eReaderKey, transcript, false)
	if err != nil {
		return nil, err
	}
	deviceRequest, err = cs.decrypt(se.Data)
	if err != nil {
		return nil, err
	}
	if len(deviceRequest) > MaxMessageBytes {
		return nil, fmt.Errorf("proximity: DeviceRequest is %d bytes, over %d: %w", len(deviceRequest), MaxMessageBytes, ErrCBORDecoding)
	}
	s.sessionTranscriptBytes, s.cipher = transcript, cs
	return deviceRequest, nil
}

// HandleSessionData processes a later message from the reader
// (§9.1.1.4): data is the decrypted payload, if any, and status the
// status code, if any. A status ends the session. On an error the
// session is closed, as for HandleSessionEstablishment.
func (s *DeviceSession) HandleSessionData(msg []byte) (data []byte, status *uint64, err error) {
	if s.closed {
		return nil, nil, ErrSessionClosed
	}
	if s.cipher == nil {
		return nil, nil, fmt.Errorf("proximity: session not established")
	}
	defer func() {
		if err != nil || status != nil {
			s.closed = true
		}
	}()
	return receive(s.cipher, msg)
}

// Encrypt builds a SessionData carrying plaintext (a DeviceResponse),
// encrypted under SKDevice. With terminate, it also carries status 20
// and closes the session.
func (s *DeviceSession) Encrypt(plaintext []byte, terminate bool) ([]byte, error) {
	if s.closed {
		return nil, ErrSessionClosed
	}
	if s.cipher == nil {
		return nil, fmt.Errorf("proximity: session not established")
	}
	msg, err := send(s.cipher, plaintext, terminate)
	if err != nil {
		return nil, err
	}
	if terminate {
		s.closed = true
	}
	return msg, nil
}

// Termination builds a SessionData carrying only status 20 and closes
// the session — the reply when the user declines or nothing matches
// the request, and the normal end of a session.
func (s *DeviceSession) Termination() []byte {
	s.closed = true
	return StatusMessage(StatusSessionTermination)
}
