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
	eDeviceKey *ecdsa.PrivateKey
	// uuid is ServiceUUID's; peripheralUUID and centralUUID each
	// mode's, nil for a mode not offered.
	uuid, peripheralUUID, centralUUID []byte
	deviceEngagement                  []byte
	handover                          cbor.RawMessage
	handoverSelect                    []byte
	nfcNegotiated                     bool
	nfcHandoverRequest                []byte
	nfcDataParameters                 *NFCDataParameters
	bleIdent                          []byte

	sessionTranscriptBytes []byte
	eReaderKey             *ecdsa.PublicKey
	cipher                 *cipherState
	closed                 bool
	// rejected counts the first messages TrySessionEstablishment
	// rejected.
	rejected int
}

type deviceConfig struct {
	bleModes []BLEMode
}

// DeviceOption configures NewDeviceSession.
type DeviceOption func(*deviceConfig)

// WithBLEMode sets the one BLE mode the engagement offers. The default
// is PeripheralServer.
func WithBLEMode(mode BLEMode) DeviceOption {
	return WithBLEModes(mode)
}

// WithBLEModes sets the BLE modes the engagement offers, each with its
// own service UUID. Offering both, the mdoc advertises
// PeripheralServerUUID and scans for CentralClientUUID until the
// reader connects either way; a reader offered both should select
// central client mode (§8.3.3.1.1.1).
func WithBLEModes(modes ...BLEMode) DeviceOption {
	return func(c *deviceConfig) { c.bleModes = modes }
}

// NewDeviceSession generates the mdoc's ephemeral key (EDeviceKey) and a
// random BLE service UUID, and builds the DeviceEngagement for QRCode
// (§8.2.1.1, §9.1.5.1). random supplies the UUID; nil means
// crypto/rand. Key generation always uses the crypto package's own
// source.
func NewDeviceSession(random io.Reader, opts ...DeviceOption) (*DeviceSession, error) {
	cfg := deviceConfig{bleModes: []BLEMode{PeripheralServer}}
	for _, opt := range opts {
		opt(&cfg)
	}
	peripheral, central, err := offeredModes(cfg.bleModes)
	if err != nil {
		return nil, err
	}
	if random == nil {
		random = rand.Reader
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("proximity: generate EDeviceKey: %w", err)
	}
	peripheralUUID, centralUUID, err := modeUUIDs(random, peripheral, central)
	if err != nil {
		return nil, err
	}
	uuid := peripheralUUID
	if uuid == nil {
		uuid = centralUUID
	}

	de, err := encodeDeviceEngagement(&key.PublicKey, peripheralUUID, centralUUID)
	if err != nil {
		return nil, err
	}
	s := newDeviceSession(key, uuid, de, nullHandover)
	pe, err := parseDeviceEngagement(de)
	if err != nil {
		return nil, err
	}
	s.bleIdent = bleIdent(pe.eDeviceKeyBytes)
	s.peripheralUUID, s.centralUUID = peripheralUUID, centralUUID
	return s, nil
}

// offeredModes reports which BLE modes modes offers: at least one, and
// none unknown.
func offeredModes(modes []BLEMode) (peripheral, central bool, err error) {
	for _, m := range modes {
		switch m {
		case PeripheralServer:
			peripheral = true
		case CentralClient:
			central = true
		default:
			return false, false, fmt.Errorf("proximity: unknown BLE mode %d", int(m))
		}
	}
	if !peripheral && !central {
		return false, false, fmt.Errorf("proximity: no BLE mode offered")
	}
	return peripheral, central, nil
}

// modeUUIDs draws a service UUID for each offered mode, peripheral
// server mode's first, so a single-mode session reads the one UUID it
// always did.
func modeUUIDs(random io.Reader, peripheral, central bool) (peripheralUUID, centralUUID []byte, err error) {
	if peripheral {
		if peripheralUUID, err = randomUUID(random); err != nil {
			return nil, nil, err
		}
	}
	if central {
		if centralUUID, err = randomUUID(random); err != nil {
			return nil, nil, err
		}
	}
	return peripheralUUID, centralUUID, nil
}

// randomUUID is a random (version 4, variant 10) UUID, RFC 9562 §5.4.
func randomUUID(random io.Reader) ([]byte, error) {
	uuid := make([]byte, 16)
	if _, err := io.ReadFull(random, uuid); err != nil {
		return nil, fmt.Errorf("proximity: generate service UUID: %w", err)
	}
	uuid[6] = uuid[6]&0x0f | 0x40
	uuid[8] = uuid[8]&0x3f | 0x80
	return uuid, nil
}

// newDeviceSession is the engagement-independent constructor: Annex D's
// vectors use an NFC engagement, with its own DeviceEngagement bytes
// and Handover.
func newDeviceSession(key *ecdsa.PrivateKey, uuid, deviceEngagement []byte, handover cbor.RawMessage) *DeviceSession {
	return &DeviceSession{eDeviceKey: key, uuid: uuid, deviceEngagement: deviceEngagement, handover: handover}
}

// QRCode is the QR code payload (§8.2.2.3): "mdoc:" followed by the
// DeviceEngagement, base64url without padding.
func (s *DeviceSession) QRCode() string {
	if s.nfcNegotiated || s.handoverSelect != nil {
		return "" // NFC engagement has no QR retrieval methods.
	}
	return encodeQR(s.deviceEngagement)
}

// ServiceUUID is the BLE service UUID the engagement offers, in
// 8-4-4-4-12 form: PeripheralServerUUID's when it offers that mode,
// else CentralClientUUID's.
func (s *DeviceSession) ServiceUUID() string { return formatUUID(s.uuid) }

// PeripheralServerUUID is the service UUID to advertise as GATT server
// in mdoc peripheral server mode, in 8-4-4-4-12 form; empty when the
// engagement doesn't offer that mode.
func (s *DeviceSession) PeripheralServerUUID() string { return formatOptionalUUID(s.peripheralUUID) }

// CentralClientUUID is the service UUID to scan for, and connect to as
// GATT client, in mdoc central client mode, in 8-4-4-4-12 form; empty
// when the engagement doesn't offer that mode.
func (s *DeviceSession) CentralClientUUID() string { return formatOptionalUUID(s.centralUUID) }

func formatOptionalUUID(uuid []byte) string {
	if uuid == nil {
		return ""
	}
	return formatUUID(uuid)
}

// BLEIdent is the value the reader's Ident characteristic must hold in
// mdoc central client mode (§8.3.3.1.1): after connecting, read it
// and disconnect if it differs. Peripheral server mode doesn't use it.
func (s *DeviceSession) BLEIdent() []byte { return s.bleIdent }

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
//
// Over a transport any nearby device can write to before the reader
// does (BLE in mdoc peripheral server mode), use
// TrySessionEstablishment instead: here one message that doesn't
// decrypt, from a device that never saw the engagement, ends the
// session.
func (s *DeviceSession) HandleSessionEstablishment(msg []byte) ([]byte, error) {
	if err := s.readyToEstablish(); err != nil {
		return nil, err
	}
	deviceRequest, _, err := s.establish(msg)
	if err != nil {
		s.close()
		return nil, err
	}
	return deviceRequest, nil
}

// MaxRejectedEstablishments is how many first messages
// TrySessionEstablishment rejects, leaving the session waiting, before
// the next one that doesn't decode or decrypt closes the session as
// HandleSessionEstablishment would.
const MaxRejectedEstablishments = 16

// TrySessionEstablishment is HandleSessionEstablishment for a message
// whose sender isn't yet known to be the reader. Until a message has
// decrypted, one that doesn't decode or decrypt — its sender doesn't
// hold the key this engagement's EDeviceKey agrees — returns an error
// wrapping ErrEstablishmentRejected and leaves the session waiting for
// its reader: send nothing back, and drop the device that sent it if
// the transport can tell. The message reveals nothing about the
// session. After MaxRejectedEstablishments such messages, the next
// closes the session with the error HandleSessionEstablishment would
// give (status 10 or 11, §9.1.1.4). An error once the message has
// decrypted closes the session as HandleSessionEstablishment's does.
//
// For NFC data retrieval it is HandleSessionEstablishment: the reader
// is the one device in the field, which waits for a status reply.
func (s *DeviceSession) TrySessionEstablishment(msg []byte) ([]byte, error) {
	if s.nfcDataParameters != nil {
		return s.HandleSessionEstablishment(msg)
	}
	if err := s.readyToEstablish(); err != nil {
		return nil, err
	}
	deviceRequest, rejectable, err := s.establish(msg)
	if err == nil {
		return deviceRequest, nil
	}
	if rejectable && s.rejected < MaxRejectedEstablishments {
		s.rejected++
		return nil, fmt.Errorf("%w: %w", ErrEstablishmentRejected, err)
	}
	s.close()
	return nil, err
}

// readyToEstablish reports why the session can't take a
// SessionEstablishment now, if it can't. Such an error closes nothing.
func (s *DeviceSession) readyToEstablish() error {
	if s.closed {
		return ErrSessionClosed
	}
	if s.nfcNegotiated && s.handoverSelect == nil {
		return fmt.Errorf("proximity: NFC handover has not completed")
	}
	if s.cipher != nil {
		return fmt.Errorf("proximity: session already established")
	}
	return nil
}

// establish decrypts a SessionEstablishment and establishes the session
// with it. rejectable is true for an error before anything decrypted:
// the message proves nothing about the session's reader. It closes
// nothing; its callers decide.
func (s *DeviceSession) establish(msg []byte) (deviceRequest []byte, rejectable bool, err error) {
	transcript, eReaderKey, cs, deviceRequest, err := s.openEstablishment(msg)
	if err != nil {
		return nil, true, err
	}
	if len(deviceRequest) > MaxMessageBytes {
		return nil, false, fmt.Errorf("proximity: DeviceRequest is %d bytes, over %d: %w", len(deviceRequest), MaxMessageBytes, ErrCBORDecoding)
	}
	s.sessionTranscriptBytes, s.eReaderKey, s.cipher = transcript, eReaderKey, cs
	return deviceRequest, false, nil
}

// openEstablishment decodes and decrypts a SessionEstablishment,
// without changing the session.
func (s *DeviceSession) openEstablishment(msg []byte) (transcript []byte, eReaderKey *ecdsa.PublicKey, cs *cipherState, deviceRequest []byte, err error) {
	if len(msg) > MaxMessageBytes {
		return nil, nil, nil, nil, fmt.Errorf("proximity: SessionEstablishment is %d bytes, over %d: %w", len(msg), MaxMessageBytes, ErrCBORDecoding)
	}
	var se sessionEstablishment
	if err := decMode.Unmarshal(msg, &se); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("proximity: decode SessionEstablishment: %w: %w", ErrCBORDecoding, err)
	}
	if se.EReaderKey == nil || se.Data == nil {
		return nil, nil, nil, nil, fmt.Errorf("proximity: SessionEstablishment needs eReaderKey and data: %w", ErrCBORDecoding)
	}
	eReaderKeyBytes, err := unwrapTag24(se.EReaderKey)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("proximity: decode EReaderKeyBytes: %w: %w", ErrCBORDecoding, err)
	}
	if eReaderKey, err = decodeCoseKey(eReaderKeyBytes); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("proximity: EReaderKey: %w", err)
	}
	if transcript, err = buildSessionTranscriptBytes(s.deviceEngagement, eReaderKeyBytes, s.handover); err != nil {
		return nil, nil, nil, nil, err
	}
	if cs, err = newSessionCipher(s.eDeviceKey, eReaderKey, transcript, false); err != nil {
		return nil, nil, nil, nil, err
	}
	if deviceRequest, err = cs.decrypt(se.Data); err != nil {
		return nil, nil, nil, nil, err
	}
	return transcript, eReaderKey, cs, deviceRequest, nil
}

// EReaderKey is the reader's ephemeral public key from its
// SessionEstablishment, which MAC device authentication
// (BuildDeviceResponseMAC) agrees a key with; nil until
// HandleSessionEstablishment succeeds, and again once the session is
// closed.
func (s *DeviceSession) EReaderKey() *ecdsa.PublicKey { return s.eReaderKey }

// close ends the session and drops its secrets: EDeviceKey, the session
// keys, and the reader's ephemeral key it agreed them with. A closed
// session refuses every further message, so nothing needs them, and a
// later compromise of the process can't decrypt what was recorded.
func (s *DeviceSession) close() {
	s.closed = true
	s.eDeviceKey, s.cipher, s.eReaderKey = nil, nil, nil
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
			s.close()
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
		s.close()
	}
	return msg, nil
}

// ErrorResponse answers a request the holder decrypted but can't
// process — a ParseDeviceRequest error — with an encrypted
// DeviceResponse carrying no documents and DeviceResponseStatusFor(err)
// (§8.3.2.1.2.3), and status 20: it closes the session.
func (s *DeviceSession) ErrorResponse(err error) ([]byte, error) {
	resp, encErr := encMode.Marshal(errorDeviceResponse{Version: deviceRequestVersion, Status: DeviceResponseStatusFor(err)})
	if encErr != nil {
		return nil, fmt.Errorf("proximity: encode DeviceResponse: %w", encErr)
	}
	return s.Encrypt(resp, true)
}

// errorDeviceResponse is a DeviceResponse with a status and no
// documents.
type errorDeviceResponse struct {
	Version string `cbor:"version"`
	Status  uint64 `cbor:"status"`
}

// Termination builds a SessionData carrying only status 20 and closes
// the session — the reply when the user declines or nothing matches
// the request, and the normal end of a session.
func (s *DeviceSession) Termination() []byte {
	s.close()
	return StatusMessage(StatusSessionTermination)
}
