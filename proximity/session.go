package proximity

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math"

	"github.com/fxamacker/cbor/v2"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/internal/hkdf"
)

// sessionEstablishment is §9.1.1.4's SessionEstablishment, the reader's
// first message. Field order matches the CDDL (and Annex D's bytes).
type sessionEstablishment struct {
	EReaderKey cbor.RawMessage `cbor:"eReaderKey"` // EReaderKeyBytes: #6.24(bstr .cbor COSE_Key)
	Data       []byte          `cbor:"data"`
}

// sessionData is §9.1.1.4's SessionData, every later message: an
// encrypted payload, a status, or both. Unknown members (Multipaz's
// optional "seq") are ignored.
type sessionData struct {
	Data   []byte  `cbor:"data,omitempty"`
	Status *uint64 `cbor:"status,omitempty"`
}

// IV identifiers (§9.1.1.5): the first 8 bytes of every nonce, by
// sending direction.
const (
	ivIdentifierReader uint64 = 0 // reader → mdoc
	ivIdentifierDevice uint64 = 1 // mdoc → reader
)

// cipherState is one established session's AES-256-GCM state
// (§9.1.1.5): a key and implicit message counter per direction, both
// counters starting at 1.
type cipherState struct {
	send, recv           cipher.AEAD
	sendID, recvID       uint64
	sendCount, recvCount uint32
}

// newCipherState derives SKReader/SKDevice (§9.1.5.2) from own and
// remote over sessionTranscriptBytes, oriented for the given role.
func newCipherState(own *ecdh.PrivateKey, remote *ecdh.PublicKey, sessionTranscriptBytes []byte, isReader bool) (*cipherState, error) {
	z, err := own.ECDH(remote)
	if err != nil {
		return nil, fmt.Errorf("proximity: ECDH: %w", err)
	}
	salt := sha256.Sum256(sessionTranscriptBytes)
	skReader, err := hkdf.Key(salt[:], z, []byte("SKReader"), 32)
	if err != nil {
		return nil, fmt.Errorf("proximity: derive SKReader: %w", err)
	}
	skDevice, err := hkdf.Key(salt[:], z, []byte("SKDevice"), 32)
	if err != nil {
		return nil, fmt.Errorf("proximity: derive SKDevice: %w", err)
	}
	reader, err := newGCM(skReader)
	if err != nil {
		return nil, err
	}
	device, err := newGCM(skDevice)
	if err != nil {
		return nil, err
	}
	s := &cipherState{sendCount: 1, recvCount: 1}
	if isReader {
		s.send, s.sendID, s.recv, s.recvID = reader, ivIdentifierReader, device, ivIdentifierDevice
	} else {
		s.send, s.sendID, s.recv, s.recvID = device, ivIdentifierDevice, reader, ivIdentifierReader
	}
	return s, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("proximity: AES: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("proximity: AES-GCM: %w", err)
	}
	return gcm, nil
}

func nonce(identifier uint64, counter uint32) []byte {
	iv := make([]byte, 12)
	binary.BigEndian.PutUint64(iv[:8], identifier)
	binary.BigEndian.PutUint32(iv[8:], counter)
	return iv
}

func (s *cipherState) encrypt(plaintext []byte) ([]byte, error) {
	if s.sendCount == math.MaxUint32 {
		return nil, fmt.Errorf("proximity: message counter exhausted")
	}
	ct := s.send.Seal(nil, nonce(s.sendID, s.sendCount), plaintext, nil)
	s.sendCount++
	return ct, nil
}

// decrypt opens ciphertext under the next expected counter. A replayed
// or reordered message fails authentication, the same as a tampered
// one, since the counter isn't sent.
func (s *cipherState) decrypt(ciphertext []byte) ([]byte, error) {
	if s.recvCount == math.MaxUint32 {
		return nil, fmt.Errorf("proximity: message counter exhausted: %w", ErrSessionEncryption)
	}
	pt, err := s.recv.Open(nil, nonce(s.recvID, s.recvCount), ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("proximity: decrypt message %d: %w", s.recvCount, ErrSessionEncryption)
	}
	s.recvCount++
	return pt, nil
}

// buildSessionTranscriptBytes builds SessionTranscriptBytes (§9.1.5.1):
// #6.24(bstr .cbor [DeviceEngagementBytes, EReaderKeyBytes, Handover]),
// where DeviceEngagementBytes and EReaderKeyBytes tag the exact bytes
// sent. handover is already-encoded CBOR: null for QR engagement, and
// an NFC handover's [Hs, Hr] once that's supported.
func buildSessionTranscriptBytes(deviceEngagement, eReaderKey []byte, handover cbor.RawMessage) ([]byte, error) {
	deviceEngagementBytes, err := wrapTag24(deviceEngagement)
	if err != nil {
		return nil, fmt.Errorf("proximity: encode DeviceEngagementBytes: %w", err)
	}
	eReaderKeyBytes, err := wrapTag24(eReaderKey)
	if err != nil {
		return nil, fmt.Errorf("proximity: encode EReaderKeyBytes: %w", err)
	}
	transcript, err := encMode.Marshal([]cbor.RawMessage{deviceEngagementBytes, eReaderKeyBytes, handover})
	if err != nil {
		return nil, fmt.Errorf("proximity: encode SessionTranscript: %w", err)
	}
	b, err := wrapTag24(transcript)
	if err != nil {
		return nil, fmt.Errorf("proximity: encode SessionTranscriptBytes: %w", err)
	}
	return b, nil
}

// encodeCoseKey encodes pub as an EC2 COSE_Key (RFC 9053 §7.1.1):
// {1: 2, -1: 1, -2: x, -3: y}.
func encodeCoseKey(pub *ecdsa.PublicKey) ([]byte, error) {
	key, err := mdoc.NewCoseKey(pub)
	if err != nil {
		return nil, fmt.Errorf("proximity: COSE_Key: %w", err)
	}
	b, err := encMode.Marshal(key)
	if err != nil {
		return nil, fmt.Errorf("proximity: encode COSE_Key: %w", err)
	}
	return b, nil
}

// decodeCoseKey decodes an ephemeral key's COSE_Key bytes, which cipher
// suite 1 requires to be on one of its ECDH curves (§9.1.5.2): of
// those, Go's standard library has P-256, P-384 and P-521.
func decodeCoseKey(b []byte) (*ecdsa.PublicKey, error) {
	var key mdoc.CoseKey
	if err := decMode.Unmarshal(b, &key); err != nil {
		return nil, fmt.Errorf("proximity: decode COSE_Key: %w: %w", ErrCBORDecoding, err)
	}
	pub, err := key.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("proximity: COSE_Key: %w", err)
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("proximity: COSE_Key: cipher suite 1 needs an ECDH key on P-256, P-384 or P-521, got %T", pub)
	}
	return ec, nil
}

// compressedCoseKey is a COSE_Key whose y may be a bool, the sign bit of
// a compressed point (RFC 9053 §7.1.1).
type compressedCoseKey struct {
	Kty int64           `cbor:"1,keyasint"`
	Crv int64           `cbor:"-1,keyasint"`
	X   []byte          `cbor:"-2,keyasint"`
	Y   cbor.RawMessage `cbor:"-3,keyasint"`
}

// decodeEDeviceKey decodes the mdoc's ephemeral key's COSE_Key bytes,
// which, unlike EReaderKey, may hold a compressed point (ISO/IEC 18013-5
// second edition §12.7.2): y the bool sign bit.
func decodeEDeviceKey(b []byte) (*ecdsa.PublicKey, error) {
	var key compressedCoseKey
	if err := decMode.Unmarshal(b, &key); err != nil {
		return nil, fmt.Errorf("proximity: decode COSE_Key: %w: %w", ErrCBORDecoding, err)
	}
	var odd bool
	if key.Y == nil || decMode.Unmarshal(key.Y, &odd) != nil {
		return decodeCoseKey(b)
	}
	curve, ok := ephemeralCurve(key.Crv)
	if key.Kty != 2 || !ok {
		return nil, fmt.Errorf("proximity: COSE_Key: cipher suite 1 needs an EC2 key on P-256, P-384 or P-521")
	}
	size := (curve.Params().BitSize + 7) / 8
	if len(key.X) != size {
		return nil, fmt.Errorf("proximity: COSE_Key: x is %d bytes, %s's are %d", len(key.X), curve.Params().Name, size)
	}
	prefix := byte(2)
	if odd {
		prefix = 3
	}
	x, y := elliptic.UnmarshalCompressed(curve, append([]byte{prefix}, key.X...))
	if x == nil {
		return nil, fmt.Errorf("proximity: COSE_Key: compressed point isn't on %s", curve.Params().Name)
	}
	uncompressed := make([]byte, 1+2*size)
	uncompressed[0] = 4
	x.FillBytes(uncompressed[1 : 1+size])
	y.FillBytes(uncompressed[1+size:])
	pub, err := ecdsa.ParseUncompressedPublicKey(curve, uncompressed)
	if err != nil {
		return nil, fmt.Errorf("proximity: COSE_Key: %w", err)
	}
	return pub, nil
}

// ephemeralCurve is the curve an ephemeral key's COSE curve identifier
// (RFC 9053 §7.1) names, if it's one this package agrees keys on.
// Cipher suite 1's brainpool curves (§9.1.5.2) aren't in Go's standard
// library.
func ephemeralCurve(crv int64) (elliptic.Curve, bool) {
	switch crv {
	case 1:
		return elliptic.P256(), true
	case 2:
		return elliptic.P384(), true
	case 3:
		return elliptic.P521(), true
	default:
		return nil, false
	}
}

// decodeSessionData size-checks and decodes msg as a SessionData.
func decodeSessionData(msg []byte) (sessionData, error) {
	if len(msg) > MaxMessageBytes {
		return sessionData{}, fmt.Errorf("proximity: SessionData is %d bytes, over %d: %w", len(msg), MaxMessageBytes, ErrCBORDecoding)
	}
	var sd sessionData
	if err := decMode.Unmarshal(msg, &sd); err != nil {
		return sessionData{}, fmt.Errorf("proximity: decode SessionData: %w: %w", ErrCBORDecoding, err)
	}
	if sd.Data == nil && sd.Status == nil {
		return sessionData{}, fmt.Errorf("proximity: SessionData has neither data nor status: %w", ErrCBORDecoding)
	}
	return sd, nil
}

func encodeSessionData(data []byte, status *uint64) ([]byte, error) {
	b, err := encMode.Marshal(sessionData{Data: data, Status: status})
	if err != nil {
		return nil, fmt.Errorf("proximity: encode SessionData: %w", err)
	}
	return b, nil
}

func statusPtr(s uint64) *uint64 { return &s }

// newSessionCipher converts the ECDSA-typed ephemeral keys (the form
// credential/mdoc's DeviceMAC takes) to crypto/ecdh for key agreement.
// Both must be on one curve (§9.1.5.2): a reader answers an EDeviceKey
// with an EReaderKey on its curve.
func newSessionCipher(own *ecdsa.PrivateKey, remote *ecdsa.PublicKey, sessionTranscriptBytes []byte, isReader bool) (*cipherState, error) {
	if own.Curve != remote.Curve {
		return nil, fmt.Errorf("proximity: the ephemeral keys are on different curves, %s and %s", own.Curve.Params().Name, remote.Curve.Params().Name)
	}
	ownECDH, err := own.ECDH()
	if err != nil {
		return nil, fmt.Errorf("proximity: ephemeral key: %w", err)
	}
	remoteECDH, err := remote.ECDH()
	if err != nil {
		return nil, fmt.Errorf("proximity: remote ephemeral key: %w", err)
	}
	return newCipherState(ownECDH, remoteECDH, sessionTranscriptBytes, isReader)
}

// receive decodes and, if it carries data, decrypts one SessionData.
func receive(cs *cipherState, msg []byte) ([]byte, *uint64, error) {
	sd, err := decodeSessionData(msg)
	if err != nil {
		return nil, nil, err
	}
	if sd.Data == nil {
		return nil, sd.Status, nil
	}
	data, err := cs.decrypt(sd.Data)
	if err != nil {
		return nil, nil, err
	}
	if data == nil {
		// An empty plaintext decrypts to nil, which callers read as a
		// status-only message: it's data, if empty.
		data = []byte{}
	}
	return data, sd.Status, nil
}

// send encrypts plaintext into a SessionData, with status 20 if
// terminate.
func send(cs *cipherState, plaintext []byte, terminate bool) ([]byte, error) {
	if plaintext == nil {
		return nil, fmt.Errorf("proximity: no message to encrypt")
	}
	ct, err := cs.encrypt(plaintext)
	if err != nil {
		return nil, err
	}
	var status *uint64
	if terminate {
		status = statusPtr(StatusSessionTermination)
	}
	return encodeSessionData(ct, status)
}
