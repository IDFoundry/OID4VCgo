// Package proximitytest is test support for ISO/IEC 18013-5 device
// retrieval: it plays the reader's side of session establishment so
// tests can send a holder any DeviceRequest, including ones package
// proximity's reader wouldn't build. It is for tests only; no shipped
// code imports it.
package proximitytest

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/fxamacker/cbor/v2"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/internal/hkdf"
)

// Tagged is #6.24(bstr .cbor b): b, already-encoded CBOR, wrapped.
func Tagged(b []byte) ([]byte, error) {
	return cbor.Marshal(cbor.Tag{Number: 24, Content: b})
}

// SessionEstablishment is a reader's SessionEstablishment for the
// holder showing qr ("mdoc:" and its DeviceEngagement), with a fresh
// ephemeral reader key: build is called with the session's
// SessionTranscriptBytes (#6.24(bstr .cbor [DeviceEngagementBytes,
// EReaderKeyBytes, null]), a QR handover) and returns the DeviceRequest
// to send, which is encrypted under SKReader as the session's first
// message (§9.1.1.5).
func SessionEstablishment(qr string, build func(sessionTranscriptBytes []byte) ([]byte, error)) ([]byte, error) {
	de, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(qr, "mdoc:"))
	if err != nil {
		return nil, fmt.Errorf("proximitytest: QR code: %w", err)
	}
	var deMap map[int]cbor.RawMessage
	var security []cbor.RawMessage
	var keyTag cbor.Tag
	var deviceKey mdoc.CoseKey
	if cbor.Unmarshal(de, &deMap) != nil || cbor.Unmarshal(deMap[1], &security) != nil || len(security) < 2 ||
		cbor.Unmarshal(security[1], &keyTag) != nil {
		return nil, errors.New("proximitytest: decode the device engagement")
	}
	keyBytes, ok := keyTag.Content.([]byte)
	if !ok || cbor.Unmarshal(keyBytes, &deviceKey) != nil {
		return nil, errors.New("proximitytest: decode EDeviceKey")
	}
	pub, err := deviceKey.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("proximitytest: EDeviceKey: %w", err)
	}
	devicePub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("proximitytest: EDeviceKey isn't an EC key")
	}
	eReader, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	readerKey, err := mdoc.NewCoseKey(&eReader.PublicKey)
	if err != nil {
		return nil, err
	}
	readerKeyBytes, err := cbor.Marshal(readerKey)
	if err != nil {
		return nil, err
	}
	deBytes, err := Tagged(de)
	if err != nil {
		return nil, err
	}
	eReaderKeyBytes, err := Tagged(readerKeyBytes)
	if err != nil {
		return nil, err
	}
	transcript, err := cbor.Marshal([]cbor.RawMessage{deBytes, eReaderKeyBytes, {0xf6}})
	if err != nil {
		return nil, err
	}
	transcriptBytes, err := Tagged(transcript)
	if err != nil {
		return nil, err
	}

	a, err := eReader.ECDH()
	if err != nil {
		return nil, err
	}
	b, err := devicePub.ECDH()
	if err != nil {
		return nil, err
	}
	z, err := a.ECDH(b)
	if err != nil {
		return nil, err
	}
	salt := sha256.Sum256(transcriptBytes)
	skReader, err := hkdf.Key(salt[:], z, []byte("SKReader"), 32)
	if err != nil {
		return nil, err
	}

	req, err := build(transcriptBytes)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(skReader)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	// The reader's first message: identifier 0, counter 1 (§9.1.1.5).
	nonce := make([]byte, 12)
	nonce[11] = 1
	return cbor.Marshal(map[string]any{"eReaderKey": cbor.RawMessage(eReaderKeyBytes), "data": gcm.Seal(nil, nonce, req, nil)})
}
