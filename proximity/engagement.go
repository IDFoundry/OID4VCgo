package proximity

import (
	"crypto/ecdsa"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/fxamacker/cbor/v2"

	"github.com/idfoundry/oid4vcgo/internal/hkdf"
)

// engagementVersion is the DeviceEngagement version this package
// writes (§8.2.1.1). It reads any 1.x.
const engagementVersion = "1.0"

// cipherSuite1 is the only cipher suite ISO/IEC 18013-5 defines
// (§9.1.5.2): ECDH over P-256, HKDF-SHA256, AES-256-GCM.
const cipherSuite1 = 1

// qrScheme prefixes a QR code's DeviceEngagement (§8.2.2.3).
const qrScheme = "mdoc:"

// Device retrieval method type and version for BLE (§8.2.1.1 Table 4).
const (
	retrievalTypeBLE    = 2
	retrievalVersionBLE = 1
)

// BLEMode selects which BLE role the mdoc offers in its engagement
// (§8.3.3.1.1).
type BLEMode int

const (
	// PeripheralServer is mdoc peripheral server mode: the mdoc
	// advertises the service UUID and the reader connects as central.
	// The default.
	PeripheralServer BLEMode = iota
	// CentralClient is mdoc central client mode: the reader advertises
	// the service UUID and the mdoc connects to it.
	CentralClient
)

func (m BLEMode) String() string {
	switch m {
	case PeripheralServer:
		return "peripheral server"
	case CentralClient:
		return "central client"
	default:
		return fmt.Sprintf("BLEMode(%d)", int(m))
	}
}

// deviceEngagement is §8.2.1.1's DeviceEngagement. Later members (5
// originInfos, 6 capabilities, from version 1.1) are ignored when read.
type deviceEngagement struct {
	Version          string            `cbor:"0,keyasint"`
	Security         cbor.RawMessage   `cbor:"1,keyasint"`
	RetrievalMethods []cbor.RawMessage `cbor:"2,keyasint,omitempty"`
}

// bleOptions is §8.2.1.1's BleOptions.
type bleOptions struct {
	PeripheralServer bool   `cbor:"0,keyasint"`
	CentralClient    bool   `cbor:"1,keyasint"`
	PeripheralUUID   []byte `cbor:"10,keyasint,omitempty"`
	CentralUUID      []byte `cbor:"11,keyasint,omitempty"`
}

// encodeDeviceEngagement builds the DeviceEngagement for a QR code: the
// mdoc's ephemeral key and one BLE retrieval method offering each mode
// that has a UUID: peripheralUUID for mdoc peripheral server mode,
// centralUUID for mdoc central client mode (§8.3.3.1.1.2: one UUID per
// mode offered).
func encodeDeviceEngagement(eDeviceKey *ecdsa.PublicKey, peripheralUUID, centralUUID []byte) ([]byte, error) {
	if peripheralUUID == nil && centralUUID == nil {
		return nil, fmt.Errorf("proximity: no BLE mode offered")
	}
	coseKey, err := encodeCoseKey(eDeviceKey)
	if err != nil {
		return nil, err
	}
	eDeviceKeyBytes, err := wrapTag24(coseKey)
	if err != nil {
		return nil, fmt.Errorf("proximity: encode EDeviceKeyBytes: %w", err)
	}
	security, err := encMode.Marshal([]any{cipherSuite1, cbor.RawMessage(eDeviceKeyBytes)})
	if err != nil {
		return nil, fmt.Errorf("proximity: encode Security: %w", err)
	}

	opts := bleOptions{
		PeripheralServer: peripheralUUID != nil, PeripheralUUID: peripheralUUID,
		CentralClient: centralUUID != nil, CentralUUID: centralUUID,
	}
	method, err := encMode.Marshal([]any{retrievalTypeBLE, retrievalVersionBLE, opts})
	if err != nil {
		return nil, fmt.Errorf("proximity: encode DeviceRetrievalMethod: %w", err)
	}

	b, err := encMode.Marshal(deviceEngagement{
		Version:          engagementVersion,
		Security:         security,
		RetrievalMethods: []cbor.RawMessage{method},
	})
	if err != nil {
		return nil, fmt.Errorf("proximity: encode DeviceEngagement: %w", err)
	}
	return b, nil
}

// parsedEngagement is what a reader needs from a DeviceEngagement.
type parsedEngagement struct {
	eDeviceKey *ecdsa.PublicKey
	// eDeviceKeyBytes is EDeviceKeyBytes as sent: #6.24(bstr .cbor
	// COSE_Key).
	eDeviceKeyBytes []byte
	// ble is false when the engagement offers no BLE retrieval method
	// (Annex D's NFC engagement carries none).
	ble     bool
	bleMode BLEMode
	uuid    []byte
}

// parseDeviceEngagement decodes b as a DeviceEngagement: version 1.x,
// cipher suite 1 with a P-256 EDeviceKey, and the first BLE retrieval
// method that offers a mode with a 16-byte UUID, preferring mdoc
// central client mode when both are offered.
func parseDeviceEngagement(b []byte) (parsedEngagement, error) {
	if len(b) > MaxMessageBytes {
		return parsedEngagement{}, fmt.Errorf("proximity: DeviceEngagement is %d bytes, over %d: %w", len(b), MaxMessageBytes, ErrCBORDecoding)
	}
	var de deviceEngagement
	if err := decMode.Unmarshal(b, &de); err != nil {
		return parsedEngagement{}, fmt.Errorf("proximity: decode DeviceEngagement: %w: %w", ErrCBORDecoding, err)
	}
	if !strings.HasPrefix(de.Version, "1.") {
		return parsedEngagement{}, fmt.Errorf("proximity: DeviceEngagement version %q, want 1.x", de.Version)
	}

	var security []cbor.RawMessage
	if err := decMode.Unmarshal(de.Security, &security); err != nil || len(security) != 2 {
		return parsedEngagement{}, fmt.Errorf("proximity: Security is not a 2-member array: %w", ErrCBORDecoding)
	}
	var suite int64
	if err := decMode.Unmarshal(security[0], &suite); err != nil {
		return parsedEngagement{}, fmt.Errorf("proximity: decode cipher suite: %w: %w", ErrCBORDecoding, err)
	}
	if suite != cipherSuite1 {
		return parsedEngagement{}, fmt.Errorf("proximity: cipher suite %d, want %d", suite, cipherSuite1)
	}
	coseKey, err := unwrapTag24(security[1])
	if err != nil {
		return parsedEngagement{}, fmt.Errorf("proximity: decode EDeviceKeyBytes: %w: %w", ErrCBORDecoding, err)
	}
	eDeviceKey, err := decodeCoseKey(coseKey)
	if err != nil {
		return parsedEngagement{}, fmt.Errorf("proximity: EDeviceKey: %w", err)
	}

	pe := parsedEngagement{eDeviceKey: eDeviceKey, eDeviceKeyBytes: []byte(security[1])}
	for _, raw := range de.RetrievalMethods {
		var method []cbor.RawMessage
		if err := decMode.Unmarshal(raw, &method); err != nil || len(method) < 3 {
			return parsedEngagement{}, fmt.Errorf("proximity: decode DeviceRetrievalMethod: %w", ErrCBORDecoding)
		}
		var typ int64
		if err := decMode.Unmarshal(method[0], &typ); err != nil {
			return parsedEngagement{}, fmt.Errorf("proximity: decode DeviceRetrievalMethod type: %w: %w", ErrCBORDecoding, err)
		}
		if typ != retrievalTypeBLE {
			continue
		}
		var opts bleOptions
		if err := decMode.Unmarshal(method[2], &opts); err != nil {
			return parsedEngagement{}, fmt.Errorf("proximity: decode BleOptions: %w: %w", ErrCBORDecoding, err)
		}
		// §8.3.3.1.1.1: when the mdoc supports both modes, the reader
		// should select mdoc central client mode.
		switch {
		case opts.CentralClient && len(opts.CentralUUID) == 16:
			pe.ble, pe.bleMode, pe.uuid = true, CentralClient, opts.CentralUUID
		case opts.PeripheralServer && len(opts.PeripheralUUID) == 16:
			pe.ble, pe.bleMode, pe.uuid = true, PeripheralServer, opts.PeripheralUUID
		default:
			continue
		}
		break
	}
	return pe, nil
}

// encodeQR is §8.2.2.3's QR code payload.
func encodeQR(deviceEngagement []byte) string {
	return qrScheme + base64.RawURLEncoding.EncodeToString(deviceEngagement)
}

// decodeQR reverses encodeQR. The scheme is matched case-insensitively,
// since QR alphanumeric mode upper-cases it.
func decodeQR(qr string) ([]byte, error) {
	if len(qr) < len(qrScheme) || !strings.EqualFold(qr[:len(qrScheme)], qrScheme) {
		return nil, fmt.Errorf("proximity: QR code does not start with %q", qrScheme)
	}
	payload := qr[len(qrScheme):]
	if base64.RawURLEncoding.DecodedLen(len(payload)) > MaxMessageBytes {
		return nil, fmt.Errorf("proximity: QR code payload over %d bytes: %w", MaxMessageBytes, ErrCBORDecoding)
	}
	b, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return nil, fmt.Errorf("proximity: decode QR code: %w", err)
	}
	return b, nil
}

// formatUUID formats a 16-byte UUID in its canonical 8-4-4-4-12 form.
func formatUUID(u []byte) string {
	if len(u) != 16 {
		return ""
	}
	return fmt.Sprintf("%x-%x-%x-%x-%x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:16])
}

// bleIdent is the BLE Ident characteristic's value (§8.3.3.1.1):
// HKDF-SHA256 with EDeviceKeyBytes as IKM, no salt, info "BLEIdent",
// 16 bytes. Only mdoc central client mode uses it: the reader, as GATT
// server, serves it, and the mdoc reads it to check it connected to
// the reader that scanned its QR code.
func bleIdent(eDeviceKeyBytes []byte) []byte {
	ident, err := hkdf.Key(nil, eDeviceKeyBytes, []byte("BLEIdent"), 16)
	if err != nil {
		panic("proximity: derive BLE Ident: " + err.Error())
	}
	return ident
}
