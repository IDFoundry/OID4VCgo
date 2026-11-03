package proximity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"io"
	"slices"
)

const nfcDataType = "iso.org:18013:nfc"

// NFCDataParameters are classic NFC carrier APDU data-field limits, excluding
// APDU headers and status words: the command limit 255–65535 and the
// response limit 256–65536, as ISO/IEC 18013-5 (second edition) §11.2
// (NOTE 2) bounds them, since the mdoc supports short APDUs at least.
// Platforms must additionally apply their own limits.
type NFCDataParameters struct {
	MaxCommand  int
	MaxResponse int
}

// NewNFCDataDeviceSession constructs static NFC engagement for classic NFC-only
// retrieval (ISO/IEC 18013-5:2021 8.2.2.2 and 8.3.3.1.2). The native platform
// carries whole encrypted messages using DO53/ENVELOPE/GET RESPONSE.
//
// The first argument is unused: NFC-only engagement has no BLE UUID, and
// key generation always uses the crypto package's own source, as
// NewDeviceSession's does.
func NewNFCDataDeviceSession(_ io.Reader, parameters NFCDataParameters) (*DeviceSession, error) {
	if err := parameters.validate(); err != nil {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("proximity: NFC key: %w", err)
	}
	security, err := encodeEngagementSecurity(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	de, err := encMode.Marshal(deviceEngagement{Version: engagementVersion, Security: security})
	if err != nil {
		return nil, err
	}
	hs, err := encodeNFCDataSelect(de, parameters)
	if err != nil {
		return nil, err
	}
	handover, err := nfcHandover(hs, nil)
	if err != nil {
		return nil, err
	}
	s := newDeviceSession(key, nil, de, handover)
	s.handoverSelect = hs
	s.nfcDataParameters = &parameters
	return s, nil
}

func nfcDataPayload(parameters NFCDataParameters) []byte {
	payload := []byte{1}
	for i, n := range []int{parameters.MaxCommand, parameters.MaxResponse} {
		size := 1
		if n > 255 {
			size = 2
		}
		if n > 65535 {
			size = 3
		}
		payload = append(payload, byte(size+1), byte(i+1))
		for shift := (size - 1) * 8; shift >= 0; shift -= 8 {
			payload = append(payload, byte((n>>shift)&0xff))
		}
	}
	return payload
}

func encodeNFCDataSelect(de []byte, parameters NFCDataParameters) ([]byte, error) {
	ac, err := encodeNDEF([]ndefRecord{{tnf: 1, typ: []byte("ac"), payload: []byte{1, 3, 'n', 'f', 'c', 1, 4, 'm', 'd', 'o', 'c'}}})
	if err != nil {
		return nil, err
	}
	return encodeNDEF([]ndefRecord{
		{tnf: 1, typ: []byte("Hs"), payload: append([]byte{0x15}, ac...)},
		{tnf: 4, typ: []byte(nfcDataType), id: []byte("nfc"), payload: nfcDataPayload(parameters)},
		{tnf: 4, typ: []byte(nfcDeviceEngagementType), id: []byte("mdoc"), payload: de},
	})
}

func (p NFCDataParameters) validate() error {
	if p.MaxCommand < 255 || p.MaxCommand > 65535 || p.MaxResponse < 256 || p.MaxResponse > 65536 {
		return fmt.Errorf("proximity: invalid NFC APDU data-field limits")
	}
	return nil
}

// ParseNFCDataHandover validates a static Hs and returns its classic NFC carrier
// limits. It rejects missing, duplicate, truncated and unsupported fields.
func ParseNFCDataHandover(hs []byte) (NFCDataParameters, error) {
	_, carriers, err := parseNFCCarriers(hs)
	if err != nil {
		return NFCDataParameters{}, err
	}
	return parseNFCDataCarriers(carriers, true)
}

// parseNFCDataCarriers finds the one classic NFC carrier among carriers
// and parses its fields. An mdoc's (limits) must carry both data-field
// limits; a reader's needn't, since ISO/IEC 18013-5 (second edition)
// §9.2.2 Table 1 has the reader not use them, and any it sends are
// parsed and ignored.
func parseNFCDataCarriers(carriers []ndefRecord, limits bool) (NFCDataParameters, error) {
	var selected *NFCDataParameters
	for _, carrier := range carriers {
		if carrier.tnf != 4 || string(carrier.typ) != nfcDataType {
			continue
		}
		if selected != nil {
			return NFCDataParameters{}, fmt.Errorf("proximity: duplicate NFC data carrier")
		}
		b := carrier.payload
		p := NFCDataParameters{}
		if len(b) == 0 || b[0] != 1 {
			return p, fmt.Errorf("proximity: unsupported NFC data carrier version")
		}
		b = b[1:]
		for len(b) > 0 {
			if len(b) < 3 || int(b[0]) > len(b)-1 || b[0] < 2 || b[0] > 4 {
				return p, fmt.Errorf("proximity: invalid NFC data field")
			}
			n := 0
			for _, v := range b[2 : 1+int(b[0])] {
				n = n*256 + int(v)
			}
			switch b[1] {
			case 1:
				if p.MaxCommand != 0 || b[0] > 3 {
					return p, fmt.Errorf("proximity: invalid NFC command limit")
				}
				p.MaxCommand = n
			case 2:
				if p.MaxResponse != 0 {
					return p, fmt.Errorf("proximity: duplicate NFC response limit")
				}
				p.MaxResponse = n
			default:
				return p, fmt.Errorf("proximity: unsupported NFC data field")
			}
			b = b[1+int(b[0]):]
		}
		if !limits {
			p = NFCDataParameters{}
		} else if err := p.validate(); err != nil {
			return p, err
		}
		selected = &p
	}
	if selected == nil {
		return NFCDataParameters{}, fmt.Errorf("proximity: no classic NFC data carrier")
	}
	return *selected, nil
}

// NewNFCDataReaderSession binds a validated static NFC data handover to the
// existing session cryptography and reader authentication/trust configuration.
func NewNFCDataReaderSession(hs []byte, opts ...ReaderOption) (*ReaderSession, error) {
	return newNFCDataReaderSession(hs, nil, opts...)
}

func newNFCDataReaderSession(hs, hr []byte, opts ...ReaderOption) (*ReaderSession, error) {
	if _, err := ParseNFCDataHandover(hs); err != nil {
		return nil, err
	}
	de, _, err := parseNFCCarriers(hs)
	if err != nil {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	handover, err := nfcHandover(hs, hr)
	if err != nil {
		return nil, err
	}
	r, err := newReaderSession(key, slices.Clone(de), handover)
	if err != nil {
		return nil, err
	}
	var cfg readerConfig
	for _, opt := range opts {
		opt(&cfg)
	}
	if err := configureReader(r, cfg); err != nil {
		return nil, err
	}
	return r, nil
}

// NewNFCNegotiatedDataDeviceSession prepares classic NFC-only retrieval via TNEP.
func NewNFCNegotiatedDataDeviceSession(random io.Reader, parameters NFCDataParameters) (*DeviceSession, error) {
	s, err := NewNFCDataDeviceSession(random, parameters)
	if err != nil {
		return nil, err
	}
	s.nfcNegotiated = true
	s.handoverSelect, s.handover = nil, nil
	return s, nil
}

func (s *DeviceSession) handleNFCDataRequest(hr []byte) ([]byte, error) {
	carriers, err := parseNFCRequestCarriers(hr)
	if err != nil {
		return nil, err
	}
	// The reader offers classic NFC; the limits are the mdoc's own.
	if _, err := parseNFCDataCarriers(carriers, false); err != nil {
		return nil, err
	}
	hs, err := encodeNFCDataSelect(s.deviceEngagement, *s.nfcDataParameters)
	if err != nil {
		return nil, err
	}
	handover, err := nfcHandover(hs, hr)
	if err != nil {
		return nil, err
	}
	s.handoverSelect, s.handover, s.nfcHandoverRequest = hs, handover, slices.Clone(hr)
	return s.HandoverSelect(), nil
}

// NewNFCNegotiatedDataReaderSession checks the Hr offered classic NFC and the
// Hs selected it with the mdoc's limits, and binds both original NDEF
// messages to the transcript. The reader then keeps to the mdoc's limits
// (ParseNFCDataHandover).
func NewNFCNegotiatedDataReaderSession(hs, hr []byte, opts ...ReaderOption) (*ReaderSession, error) {
	carriers, err := parseNFCRequestCarriers(hr)
	if err != nil {
		return nil, err
	}
	if _, err := parseNFCDataCarriers(carriers, false); err != nil {
		return nil, err
	}
	return newNFCDataReaderSession(hs, hr, opts...)
}

// NewNFCHandoverRequestWithNFCData offers classic NFC in addition to the BLE
// modes. The resulting original Hr must be retained until session construction.
//
// The NFC carrier carries its version alone: ISO/IEC 18013-5 (second
// edition) §9.2.2 Table 1 has the data-field limits be the mdoc's, not
// the reader's. parameters is
// still checked, as the reader's own limits, but isn't sent; the reader
// passes its controller's limit to the exchanges instead (nfcapdu.Transact).
func NewNFCHandoverRequestWithNFCData(random io.Reader, parameters NFCDataParameters, modes ...BLEMode) ([]byte, error) {
	if err := parameters.validate(); err != nil {
		return nil, err
	}
	hr, err := NewNFCHandoverRequest(random, modes...)
	if err != nil {
		return nil, err
	}
	records, err := parseNDEF(hr)
	if err != nil {
		return nil, err
	}
	embedded, err := parseNDEF(records[0].payload[1:])
	if err != nil {
		return nil, err
	}
	embedded = append(embedded, ndefRecord{tnf: 1, typ: []byte("ac"), payload: []byte{1, 3, 'n', 'f', 'c', 0}})
	encoded, err := encodeNDEF(embedded)
	if err != nil {
		return nil, err
	}
	records[0].payload = append([]byte{0x15}, encoded...)
	records = append(records, ndefRecord{tnf: 4, typ: []byte(nfcDataType), id: []byte("nfc"), payload: []byte{1}})
	result, err := encodeNDEF(records)
	if err != nil {
		return nil, err
	}
	return result, nil
}
