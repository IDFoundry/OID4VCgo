package proximity

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"io"
	"slices"

	"github.com/fxamacker/cbor/v2"
)

const (
	nfcDeviceEngagementType = "iso.org:18013:deviceengagement"
	nfcBLEType              = "application/vnd.bluetooth.le.oob"
)

// NewNFCDeviceSession creates a static NFC engagement (ISO/IEC 18013-5
// 8.2.2.1), followed by BLE retrieval. HandoverSelect supplies the NDEF
// file content to the platform's Type 4 tag service. Repeated reads
// must use that same session until it is closed. No NFC transport is
// implemented here. The offered BLE roles share one UUID for static
// handover (8.3.3.1.1.2), unlike QR's distinct UUIDs.
func NewNFCDeviceSession(random io.Reader, opts ...DeviceOption) (*DeviceSession, error) {
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
	uuid, err := randomUUID(random)
	if err != nil {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("proximity: generate EDeviceKey: %w", err)
	}
	security, err := encodeEngagementSecurity(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	de, err := encMode.Marshal(deviceEngagement{Version: engagementVersion, Security: security})
	if err != nil {
		return nil, fmt.Errorf("proximity: encode NFC DeviceEngagement: %w", err)
	}
	role := byte(0)
	if central {
		role = 1
	}
	if central && peripheral {
		role = 3
	}
	hs, err := encodeNFCSelect(de, role, uuid)
	if err != nil {
		return nil, err
	}
	handover, err := encMode.Marshal([]any{hs, nil})
	if err != nil {
		return nil, err
	}
	s := newDeviceSession(key, uuid, de, handover)
	s.handoverSelect = hs
	if peripheral {
		s.peripheralUUID = slices.Clone(uuid)
	}
	if central {
		s.centralUUID = slices.Clone(uuid)
	}
	pe, err := parseDeviceEngagement(de)
	if err != nil {
		return nil, err
	}
	s.bleIdent = bleIdent(pe.eDeviceKeyBytes)
	return s, nil
}

// HandoverSelect returns a copy of this session's static NFC NDEF
// message, without Type 4 NLEN. It is nil for QR sessions. Returning a
// copy prevents a platform reader from changing the session transcript.
func (s *DeviceSession) HandoverSelect() []byte { return slices.Clone(s.handoverSelect) }

// NewNFCReaderSession reads a static NFC Handover Select message (no
// NLEN prefix), selects a BLE carrier, and applies the same reader
// options and trust policy as NewReaderSession. The exact received
// bytes, rather than a re-encoding, enter the session transcript.
func NewNFCReaderSession(hs []byte, opts ...ReaderOption) (*ReaderSession, error) {
	return newNFCReaderSession(hs, nil, opts...)
}

func newNFCReaderSession(hs, hr []byte, opts ...ReaderOption) (*ReaderSession, error) {
	de, mode, uuid, err := parseNFCSelectWithRequest(hs, hr)
	if err != nil {
		return nil, err
	}
	handover, err := nfcHandover(hs, hr)
	if err != nil {
		return nil, err
	}
	r, err := newReaderSession(nil, slices.Clone(de), handover)
	if err != nil {
		return nil, err
	}
	r.engagement.ble, r.engagement.bleMode, r.engagement.uuid = true, mode, slices.Clone(uuid)
	var cfg readerConfig
	for _, opt := range opts {
		opt(&cfg)
	}
	if err := configureReader(r, cfg); err != nil {
		return nil, err
	}
	return r, nil
}

func parseNFCSelect(hs []byte) (de []byte, mode BLEMode, uuid []byte, err error) {
	return parseNFCSelectWithRequest(hs, nil)
}

func parseNFCSelectWithRequest(hs, hr []byte) (de []byte, mode BLEMode, uuid []byte, err error) {
	var offers []nfcBLEOffer
	if hr != nil {
		offers, err = parseNFCRequest(hr)
		if err != nil {
			return nil, 0, nil, err
		}
	}
	de, carriers, err := parseNFCCarriers(hs)
	if err != nil {
		return nil, 0, nil, err
	}
	for _, carrier := range carriers {
		if carrier.tnf != 2 || string(carrier.typ) != nfcBLEType {
			continue
		}
		m, u, e := selectNFCBLE(carrier.payload, offers)
		if e != nil {
			return nil, 0, nil, e
		}
		if uuid == nil {
			mode, uuid = m, u
		}
	}
	if uuid == nil {
		return nil, 0, nil, fmt.Errorf("proximity: NFC handover: no supported BLE carrier")
	}
	return de, mode, uuid, nil
}

func parseNFCCarriers(hs []byte) (de []byte, carriers []ndefRecord, err error) {
	invalid := func(reason string) ([]byte, []ndefRecord, error) {
		return nil, nil, fmt.Errorf("proximity: NFC handover: %s", reason)
	}
	records, err := parseNDEF(hs)
	if err != nil {
		return nil, nil, err
	}
	first := records[0]
	if first.tnf != 1 || string(first.typ) != "Hs" || len(first.payload) < 2 || first.payload[0] != 0x15 {
		return invalid("missing Hs version 1.5")
	}
	byID := map[string]ndefRecord{}
	for i, r := range records {
		if i > 0 && r.tnf == 1 && string(r.typ) == "Hs" {
			return invalid("duplicate Hs record")
		}
		if len(r.id) != 0 {
			if _, exists := byID[string(r.id)]; exists {
				return invalid("duplicate record ID")
			}
			byID[string(r.id)] = r
		}
		if r.tnf == 4 && string(r.typ) == nfcDeviceEngagementType {
			if de != nil || string(r.id) != "mdoc" {
				return invalid("duplicate or incorrectly identified DeviceEngagement")
			}
			de = r.payload
		}
	}
	if de == nil {
		return invalid("missing DeviceEngagement")
	}
	var engagement map[int]cbor.RawMessage
	if err := decMode.Unmarshal(de, &engagement); err != nil {
		return invalid("invalid DeviceEngagement")
	}
	if _, hasRetrieval := engagement[2]; hasRetrieval {
		return invalid("NFC DeviceEngagement contains retrieval methods")
	}
	if _, err := parseDeviceEngagement(de); err != nil {
		return nil, nil, err
	}
	acs, err := parseNDEF(first.payload[1:])
	if err != nil {
		return nil, nil, err
	}
	seen := map[string]bool{}
	for _, ac := range acs {
		if ac.tnf != 1 || string(ac.typ) != "ac" {
			return invalid("unexpected embedded Hs record")
		}
		carrierID, auxIDs, err := parseAlternativeCarrier(ac.payload)
		if err != nil {
			return nil, nil, err
		}
		if seen[carrierID] {
			return invalid("duplicate alternative carrier")
		}
		seen[carrierID] = true
		carrier, exists := byID[carrierID]
		if !exists {
			return invalid("dangling carrier reference")
		}
		hasEngagement := false
		for _, id := range auxIDs {
			if _, exists := byID[id]; !exists {
				return invalid("dangling auxiliary reference")
			}
			if id == "mdoc" {
				hasEngagement = true
			}
		}
		if !hasEngagement && ((carrier.tnf == 2 && string(carrier.typ) == nfcBLEType) || (carrier.tnf == 4 && string(carrier.typ) == nfcDataType)) {
			return invalid("carrier does not reference DeviceEngagement")
		}
		carriers = append(carriers, carrier)
	}
	return de, carriers, nil
}

func parseAlternativeCarrier(b []byte) (string, []string, error) {
	bad := func() (string, []string, error) {
		return "", nil, fmt.Errorf("proximity: malformed alternative carrier")
	}
	if len(b) < 4 || b[0]&0xfc != 0 {
		return bad()
	}
	n := int(b[1])
	if n == 0 || n > len(b)-3 {
		return bad()
	}
	id := string(b[2 : 2+n])
	pos := 2 + n
	count := int(b[pos])
	pos++
	var aux []string
	seen := map[string]bool{id: true}
	for i := 0; i < count; i++ {
		if pos == len(b) {
			return bad()
		}
		size := int(b[pos])
		pos++
		if size == 0 || size > len(b)-pos {
			return bad()
		}
		ref := string(b[pos : pos+size])
		pos += size
		if seen[ref] {
			return bad()
		}
		seen[ref] = true
		aux = append(aux, ref)
	}
	if pos != len(b) {
		return bad()
	}
	return id, aux, nil
}

func readNFCBLE(b []byte) (int, []byte, error) {
	role := -1
	var uuid []byte
	for pos := 0; pos < len(b); {
		size := int(b[pos])
		pos++
		if size < 1 || size > len(b)-pos {
			return 0, nil, fmt.Errorf("proximity: malformed BLE OOB field")
		}
		typ, value := b[pos], b[pos+1:pos+size]
		pos += size
		switch typ {
		case 0x1c:
			if role != -1 || len(value) != 1 || value[0] > 3 {
				return 0, nil, fmt.Errorf("proximity: invalid BLE LE Role")
			}
			role = int(value[0])
		case 6, 7:
			if uuid != nil || len(value) != 16 {
				return 0, nil, fmt.Errorf("proximity: invalid BLE service UUID")
			}
			uuid = slices.Clone(value)
			slices.Reverse(uuid)
		}
	}
	if role < 0 || (uuid != nil && bytes.Equal(uuid, make([]byte, 16))) {
		return 0, nil, fmt.Errorf("proximity: incomplete BLE carrier")
	}
	return role, uuid, nil
}
