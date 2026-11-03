package proximity

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"slices"
)

type nfcBLEOffer struct {
	mode BLEMode // mdoc role; the reader's LE Role is its complement.
	uuid []byte  // supplied by the reader when it can be the peripheral.
}

func nfcHandover(hs, hr []byte) ([]byte, error) {
	if hr == nil {
		return encMode.Marshal([]any{hs, nil})
	}
	return encMode.Marshal([]any{hs, hr})
}

func nfcBLEPayload(role byte, uuid []byte) []byte {
	b := []byte{2, 0x1c, role}
	if len(uuid) != 0 {
		b = append(b, 17, 7)
		for i := len(uuid) - 1; i >= 0; i-- {
			b = append(b, uuid[i])
		}
	}
	return b
}

func encodeNFCSelect(de []byte, role byte, uuid []byte) ([]byte, error) {
	ac, err := encodeNDEF([]ndefRecord{{tnf: 1, typ: []byte("ac"), payload: []byte{1, 1, '0', 1, 4, 'm', 'd', 'o', 'c'}}})
	if err != nil {
		return nil, err
	}
	return encodeNDEF([]ndefRecord{
		{tnf: 1, typ: []byte("Hs"), payload: append([]byte{0x15}, ac...)},
		{tnf: 2, typ: []byte(nfcBLEType), id: []byte("0"), payload: nfcBLEPayload(role, uuid)},
		{tnf: 4, typ: []byte(nfcDeviceEngagementType), id: []byte("mdoc"), payload: de},
	})
}

// NewNFCNegotiatedDeviceSession prepares the holder's key and supported
// BLE modes, but no session transcript is usable until a complete Hr
// has been accepted by HandleHandoverRequest. The platform implements
// TNEP and passes complete NDEF messages to that method.
func NewNFCNegotiatedDeviceSession(random io.Reader, opts ...DeviceOption) (*DeviceSession, error) {
	s, err := NewNFCDeviceSession(random, opts...)
	if err != nil {
		return nil, err
	}
	s.nfcNegotiated = true
	s.handoverSelect = nil
	s.handover = nil
	return s, nil
}

// HandleHandoverRequest selects a supported BLE mode from the reader's
// complete Hr NDEF message. A repeated identical request returns the
// same Hs; a different request cannot replace an accepted transcript.
// This method, like DeviceSession, is not safe for concurrent calls.
func (s *DeviceSession) HandleHandoverRequest(hr []byte) ([]byte, error) {
	if s.closed {
		return nil, ErrSessionClosed
	}
	if !s.nfcNegotiated || s.cipher != nil {
		return nil, fmt.Errorf("proximity: not awaiting negotiated NFC handover")
	}
	if s.nfcHandoverRequest != nil {
		if !bytes.Equal(s.nfcHandoverRequest, hr) {
			return nil, fmt.Errorf("proximity: NFC handover is already selected")
		}
		return s.HandoverSelect(), nil
	}
	if s.nfcDataParameters != nil {
		return s.handleNFCDataRequest(hr)
	}
	offers, err := parseNFCRequest(hr)
	if err != nil {
		return nil, err
	}
	for _, offer := range offers {
		var uuid, wireUUID []byte
		role := byte(0)
		switch {
		case offer.mode == CentralClient && s.centralUUID != nil:
			uuid = offer.uuid
			role = 1 // central UUID comes from Hr, not Hs.
		case offer.mode == PeripheralServer && s.peripheralUUID != nil:
			uuid = s.peripheralUUID
			wireUUID = uuid
		default:
			continue
		}
		hs, err := encodeNFCSelect(s.deviceEngagement, role, wireUUID)
		if err != nil {
			return nil, err
		}
		handover, err := nfcHandover(hs, hr)
		if err != nil {
			return nil, err
		}
		s.uuid = slices.Clone(uuid)
		s.peripheralUUID, s.centralUUID = nil, nil
		if offer.mode == CentralClient {
			s.centralUUID = slices.Clone(uuid)
		} else {
			s.peripheralUUID = slices.Clone(uuid)
		}
		s.handoverSelect = hs
		s.handover = handover
		s.nfcHandoverRequest = slices.Clone(hr)
		return s.HandoverSelect(), nil
	}
	return nil, fmt.Errorf("proximity: no mutually supported NFC BLE role")
}

// NewNFCHandoverRequest encodes the reader's Hr NDEF message for the
// supported mdoc modes. The reader's actual LE Role is complementary.
// Keep the exact bytes until NewNFCNegotiatedReaderSession is called.
func NewNFCHandoverRequest(random io.Reader, modes ...BLEMode) ([]byte, error) {
	if len(modes) == 0 {
		modes = []BLEMode{PeripheralServer, CentralClient}
	}
	peripheral, central, err := offeredModes(modes)
	if err != nil {
		return nil, err
	}
	if random == nil {
		random = rand.Reader
	}
	cr := make([]byte, 2)
	if _, err := io.ReadFull(random, cr); err != nil {
		return nil, fmt.Errorf("proximity: collision resolution: %w", err)
	}
	role := byte(1) // reader central, mdoc peripheral.
	var uuid []byte
	if central {
		role = 0
		uuid, err = randomUUID(random)
		if err != nil {
			return nil, err
		}
	}
	if peripheral && central {
		role = 2
	}
	embedded, err := encodeNDEF([]ndefRecord{
		{tnf: 1, typ: []byte("cr"), payload: cr},
		{tnf: 1, typ: []byte("ac"), payload: []byte{1, 1, '0', 0}},
	})
	if err != nil {
		return nil, err
	}
	return encodeNDEF([]ndefRecord{
		{tnf: 1, typ: []byte("Hr"), payload: append([]byte{0x15}, embedded...)},
		{tnf: 2, typ: []byte(nfcBLEType), id: []byte("0"), payload: nfcBLEPayload(role, uuid)},
	})
}

// NewNFCNegotiatedReaderSession binds the exact Hs and Hr messages into
// the transcript and checks the selection against what the reader offered.
func NewNFCNegotiatedReaderSession(hs, hr []byte, opts ...ReaderOption) (*ReaderSession, error) {
	if len(hr) == 0 {
		return nil, fmt.Errorf("proximity: negotiated NFC needs Handover Request")
	}
	return newNFCReaderSession(hs, hr, opts...)
}

func selectNFCBLE(payload []byte, offers []nfcBLEOffer) (BLEMode, []byte, error) {
	role, uuid, err := readNFCBLE(payload)
	if err != nil {
		return 0, nil, err
	}
	// LE Role 0 is peripheral only (mdoc peripheral server mode), 1 central
	// only. 2 and 3 offer both, preferring one; the reader takes mdoc
	// central client mode either way, as ISO/IEC 18013-5 (second edition)
	// §11.1.3.1 says it should when the mdoc supports both.
	mode := CentralClient
	if role == 0 {
		mode = PeripheralServer
	}
	if offers == nil {
		if uuid == nil {
			return 0, nil, fmt.Errorf("proximity: static NFC BLE carrier has no UUID")
		}
		return mode, uuid, nil
	}
	if role > 1 {
		return 0, nil, fmt.Errorf("proximity: ambiguous negotiated BLE selection")
	}
	for _, offer := range offers {
		if offer.mode != mode {
			continue
		}
		if mode == CentralClient {
			if uuid != nil {
				return 0, nil, fmt.Errorf("proximity: negotiated central-client UUID must come from Hr")
			}
			return mode, offer.uuid, nil
		}
		if uuid != nil {
			return mode, uuid, nil
		}
	}
	return 0, nil, fmt.Errorf("proximity: NFC selection was not offered or has no UUID")
}

func parseNFCRequest(hr []byte) ([]nfcBLEOffer, error) {
	carriers, err := parseNFCRequestCarriers(hr)
	if err != nil {
		return nil, err
	}
	var offers []nfcBLEOffer
	for _, carrier := range carriers {
		if carrier.tnf != 2 || string(carrier.typ) != nfcBLEType {
			continue
		}
		role, uuid, err := readNFCBLE(carrier.payload)
		if err != nil {
			return nil, err
		}
		if role == 3 {
			if uuid == nil {
				return nil, fmt.Errorf("proximity: reader peripheral role requires UUID")
			}
			offers = append(offers, nfcBLEOffer{mode: PeripheralServer}, nfcBLEOffer{CentralClient, uuid})
			continue
		}
		if role != 1 {
			if uuid == nil {
				return nil, fmt.Errorf("proximity: reader peripheral role requires UUID")
			}
			offers = append(offers, nfcBLEOffer{CentralClient, uuid})
		}
		if role != 0 {
			offers = append(offers, nfcBLEOffer{mode: PeripheralServer})
		}
	}
	if len(offers) == 0 {
		return nil, fmt.Errorf("proximity: Hr offers no supported BLE carrier")
	}
	return offers, nil
}

func parseNFCRequestCarriers(hr []byte) ([]ndefRecord, error) {
	records, err := parseNDEF(hr)
	if err != nil {
		return nil, err
	}
	first := records[0]
	if first.tnf != 1 || string(first.typ) != "Hr" || len(first.payload) < 2 || first.payload[0] != 0x15 {
		return nil, fmt.Errorf("proximity: missing Hr version 1.5")
	}
	byID := map[string]ndefRecord{}
	for i, r := range records {
		if i > 0 && r.tnf == 1 && string(r.typ) == "Hr" {
			return nil, fmt.Errorf("proximity: duplicate Hr")
		}
		if len(r.id) > 0 {
			if _, ok := byID[string(r.id)]; ok {
				return nil, fmt.Errorf("proximity: duplicate Hr record ID")
			}
			byID[string(r.id)] = r
		}
	}
	embedded, err := parseNDEF(first.payload[1:])
	if err != nil {
		return nil, err
	}
	// Reader/writer TNEP requests can omit peer-mode collision resolution.
	// If supplied, it must remain a valid leading record; the carrier loop
	// below rejects duplicate or misplaced collision records.
	if embedded[0].tnf == 1 && string(embedded[0].typ) == "cr" {
		if len(embedded[0].payload) != 2 {
			return nil, fmt.Errorf("proximity: invalid Hr collision resolution")
		}
		embedded = embedded[1:]
	}
	var carriers []ndefRecord
	seen := map[string]bool{}
	for _, ac := range embedded {
		if ac.tnf != 1 || string(ac.typ) != "ac" {
			return nil, fmt.Errorf("proximity: unexpected Hr embedded record")
		}
		id, aux, err := parseAlternativeCarrier(ac.payload)
		if err != nil {
			return nil, err
		}
		if seen[id] {
			return nil, fmt.Errorf("proximity: duplicate Hr carrier")
		}
		seen[id] = true
		carrier, ok := byID[id]
		if !ok {
			return nil, fmt.Errorf("proximity: dangling Hr carrier")
		}
		for _, ref := range aux {
			if _, ok := byID[ref]; !ok {
				return nil, fmt.Errorf("proximity: dangling Hr auxiliary reference")
			}
		}
		carriers = append(carriers, carrier)
	}
	if len(carriers) == 0 {
		return nil, fmt.Errorf("proximity: Hr offers no carrier")
	}
	return carriers, nil
}
