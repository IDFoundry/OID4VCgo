package proximity

import (
	"fmt"
	"sort"
	"strings"

	"github.com/fxamacker/cbor/v2"
)

// deviceRequestVersion is the DeviceRequest version this package writes
// (§8.3.2.1.2.1). ParseDeviceRequest accepts any 1.x.
const deviceRequestVersion = "1.0"

// DocRequest is one document request from a DeviceRequest
// (§8.3.2.1.2.1).
type DocRequest struct {
	// DocType is the requested document type, e.g.
	// "org.iso.18013.5.1.mDL".
	DocType string

	// Elements are the requested [namespace, element] pairs, in the
	// order the request lists them — the form BuildDeviceResponse takes
	// the consented ones in.
	Elements [][2]string

	// IntentToRetain is each requested element's intentToRetain flag:
	// whether the reader says it will keep the value after the
	// transaction, for the consent prompt.
	IntentToRetain map[[2]string]bool

	// ItemsRequestBytes is the request's ItemsRequestBytes exactly as
	// received — #6.24(bstr .cbor ItemsRequest) — since reader
	// authentication (§9.1.4) signs these bytes.
	ItemsRequestBytes []byte

	// ReaderAuth is the request's readerAuth COSE_Sign1 as received, or
	// nil: DeviceSession.VerifyReaderAuth checks it.
	ReaderAuth []byte
}

type wireDeviceRequest struct {
	Version     string           `cbor:"version"`
	DocRequests []wireDocRequest `cbor:"docRequests"`
}

type wireDocRequest struct {
	ItemsRequest cbor.RawMessage `cbor:"itemsRequest"`
	ReaderAuth   cbor.RawMessage `cbor:"readerAuth,omitempty"`
}

type wireItemsRequest struct {
	DocType    string          `cbor:"docType"`
	NameSpaces cbor.RawMessage `cbor:"nameSpaces"`
	// requestInfo is optional and not used.
}

// ParseDeviceRequest decodes a DeviceRequest (§8.3.2.1.2.1), as
// DeviceSession.HandleSessionEstablishment or HandleSessionData
// returns it. An error wraps ErrCBORDecoding for bytes that aren't
// well-formed CBOR, or ErrCBORValidation for well-formed CBOR that isn't
// a DeviceRequest: answer either with DeviceSession.ErrorResponse.
func ParseDeviceRequest(b []byte) ([]DocRequest, error) {
	if len(b) > MaxMessageBytes {
		return nil, fmt.Errorf("proximity: DeviceRequest is %d bytes, over %d: %w", len(b), MaxMessageBytes, ErrCBORDecoding)
	}
	if err := decMode.Wellformed(b); err != nil {
		return nil, fmt.Errorf("proximity: decode DeviceRequest: %w: %w", ErrCBORDecoding, err)
	}
	var req wireDeviceRequest
	if err := decMode.Unmarshal(b, &req); err != nil {
		return nil, fmt.Errorf("proximity: decode DeviceRequest: %w: %w", ErrCBORValidation, err)
	}
	if !strings.HasPrefix(req.Version, "1.") {
		return nil, fmt.Errorf("proximity: DeviceRequest version %q, want 1.x: %w", req.Version, ErrCBORValidation)
	}
	if len(req.DocRequests) == 0 {
		return nil, fmt.Errorf("proximity: DeviceRequest has no docRequests: %w", ErrCBORValidation)
	}

	out := make([]DocRequest, 0, len(req.DocRequests))
	for i, dr := range req.DocRequests {
		parsed, err := parseDocRequest(dr)
		if err != nil {
			return nil, fmt.Errorf("proximity: docRequests[%d]: %w", i, err)
		}
		out = append(out, parsed)
	}
	return out, nil
}

func parseDocRequest(dr wireDocRequest) (DocRequest, error) {
	if dr.ItemsRequest == nil {
		return DocRequest{}, fmt.Errorf("no itemsRequest: %w", ErrCBORValidation)
	}
	itemsRequest, err := unwrapTag24(dr.ItemsRequest)
	if err != nil {
		return DocRequest{}, fmt.Errorf("decode ItemsRequestBytes: %w: %w", ErrCBORValidation, err)
	}
	if err := decMode.Wellformed(itemsRequest); err != nil {
		return DocRequest{}, fmt.Errorf("decode ItemsRequest: %w: %w", ErrCBORDecoding, err)
	}
	var items wireItemsRequest
	if err := decMode.Unmarshal(itemsRequest, &items); err != nil {
		return DocRequest{}, fmt.Errorf("decode ItemsRequest: %w: %w", ErrCBORValidation, err)
	}
	if items.DocType == "" {
		return DocRequest{}, fmt.Errorf("ItemsRequest has no docType: %w", ErrCBORValidation)
	}
	// Typed decode first, for its type and duplicate-key checks; then
	// the ordered walk for the request's own element order.
	var typed map[string]map[string]bool
	if err := decMode.Unmarshal(items.NameSpaces, &typed); err != nil {
		return DocRequest{}, fmt.Errorf("decode nameSpaces: %w: %w", ErrCBORValidation, err)
	}
	if len(typed) == 0 {
		return DocRequest{}, fmt.Errorf("ItemsRequest has no nameSpaces: %w", ErrCBORValidation)
	}

	out := DocRequest{
		DocType:           items.DocType,
		IntentToRetain:    map[[2]string]bool{},
		ItemsRequestBytes: []byte(dr.ItemsRequest),
	}
	if dr.ReaderAuth != nil {
		out.ReaderAuth = []byte(dr.ReaderAuth)
	}
	namespaces, nsValues, err := orderedMapEntries(items.NameSpaces)
	if err != nil {
		return DocRequest{}, err
	}
	for i, ns := range namespaces {
		elements, _, err := orderedMapEntries(nsValues[i])
		if err != nil {
			return DocRequest{}, err
		}
		if len(elements) == 0 {
			return DocRequest{}, fmt.Errorf("namespace %q requests no elements: %w", ns, ErrCBORValidation)
		}
		for _, el := range elements {
			pair := [2]string{ns, el}
			out.Elements = append(out.Elements, pair)
			out.IntentToRetain[pair] = typed[ns][el]
		}
	}
	return out, nil
}

// orderedMapEntries walks raw, a CBOR map with text-string keys, and
// returns its keys in encoded order with each value's raw bytes —
// order a Go map can't keep. raw has already been decoded once with
// decMode, so its structure is known to be valid.
func orderedMapEntries(raw []byte) (keys []string, values []cbor.RawMessage, err error) {
	n, indefinite, rest, err := cborMapHeader(raw)
	if err != nil {
		return nil, nil, err
	}
	for i := uint64(0); indefinite || i < n; i++ {
		if indefinite {
			if len(rest) == 0 {
				return nil, nil, fmt.Errorf("truncated map: %w", ErrCBORDecoding)
			}
			if rest[0] == 0xff {
				break
			}
		}
		var key string
		if rest, err = decMode.UnmarshalFirst(rest, &key); err != nil {
			return nil, nil, fmt.Errorf("decode map key: %w: %w", ErrCBORDecoding, err)
		}
		var value cbor.RawMessage
		if rest, err = decMode.UnmarshalFirst(rest, &value); err != nil {
			return nil, nil, fmt.Errorf("decode map value: %w: %w", ErrCBORDecoding, err)
		}
		keys = append(keys, key)
		values = append(values, value)
	}
	return keys, values, nil
}

// cborMapHeader decodes a CBOR map's header: its number of pairs, or
// indefinite, and the bytes after the header.
func cborMapHeader(raw []byte) (n uint64, indefinite bool, rest []byte, err error) {
	if len(raw) == 0 || raw[0]>>5 != 5 {
		return 0, false, nil, fmt.Errorf("not a CBOR map: %w", ErrCBORDecoding)
	}
	info := raw[0] & 0x1f
	rest = raw[1:]
	switch {
	case info < 24:
		return uint64(info), false, rest, nil
	case info <= 27:
		size := 1 << (info - 24)
		if len(rest) < size {
			return 0, false, nil, fmt.Errorf("truncated map header: %w", ErrCBORDecoding)
		}
		for _, b := range rest[:size] {
			n = n<<8 | uint64(b)
		}
		return n, false, rest[size:], nil
	case info == 31:
		return 0, true, rest, nil
	default:
		return 0, false, nil, fmt.Errorf("invalid map header: %w", ErrCBORDecoding)
	}
}

// encodeDeviceRequest builds a DeviceRequest with one DocRequest for
// docType and elements (namespace → element identifiers), every
// intentToRetain false, and signed by sign if it isn't nil: it returns
// the readerAuth for the request's ItemsRequestBytes. Namespaces and
// elements are encoded sorted, so the same request always gives the
// same bytes.
func encodeDeviceRequest(docType string, elements map[string][]string, sign func(itemsRequestBytes []byte) ([]byte, error)) ([]byte, error) {
	if docType == "" {
		return nil, fmt.Errorf("proximity: docType is required")
	}
	nameSpaces := map[string]map[string]bool{}
	for ns, els := range elements {
		if len(els) == 0 {
			continue
		}
		m := map[string]bool{}
		for _, el := range els {
			m[el] = false
		}
		nameSpaces[ns] = m
	}
	if len(nameSpaces) == 0 {
		return nil, fmt.Errorf("proximity: request at least one element")
	}
	items, err := sortedEncMode.Marshal(struct {
		DocType    string                     `cbor:"docType"`
		NameSpaces map[string]map[string]bool `cbor:"nameSpaces"`
	}{docType, nameSpaces})
	if err != nil {
		return nil, fmt.Errorf("proximity: encode ItemsRequest: %w", err)
	}
	itemsBytes, err := wrapTag24(items)
	if err != nil {
		return nil, fmt.Errorf("proximity: encode ItemsRequestBytes: %w", err)
	}
	doc := wireDocRequest{ItemsRequest: itemsBytes}
	if sign != nil {
		if doc.ReaderAuth, err = sign(itemsBytes); err != nil {
			return nil, err
		}
	}
	b, err := encMode.Marshal(wireDeviceRequest{
		Version:     deviceRequestVersion,
		DocRequests: []wireDocRequest{doc},
	})
	if err != nil {
		return nil, fmt.Errorf("proximity: encode DeviceRequest: %w", err)
	}
	return b, nil
}

// requestedSet is the [namespace, element] pairs a request asked for.
type requestedSet map[[2]string]bool

func newRequestedSet(elements map[string][]string) requestedSet {
	set := requestedSet{}
	for ns, els := range elements {
		for _, el := range els {
			set[[2]string{ns, el}] = true
		}
	}
	return set
}

// unrequested lists, sorted, the elements in nameSpaces that set
// doesn't contain.
func (set requestedSet) unrequested(nameSpaces map[string]map[string]interface{}) []string {
	var extra []string
	for ns, els := range nameSpaces {
		for el := range els {
			if !set[[2]string{ns, el}] {
				extra = append(extra, ns+"/"+el)
			}
		}
	}
	sort.Strings(extra)
	return extra
}
