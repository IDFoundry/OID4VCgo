package proximity

import (
	"errors"
	"fmt"
	"math"

	"github.com/fxamacker/cbor/v2"

	"github.com/idfoundry/oid4vcgo/internal/strictcbor"
)

// Limits on a DeviceRequest's request-level information and signatures
// (DecodeDeviceRequest). They are this library's resource policy, not
// limits ISO/IEC 18013-5 sets: each bounds work done, and what is shown
// to the holder, for a request anyone who saw the engagement can send.
// A request over any of them is refused whole, never truncated. The
// totals apply on top of the per-item limits, and count every encoded
// entry, repeats included.
const (
	// MaxReaderSignatures is the most readerAuthAll signatures one
	// request may carry, as mdocdcapi.MaxReaderSignatures.
	MaxReaderSignatures = 8
	// MaxDeviceRequestInfoBytes bounds the encoded deviceRequestInfo,
	// its tag and byte string head included, and any unknown fields in
	// it.
	MaxDeviceRequestInfoBytes = 64 << 10
	// MaxUseCases is the most use cases one request may list.
	MaxUseCases = 16
	// MaxDocumentSetsPerUseCase is the most document sets one use case
	// may list.
	MaxDocumentSetsPerUseCase = 8
	// MaxDocumentSets is the most document sets one request may list,
	// across its use cases.
	MaxDocumentSets = 64
	// MaxDocumentReferencesPerSet is the most document request indices
	// one document set may list: MaxDocRequests.
	MaxDocumentReferencesPerSet = MaxDocRequests
	// MaxDocumentReferences is the most document request indices one
	// request may list, across its document sets.
	MaxDocumentReferences = 256
	// MaxPurposeHintsPerUseCase is the most purpose hints one use case
	// may carry.
	MaxPurposeHintsPerUseCase = 16
	// MaxPurposeHints is the most purpose hints one request may carry,
	// across its use cases.
	MaxPurposeHints = 64
	// MaxControllerIDBytes bounds each purpose hint's controller ID, in
	// UTF-8 bytes.
	MaxControllerIDBytes = 256
)

// RequestInfo is a DeviceRequest's deviceRequestInfo, as far as this
// package understands it: the second edition's use cases, in the
// working representation of Multipaz 0.102.0, which still has to be
// checked against the ISO/IEC 18013-5 second edition text. Unknown
// fields are accepted, and signed, but not shown here.
type RequestInfo struct {
	// UseCases are the request's use cases, in the request's order;
	// empty, not nil, when the information lists none.
	UseCases []UseCase

	// Signed reports whether a verified readerAuthAll covers this
	// information: every signature the request carries verified over
	// this session, and at least one of them signs the whole request.
	// It says nothing about whether the signer is trusted — see the
	// ReaderAuthentication that came with it — nor whether its
	// certificate entitles it to the purposes claimed. Decoding alone
	// leaves it false.
	Signed bool
}

// UseCase is one of a request's use cases: a set of alternatives,
// each a group of the request's documents, and why the reader asks.
type UseCase struct {
	// Mandatory is the use case's mandatory flag, as the reader sent
	// it. What it obliges the holder to is the application's decision.
	Mandatory bool

	// DocumentSets are the use case's document sets, in the request's
	// order: each lists indices into the request's DocRequests, in the
	// set's order, repeats kept. Empty, not nil, when it lists none.
	DocumentSets [][]int

	// PurposeHints maps each controller ID to a purpose code, as the
	// reader sent them: the code is neither translated nor checked
	// against what the reader's certificate allows. Empty, not nil,
	// when the use case carries none.
	PurposeHints map[string]int32
}

// clone is a deep copy of info; nil for nil.
func (info *RequestInfo) clone() *RequestInfo {
	if info == nil {
		return nil
	}
	out := &RequestInfo{UseCases: make([]UseCase, len(info.UseCases)), Signed: info.Signed}
	for i, uc := range info.UseCases {
		c := UseCase{Mandatory: uc.Mandatory, DocumentSets: make([][]int, len(uc.DocumentSets)), PurposeHints: make(map[string]int32, len(uc.PurposeHints))}
		for j, set := range uc.DocumentSets {
			c.DocumentSets[j] = append(make([]int, 0, len(set)), set...)
		}
		for k, v := range uc.PurposeHints {
			c.PurposeHints[k] = v
		}
		out.UseCases[i] = c
	}
	return out
}

// requestInfoBudget counts the request-wide totals while one
// deviceRequestInfo is parsed.
type requestInfoBudget struct {
	documentSets, references, hints int
}

// parseDeviceRequestInfo decodes raw, a DeviceRequest's
// deviceRequestInfo as received — #6.24(bstr .cbor DeviceRequestInfo) —
// for a request with docCount DocRequests.
func parseDeviceRequestInfo(raw []byte, docCount int) (*RequestInfo, error) {
	if len(raw) > MaxDeviceRequestInfoBytes {
		return nil, fmt.Errorf("deviceRequestInfo is %d bytes, over %d: %w", len(raw), MaxDeviceRequestInfoBytes, ErrCBORValidation)
	}
	if len(raw) > 0 && raw[0] == 0xf6 {
		return nil, fmt.Errorf("deviceRequestInfo is null: %w", ErrCBORValidation)
	}
	content, err := unwrapTag24(raw)
	if err != nil {
		return nil, fmt.Errorf("deviceRequestInfo isn't #6.24(bstr): %w: %w", ErrCBORValidation, err)
	}
	// The outer walk doesn't look inside byte strings: check the
	// embedded item, its duplicate keys and nesting, here.
	if err := decMode.Wellformed(content); err != nil {
		return nil, fmt.Errorf("decode DeviceRequestInfo: %w: %w", ErrCBORDecoding, err)
	}
	if !strictcbor.IsMap(content) {
		return nil, fmt.Errorf("DeviceRequestInfo isn't a map: %w", ErrCBORValidation)
	}
	info := &RequestInfo{UseCases: []UseCase{}}
	var budget requestInfoBudget
	err = mapEntries(content, -1, "DeviceRequestInfo", func(key string, known bool, value []byte) error {
		if !known || key != "useCases" {
			return nil // an extension: signed as received, not interpreted
		}
		return arrayItems(value, MaxUseCases, "useCases", func(i int, item []byte) error {
			uc, err := parseUseCase(item, docCount, &budget)
			if err != nil {
				return fmt.Errorf("useCases[%d]: %w", i, err)
			}
			info.UseCases = append(info.UseCases, uc)
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	return info, nil
}

func parseUseCase(raw []byte, docCount int, budget *requestInfoBudget) (UseCase, error) {
	uc := UseCase{DocumentSets: [][]int{}, PurposeHints: map[string]int32{}}
	var mandatory, documentSets bool
	err := mapEntries(raw, -1, "use case", func(key string, known bool, value []byte) error {
		if !known {
			return nil
		}
		switch key {
		case "mandatory":
			mandatory = true
			switch {
			case len(value) == 1 && value[0] == 0xf5:
				uc.Mandatory = true
			case len(value) == 1 && value[0] == 0xf4:
				uc.Mandatory = false
			default:
				return fmt.Errorf("mandatory isn't a boolean: %w", ErrCBORValidation)
			}
		case "documentSets":
			documentSets = true
			return arrayItems(value, MaxDocumentSetsPerUseCase, "documentSets", func(i int, item []byte) error {
				if budget.documentSets++; budget.documentSets > MaxDocumentSets {
					return fmt.Errorf("the request lists over %d document sets: %w", MaxDocumentSets, ErrCBORValidation)
				}
				set := []int{}
				err := arrayItems(item, MaxDocumentReferencesPerSet, "document set", func(_ int, ref []byte) error {
					if budget.references++; budget.references > MaxDocumentReferences {
						return fmt.Errorf("the request lists over %d document references: %w", MaxDocumentReferences, ErrCBORValidation)
					}
					index, err := documentIndex(ref, docCount)
					if err != nil {
						return err
					}
					set = append(set, index)
					return nil
				})
				if err != nil {
					return fmt.Errorf("documentSets[%d]: %w", i, err)
				}
				uc.DocumentSets = append(uc.DocumentSets, set)
				return nil
			})
		case "purposeHints":
			return mapEntries(value, MaxPurposeHintsPerUseCase, "purposeHints", func(controllerID string, text bool, code []byte) error {
				if budget.hints++; budget.hints > MaxPurposeHints {
					return fmt.Errorf("the request carries over %d purpose hints: %w", MaxPurposeHints, ErrCBORValidation)
				}
				if !text {
					return fmt.Errorf("a purpose hint's controller ID isn't text: %w", ErrCBORValidation)
				}
				if len(controllerID) > MaxControllerIDBytes {
					return fmt.Errorf("a controller ID is %d bytes, over %d: %w", len(controllerID), MaxControllerIDBytes, ErrCBORValidation)
				}
				v, err := purposeCode(code)
				if err != nil {
					return fmt.Errorf("purpose hint %q: %w", controllerID, err)
				}
				uc.PurposeHints[controllerID] = v
				return nil
			})
		}
		return nil
	})
	if err != nil {
		return UseCase{}, err
	}
	if !mandatory {
		return UseCase{}, fmt.Errorf("use case has no mandatory: %w", ErrCBORValidation)
	}
	if !documentSets {
		return UseCase{}, fmt.Errorf("use case has no documentSets: %w", ErrCBORValidation)
	}
	return uc, nil
}

// documentIndex is raw, an unsigned integer, as an index into a
// request's docCount DocRequests.
func documentIndex(raw []byte, docCount int) (int, error) {
	if len(raw) == 0 || raw[0]>>5 != 0 {
		return 0, fmt.Errorf("a document reference isn't an unsigned integer: %w", ErrCBORValidation)
	}
	var v uint64
	if err := decMode.Unmarshal(raw, &v); err != nil {
		return 0, fmt.Errorf("decode a document reference: %w: %w", ErrCBORValidation, err)
	}
	if docCount <= 0 || v >= uint64(docCount) {
		return 0, fmt.Errorf("document reference %d, but the request has %d DocRequests: %w", v, docCount, ErrCBORValidation)
	}
	return int(v), nil
}

// purposeCode is raw, an integer, as a signed 32-bit purpose code.
func purposeCode(raw []byte) (int32, error) {
	// Major types 0 and 1 only: no float, and no bignum tag.
	if len(raw) == 0 || raw[0]>>5 > 1 {
		return 0, fmt.Errorf("the purpose code isn't an integer: %w", ErrCBORValidation)
	}
	var v int64
	if err := decMode.Unmarshal(raw, &v); err != nil || v < math.MinInt32 || v > math.MaxInt32 {
		return 0, fmt.Errorf("the purpose code is outside the signed 32-bit range: %w", ErrCBORValidation)
	}
	return int32(v), nil
}

// mapEntries calls fn with each entry of raw, a CBOR map, in encoded
// order: its key decoded when it is a text string (known), and its
// value's encoded bytes. raw must already have been walked by decMode.
// limit, if not negative, bounds the entries, checked against a
// definite length before any is read, and before each of an indefinite
// map's.
func mapEntries(raw []byte, limit int, what string, fn func(key string, known bool, value []byte) error) error {
	n, indefinite, _, err := cborHeader(raw, 5)
	if err != nil {
		return fmt.Errorf("%s isn't a map: %w", what, ErrCBORValidation)
	}
	if limit >= 0 && !indefinite && n > uint64(limit) {
		return fmt.Errorf("%s has %d entries, over %d: %w", what, n, limit, ErrCBORValidation)
	}
	count := 0
	err = strictcbor.Entries(raw, func(key, value []byte) error {
		if count++; limit >= 0 && count > limit {
			return fmt.Errorf("%s has over %d entries: %w", what, limit, ErrCBORValidation)
		}
		var name string
		known := len(key) > 0 && key[0]>>5 == 3 && decMode.Unmarshal(key, &name) == nil
		return fn(name, known, value)
	})
	if err != nil && !errors.Is(err, ErrCBORValidation) && !errors.Is(err, ErrCBORDecoding) {
		return fmt.Errorf("%s: %w: %w", what, ErrCBORDecoding, err)
	}
	return err
}

// arrayItems calls fn with each item of raw, a CBOR array, in order.
// raw must already have been walked by decMode. limit bounds the items,
// checked against a definite length before any is read, and before
// each of an indefinite array's.
func arrayItems(raw []byte, limit int, what string, fn func(i int, item []byte) error) error {
	n, indefinite, rest, err := cborHeader(raw, 4)
	if err != nil {
		return fmt.Errorf("%s isn't an array: %w", what, ErrCBORValidation)
	}
	if !indefinite && (limit < 0 || n > uint64(limit)) {
		return fmt.Errorf("%s has %d items, over %d: %w", what, n, limit, ErrCBORValidation)
	}
	for i := 0; indefinite || uint64(i) < n; i++ {
		if indefinite {
			if len(rest) == 0 {
				return fmt.Errorf("%s: truncated: %w", what, ErrCBORDecoding)
			}
			if rest[0] == 0xff {
				break
			}
		}
		if i >= limit {
			return fmt.Errorf("%s has over %d items: %w", what, limit, ErrCBORValidation)
		}
		var item cbor.RawMessage
		if rest, err = decMode.UnmarshalFirst(rest, &item); err != nil {
			return fmt.Errorf("%s[%d]: %w: %w", what, i, ErrCBORDecoding, err)
		}
		if err := fn(i, item); err != nil {
			return err
		}
	}
	return nil
}
