package proximity

import (
	"errors"
	"fmt"
	"math"

	"github.com/fxamacker/cbor/v2"

	"github.com/idfoundry/oid4vcgo/internal/displaytext"
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
// package understands it: the use cases of the ISO/IEC 18013-5 second
// edition draft (CD ballot resolution, §10.2.5), as Multipaz 0.102.0
// also builds them. Unknown fields are accepted, and signed, but not
// shown here. Each document request's own information is
// DocRequest.RequestInfo.
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
	// against what the reader's certificate allows. Controller IDs are
	// identifiers, not names, but hold no control, line separator or
	// invisible format characters, nor surrounding space: information
	// with one isn't read (DeviceRequest.RequestInfoError). Empty, not nil,
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
// for a request with docCount DocRequests. err is for an envelope that
// isn't that, which refuses the request: null, untagged, over
// MaxDeviceRequestInfoBytes, not well-formed, or not a map. unread is
// for a well-formed map whose known fields don't have RequestInfo's
// shape, or exceed this package's other limits: the information is
// then not shown (info is nil), but the request stands, its signatures
// checked over raw as received. The second edition is still a draft,
// and a request from a reader following a later text isn't malformed
// for that.
func parseDeviceRequestInfo(raw []byte, docCount int) (info *RequestInfo, unread, err error) {
	if len(raw) > MaxDeviceRequestInfoBytes {
		return nil, nil, fmt.Errorf("deviceRequestInfo is %d bytes, over %d: %w", len(raw), MaxDeviceRequestInfoBytes, ErrCBORValidation)
	}
	if len(raw) > 0 && raw[0] == 0xf6 {
		return nil, nil, fmt.Errorf("deviceRequestInfo is null: %w", ErrCBORValidation)
	}
	content, err := unwrapTag24(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("deviceRequestInfo isn't #6.24(bstr): %w: %w", ErrCBORValidation, err)
	}
	// The outer walk doesn't look inside byte strings: check the
	// embedded item, its duplicate keys and nesting, here.
	if err := decMode.Wellformed(content); err != nil {
		return nil, nil, fmt.Errorf("decode DeviceRequestInfo: %w: %w", ErrCBORDecoding, err)
	}
	if !strictcbor.IsMap(content) {
		return nil, nil, fmt.Errorf("DeviceRequestInfo isn't a map: %w", ErrCBORValidation)
	}
	info = &RequestInfo{UseCases: []UseCase{}}
	var budget requestInfoBudget
	unread = mapEntries(content, -1, "DeviceRequestInfo", func(key string, known bool, value []byte) error {
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
	if unread != nil {
		return nil, unread, nil
	}
	return info, nil, nil
}

func parseUseCase(raw []byte, docCount int, budget *requestInfoBudget) (UseCase, error) {
	uc := UseCase{DocumentSets: [][]int{}, PurposeHints: map[string]int32{}}
	var mandatory, documentSets bool
	err := mapEntries(raw, -1, "use case", func(key string, known bool, value []byte) error {
		if !known {
			return nil
		}
		var err error
		switch key {
		case "mandatory":
			mandatory = true
			uc.Mandatory, err = cborBool(value, "mandatory")
		case "documentSets":
			documentSets = true
			uc.DocumentSets, err = parseDocumentSets(value, docCount, budget)
		case "purposeHints":
			uc.PurposeHints, err = parsePurposeHints(value, budget)
		}
		return err
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

// cborBool is raw, a CBOR true or false.
func cborBool(raw []byte, what string) (bool, error) {
	switch {
	case len(raw) == 1 && raw[0] == 0xf5:
		return true, nil
	case len(raw) == 1 && raw[0] == 0xf4:
		return false, nil
	default:
		return false, fmt.Errorf("%s isn't a boolean: %w", what, ErrCBORValidation)
	}
}

// parseDocumentSets is a use case's documentSets, each a set of indexes
// into the request's docCount DocRequests, counted against budget.
func parseDocumentSets(raw []byte, docCount int, budget *requestInfoBudget) ([][]int, error) {
	sets := [][]int{}
	err := arrayItems(raw, MaxDocumentSetsPerUseCase, "documentSets", func(i int, item []byte) error {
		if budget.documentSets++; budget.documentSets > MaxDocumentSets {
			return fmt.Errorf("the request lists over %d document sets: %w", MaxDocumentSets, ErrCBORValidation)
		}
		set, err := parseDocumentSet(item, docCount, budget)
		if err != nil {
			return fmt.Errorf("documentSets[%d]: %w", i, err)
		}
		sets = append(sets, set)
		return nil
	})
	return sets, err
}

// parseDocumentSet is one document set's indexes into the request's
// docCount DocRequests, counted against budget.
func parseDocumentSet(raw []byte, docCount int, budget *requestInfoBudget) ([]int, error) {
	set := []int{}
	err := arrayItems(raw, MaxDocumentReferencesPerSet, "document set", func(_ int, ref []byte) error {
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
	return set, err
}

// parsePurposeHints is a use case's purposeHints, keyed by controller
// ID, counted against budget.
func parsePurposeHints(raw []byte, budget *requestInfoBudget) (map[string]int32, error) {
	hints := map[string]int32{}
	err := mapEntries(raw, MaxPurposeHintsPerUseCase, "purposeHints", func(controllerID string, text bool, code []byte) error {
		if budget.hints++; budget.hints > MaxPurposeHints {
			return fmt.Errorf("the request carries over %d purpose hints: %w", MaxPurposeHints, ErrCBORValidation)
		}
		if !text {
			return fmt.Errorf("a purpose hint's controller ID isn't text: %w", ErrCBORValidation)
		}
		if err := checkControllerID(controllerID); err != nil {
			return err
		}
		v, err := purposeCode(code)
		if err != nil {
			return fmt.Errorf("purpose hint %q: %w", controllerID, err)
		}
		hints[controllerID] = v
		return nil
	})
	return hints, err
}

// checkControllerID refuses a controller ID over MaxControllerIDBytes,
// or one that display text would have to clean (control, line
// separator or invisible characters, surrounding space): it is an
// identifier, which an app may still show.
func checkControllerID(controllerID string) error {
	if len(controllerID) > MaxControllerIDBytes {
		return fmt.Errorf("a controller ID is %d bytes, over %d: %w", len(controllerID), MaxControllerIDBytes, ErrCBORValidation)
	}
	if displaytext.Clean(controllerID, MaxControllerIDBytes) != controllerID {
		return fmt.Errorf("a controller ID %q isn't plain text: %w", controllerID, ErrCBORValidation)
	}
	return nil
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
// raw must already have been walked by decMode. limit, if not
// negative, bounds the items,
// checked against a definite length before any is read, and before
// each of an indefinite array's.
func arrayItems(raw []byte, limit int, what string, fn func(i int, item []byte) error) error {
	n, indefinite, rest, err := cborHeader(raw, 4)
	if err != nil {
		return fmt.Errorf("%s isn't an array: %w", what, ErrCBORValidation)
	}
	if limit >= 0 && !indefinite && n > uint64(limit) {
		return fmt.Errorf("%s has %d items, over %d: %w", what, n, limit, ErrCBORValidation)
	}
	for i := 0; indefinite || uint64(i) < n; i++ {
		ended, err := indefiniteEnded(rest, indefinite, what)
		if err != nil {
			return err
		}
		if ended {
			break
		}
		var item cbor.RawMessage
		if item, rest, err = nextArrayItem(rest, i, limit, what); err != nil {
			return err
		}
		if err := fn(i, item); err != nil {
			return err
		}
	}
	return nil
}

// indefiniteEnded reports whether rest, the remainder of an indefinite
// array, starts with its break; it's always false for a definite one.
func indefiniteEnded(rest []byte, indefinite bool, what string) (bool, error) {
	if !indefinite {
		return false, nil
	}
	if len(rest) == 0 {
		return false, fmt.Errorf("%s: truncated: %w", what, ErrCBORDecoding)
	}
	return rest[0] == 0xff, nil
}

// nextArrayItem is item i of an array, decoded from the start of rest,
// and what follows it; i at limit, if limit isn't negative, is refused.
func nextArrayItem(rest []byte, i, limit int, what string) (cbor.RawMessage, []byte, error) {
	if limit >= 0 && i >= limit {
		return nil, nil, fmt.Errorf("%s has over %d items: %w", what, limit, ErrCBORValidation)
	}
	var item cbor.RawMessage
	rest, err := decMode.UnmarshalFirst(rest, &item)
	if err != nil {
		return nil, nil, fmt.Errorf("%s[%d]: %w: %w", what, i, ErrCBORDecoding, err)
	}
	return item, rest, nil
}
