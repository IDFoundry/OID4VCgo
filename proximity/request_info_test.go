package proximity

import (
	"errors"
	"math"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// decodeInfo decodes a request with docCount unsigned documents and
// info as its deviceRequestInfo.
func decodeInfo(t *testing.T, docCount int, info cbor.RawMessage) (*DeviceRequest, error) {
	t.Helper()
	return DecodeDeviceRequest(testRequest{docs: testDocs(docCount, nil), info: info}.build(t, testTranscriptBytes(t, "info")))
}

// useCase is a use case map with mandatory and documentSets, plus
// extra entries.
func useCase(sets any, extra ...any) map[string]any {
	uc := map[string]any{"mandatory": true, "documentSets": sets}
	for i := 0; i+1 < len(extra); i += 2 {
		uc[extra[i].(string)] = extra[i+1]
	}
	return uc
}

// hints is n purpose hints, controller IDs from prefix.
func hints(prefix string, n int) map[string]int {
	out := map[string]int{}
	for i := 0; i < n; i++ {
		out[prefix+string(rune('A'+i%26))+string(rune('a'+i/26))] = i
	}
	return out
}

// indefiniteArray encodes items as an indefinite-length array.
func indefiniteArray(t *testing.T, items ...any) cbor.RawMessage {
	t.Helper()
	out := []byte{0x9f}
	for _, it := range items {
		out = append(out, mustCBOR(t, it)...)
	}
	return append(out, 0xff)
}

// The decoded information keeps what the reader sent, in its order:
// mandatory flags, document sets with repeats, negative and unfamiliar
// purpose codes; an unknown extension is accepted and not shown.
func TestDecodeDeviceRequest_RequestInfo(t *testing.T) {
	req, err := decodeInfo(t, 2, sampleInfo(t))
	if err != nil {
		t.Fatal(err)
	}
	got := req.RequestInfo()
	want := &RequestInfo{UseCases: []UseCase{
		{Mandatory: true, DocumentSets: [][]int{{0}, {1, 0}}, PurposeHints: map[string]int32{"org.example": 3, "org.example.neg": -2}},
		{Mandatory: false, DocumentSets: [][]int{}, PurposeHints: map[string]int32{}},
	}}
	if !equalRequestInfo(got, want) {
		t.Errorf("RequestInfo = %+v, want %+v", got, want)
	}
	if got.Signed {
		t.Error("Signed set by decoding")
	}
	if got.UseCases[1].DocumentSets == nil || got.UseCases[1].PurposeHints == nil {
		t.Error("empty collections came back nil")
	}

	repeats, err := decodeInfo(t, 2, infoOf(t, map[string]any{"useCases": []any{useCase([][]int{{1, 1, 0}})}}))
	if err != nil {
		t.Fatal(err)
	}
	if sets := repeats.RequestInfo().UseCases[0].DocumentSets; len(sets) != 1 || len(sets[0]) != 3 || sets[0][0] != 1 || sets[0][1] != 1 {
		t.Errorf("a repeated index: %v, want [[1 1 0]]", sets)
	}
}

// Absent information, information without useCases, and an empty map
// are distinct from each other only in the first: nil, against present
// information with no use cases.
func TestDecodeDeviceRequest_AbsentAndEmpty(t *testing.T) {
	absent, err := decodeInfo(t, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	if absent.RequestInfo() != nil {
		t.Error("absent information: RequestInfo isn't nil")
	}
	for name, info := range map[string]cbor.RawMessage{
		"empty map":           infoOf(t, map[string]any{}),
		"only an extension":   infoOf(t, map[string]any{"other": []int{1}}),
		"empty useCases":      infoOf(t, map[string]any{"useCases": []any{}}),
		"indefinite empty":    infoOf(t, map[string]any{"useCases": indefiniteArray(t)}),
		"integer-keyed field": tagged(t, []byte{0xa1, 0x01, 0x02}),
	} {
		t.Run(name, func(t *testing.T) {
			req, err := decodeInfo(t, 1, info)
			if err != nil {
				t.Fatal(err)
			}
			got := req.RequestInfo()
			if got == nil || got.UseCases == nil || len(got.UseCases) != 0 {
				t.Errorf("RequestInfo = %+v, want present with no use cases", got)
			}
		})
	}
}

// Known fields of the wrong shape are refused, the request with them:
// never dropped and treated as absent.
func TestDecodeDeviceRequest_RefusesMalformedInfo(t *testing.T) {
	ok := [][]int{{0}}
	for name, tc := range map[string]struct {
		info cbor.RawMessage
		want error
	}{
		"null information":        {cbor.RawMessage{0xf6}, ErrCBORValidation},
		"untagged map":            {mustCBOR(t, map[string]any{}), ErrCBORValidation},
		"tag 24 of a text string": {mustCBOR(t, cbor.Tag{Number: 24, Content: "x"}), ErrCBORValidation},
		"another tag":             {mustCBOR(t, cbor.Tag{Number: 25, Content: []byte{0xa0}}), ErrCBORValidation},
		"embedded array":          {infoOf(t, []int{}), ErrCBORValidation},
		"embedded malformed":      {tagged(t, []byte{0xa1, 0x61}), ErrCBORDecoding},
		"embedded trailing bytes": {tagged(t, []byte{0xa0, 0xa0}), ErrCBORDecoding},
		"duplicate key":           {tagged(t, append(append([]byte{0xa2}, mustCBOR(t, "useCases")...), append(append([]byte{0x80}, mustCBOR(t, "useCases")...), 0x80)...)), ErrCBORDecoding},
		"duplicate extension key": {tagged(t, []byte{0xa1, 0x61, 'x', 0xa2, 0x01, 0x01, 0x01, 0x02}), ErrCBORDecoding},
		"null useCases":           {infoOf(t, map[string]any{"useCases": nil}), ErrCBORValidation},
		"useCases a map":          {infoOf(t, map[string]any{"useCases": map[string]any{}}), ErrCBORValidation},
		"use case not a map":      {infoOf(t, map[string]any{"useCases": []any{1}}), ErrCBORValidation},
		"no mandatory":            {infoOf(t, map[string]any{"useCases": []any{map[string]any{"documentSets": ok}}}), ErrCBORValidation},
		"mandatory not boolean":   {infoOf(t, map[string]any{"useCases": []any{map[string]any{"mandatory": 1, "documentSets": ok}}}), ErrCBORValidation},
		"null mandatory":          {infoOf(t, map[string]any{"useCases": []any{map[string]any{"mandatory": nil, "documentSets": ok}}}), ErrCBORValidation},
		"no documentSets":         {infoOf(t, map[string]any{"useCases": []any{map[string]any{"mandatory": true}}}), ErrCBORValidation},
		"null documentSets":       {infoOf(t, map[string]any{"useCases": []any{useCase(nil)}}), ErrCBORValidation},
		"document set not array":  {infoOf(t, map[string]any{"useCases": []any{useCase([]any{0})}}), ErrCBORValidation},
		"index past documents":    {infoOf(t, map[string]any{"useCases": []any{useCase([][]int{{1}})}}), ErrCBORValidation},
		"negative index":          {infoOf(t, map[string]any{"useCases": []any{useCase([][]int{{-1}})}}), ErrCBORValidation},
		"float index":             {infoOf(t, map[string]any{"useCases": []any{useCase([][]float64{{0}})}}), ErrCBORValidation},
		"text index":              {infoOf(t, map[string]any{"useCases": []any{useCase([][]string{{"0"}})}}), ErrCBORValidation},
		"null purposeHints":       {infoOf(t, map[string]any{"useCases": []any{useCase(ok, "purposeHints", nil)}}), ErrCBORValidation},
		"purposeHints an array":   {infoOf(t, map[string]any{"useCases": []any{useCase(ok, "purposeHints", []int{1})}}), ErrCBORValidation},
		"integer controller ID":   {infoOf(t, map[string]any{"useCases": []any{useCase(ok, "purposeHints", map[int]int{1: 1})}}), ErrCBORValidation},
		"text purpose code":       {infoOf(t, map[string]any{"useCases": []any{useCase(ok, "purposeHints", map[string]string{"c": "1"})}}), ErrCBORValidation},
		"float purpose code":      {infoOf(t, map[string]any{"useCases": []any{useCase(ok, "purposeHints", map[string]float64{"c": 1})}}), ErrCBORValidation},
		"bignum purpose code":     {infoOf(t, map[string]any{"useCases": []any{useCase(ok, "purposeHints", map[string]any{"c": cbor.Tag{Number: 2, Content: []byte{1}}})}}), ErrCBORValidation},
		"code above int32":        {infoOf(t, map[string]any{"useCases": []any{useCase(ok, "purposeHints", map[string]int64{"c": math.MaxInt32 + 1})}}), ErrCBORValidation},
		"code below int32":        {infoOf(t, map[string]any{"useCases": []any{useCase(ok, "purposeHints", map[string]int64{"c": math.MinInt32 - 1})}}), ErrCBORValidation},
		"code past int64":         {infoOf(t, map[string]any{"useCases": []any{useCase(ok, "purposeHints", map[string]uint64{"c": math.MaxUint64})}}), ErrCBORValidation},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := decodeInfo(t, 1, tc.info)
			if !errors.Is(err, tc.want) {
				t.Errorf("DecodeDeviceRequest = %v, want %v", err, tc.want)
			}
		})
	}
}

// Purpose codes span signed 32-bit integers exactly; unknown fields of
// a use case are accepted; controller IDs are kept as received.
func TestDecodeDeviceRequest_AcceptsBoundaryValues(t *testing.T) {
	odd := "Ünïcode/ID with spaces"
	req, err := decodeInfo(t, 1, infoOf(t, map[string]any{"useCases": []any{
		useCase([][]int{{0}}, "purposeHints", map[string]int64{"max": math.MaxInt32, "min": math.MinInt32, "zero": 0, odd: 7}, "futureField", map[string]any{"x": []int{1}}),
	}}))
	if err != nil {
		t.Fatal(err)
	}
	h := req.RequestInfo().UseCases[0].PurposeHints
	if h["max"] != math.MaxInt32 || h["min"] != math.MinInt32 || h["zero"] != 0 || h[odd] != 7 {
		t.Errorf("PurposeHints = %v", h)
	}
}

// Every limit: its exact value is accepted, one more refused, whole.
func TestDecodeDeviceRequest_Limits(t *testing.T) {
	sets := func(n, per int) [][]int {
		out := make([][]int, n)
		for i := range out {
			out[i] = make([]int, per)
		}
		return out
	}
	useCases := func(n int, uc func(i int) any) cbor.RawMessage {
		ucs := make([]any, n)
		for i := range ucs {
			ucs[i] = uc(i)
		}
		return infoOf(t, map[string]any{"useCases": ucs})
	}
	plain := func(int) any { return useCase([][]int{{0}}) }
	id := func(n int) string { return strings.Repeat("c", n) }
	for name, tc := range map[string]struct {
		at, over cbor.RawMessage
	}{
		"use cases": {useCases(MaxUseCases, plain), useCases(MaxUseCases+1, plain)},
		"use cases, indefinite": {
			infoOf(t, map[string]any{"useCases": indefiniteArray(t, useCases16(t)...)}),
			infoOf(t, map[string]any{"useCases": indefiniteArray(t, append(useCases16(t), useCase([][]int{{0}}))...)}),
		},
		"document sets per use case": {
			useCases(1, func(int) any { return useCase(sets(MaxDocumentSetsPerUseCase, 1)) }),
			useCases(1, func(int) any { return useCase(sets(MaxDocumentSetsPerUseCase+1, 1)) }),
		},
		"document sets in all": {
			useCases(MaxDocumentSets/MaxDocumentSetsPerUseCase, func(int) any { return useCase(sets(MaxDocumentSetsPerUseCase, 1)) }),
			useCases(MaxDocumentSets/MaxDocumentSetsPerUseCase+1, func(i int) any {
				if i == MaxDocumentSets/MaxDocumentSetsPerUseCase {
					return useCase(sets(1, 1))
				}
				return useCase(sets(MaxDocumentSetsPerUseCase, 1))
			}),
		},
		"references per set": {
			useCases(1, func(int) any { return useCase(sets(1, MaxDocumentReferencesPerSet)) }),
			useCases(1, func(int) any { return useCase(sets(1, MaxDocumentReferencesPerSet+1)) }),
		},
		"references per set, indefinite": {
			useCases(1, func(int) any { return useCase([]any{indefiniteArray(t, 0, 0, 0, 0, 0, 0, 0, 0)}) }),
			useCases(1, func(int) any { return useCase([]any{indefiniteArray(t, 0, 0, 0, 0, 0, 0, 0, 0, 0)}) }),
		},
		// 64 sets of 4 references are 256; one set of 5 makes 257.
		"references in all": {
			useCases(8, func(int) any { return useCase(sets(8, 4)) }),
			useCases(8, func(i int) any {
				if i == 7 {
					return useCase(append(sets(7, 4), make([]int, 5)))
				}
				return useCase(sets(8, 4))
			}),
		},
		"purpose hints per use case": {
			useCases(1, func(int) any { return useCase([][]int{{0}}, "purposeHints", hints("h", MaxPurposeHintsPerUseCase)) }),
			useCases(1, func(int) any { return useCase([][]int{{0}}, "purposeHints", hints("h", MaxPurposeHintsPerUseCase+1)) }),
		},
		"purpose hints in all": {
			useCases(MaxPurposeHints/MaxPurposeHintsPerUseCase, func(int) any {
				return useCase([][]int{{0}}, "purposeHints", hints("h", MaxPurposeHintsPerUseCase))
			}),
			useCases(MaxPurposeHints/MaxPurposeHintsPerUseCase+1, func(i int) any {
				if i == MaxPurposeHints/MaxPurposeHintsPerUseCase {
					return useCase([][]int{{0}}, "purposeHints", hints("h", 1))
				}
				return useCase([][]int{{0}}, "purposeHints", hints("h", MaxPurposeHintsPerUseCase))
			}),
		},
		"controller ID bytes": {
			useCases(1, func(int) any {
				return useCase([][]int{{0}}, "purposeHints", map[string]int{id(MaxControllerIDBytes): 1})
			}),
			useCases(1, func(int) any {
				return useCase([][]int{{0}}, "purposeHints", map[string]int{id(MaxControllerIDBytes + 1): 1})
			}),
		},
		// 2 + 3 + 6 + padding bytes: the tag, the byte string's head,
		// {"x": h'…'}'s map, key and byte string heads.
		"information bytes": {
			paddedInfo(t, MaxDeviceRequestInfoBytes-11),
			paddedInfo(t, MaxDeviceRequestInfoBytes-10),
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeInfo(t, 1, tc.at); err != nil {
				t.Errorf("at the limit: %v", err)
			}
			if _, err := decodeInfo(t, 1, tc.over); !errors.Is(err, ErrCBORValidation) {
				t.Errorf("over the limit: %v, want a validation error", err)
			}
		})
	}
	if n := len(paddedInfo(t, MaxDeviceRequestInfoBytes-11)); n != MaxDeviceRequestInfoBytes {
		t.Fatalf("the at-limit information is %d bytes, want %d", n, MaxDeviceRequestInfoBytes)
	}
}

func useCases16(t *testing.T) []any {
	t.Helper()
	out := make([]any, MaxUseCases)
	for i := range out {
		out[i] = useCase([][]int{{0}})
	}
	return out
}

// readerAuthAll, when present, is an array of 1 to MaxReaderSignatures
// entries: null, empty, another type and one too many are refused. Its
// entries' contents are for VerifyDeviceRequest to check.
func TestDecodeDeviceRequest_ReaderAuthAllShape(t *testing.T) {
	base := testRequest{docs: testDocs(1, nil)}.build(t, testTranscriptBytes(t, "shape"))
	sigs := func(n int) cbor.RawMessage {
		out := make([]cbor.RawMessage, n)
		for i := range out {
			out[i] = mustCBOR(t, []any{[]byte{}, map[int]any{}, nil, []byte{}})
		}
		return mustCBOR(t, out)
	}
	for name, tc := range map[string]struct {
		all cbor.RawMessage
		ok  bool
	}{
		"one":              {sigs(1), true},
		"the most":         {sigs(MaxReaderSignatures), true},
		"garbage contents": {mustCBOR(t, []any{"not a COSE_Sign1"}), true},
		"one too many":     {sigs(MaxReaderSignatures + 1), false},
		"empty":            {cbor.RawMessage{0x80}, false},
		"empty indefinite": {cbor.RawMessage{0x9f, 0xff}, false},
		"null":             {cbor.RawMessage{0xf6}, false},
		"a map":            {cbor.RawMessage{0xa0}, false},
		"a byte string":    {mustCBOR(t, []byte{1}), false},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := DecodeDeviceRequest(editRequest(t, base, func(m map[string]cbor.RawMessage) { m["readerAuthAll"] = tc.all }))
			if tc.ok && err != nil {
				t.Errorf("refused: %v", err)
			}
			if !tc.ok && !errors.Is(err, ErrCBORValidation) {
				t.Errorf("DecodeDeviceRequest = %v, want a validation error", err)
			}
		})
	}
}

// The request-level fields are checked whatever the 1.x version: a
// "1.0" request carrying malformed information is refused, not read as
// first-edition and its information ignored.
func TestDecodeDeviceRequest_VersionDoesNotHideFields(t *testing.T) {
	bad := testRequest{docs: testDocs(1, nil), info: cbor.RawMessage{0xf6}, version: "1.0"}.build(t, testTranscriptBytes(t, "version"))
	if _, err := DecodeDeviceRequest(bad); !errors.Is(err, ErrCBORValidation) {
		t.Errorf("version 1.0 with null information: %v, want a validation error", err)
	}
	good := testRequest{docs: testDocs(1, nil), info: infoOf(t, map[string]any{}), version: "1.0"}.build(t, testTranscriptBytes(t, "version"))
	if req, err := DecodeDeviceRequest(good); err != nil || req.RequestInfo() == nil {
		t.Errorf("version 1.0 with information: %v, want it decoded", err)
	}
}

// paddedInfo is #6.24(<<{"x": h'00…'}>>) with n bytes of padding, n
// from 256 to 65535: 11 bytes more in all.
func paddedInfo(t *testing.T, n int) cbor.RawMessage {
	t.Helper()
	return tagged(t, append([]byte{0xa1, 0x61, 'x', 0x59, byte(n >> 8), byte(n)}, make([]byte, n)...))
}
