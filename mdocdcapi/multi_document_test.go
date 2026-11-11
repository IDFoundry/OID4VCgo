package mdocdcapi

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/internal/testmdoc"
	"github.com/idfoundry/oid4vcgo/verifier"
)

// issuerKeysByType resolves each document type's issuer key.
type issuerKeysByType map[string]crypto.PublicKey

func (k issuerKeysByType) ResolveMdocIssuerKey(_ context.Context, _ [][]byte, docType string) (crypto.PublicKey, oid4vci.COSEAlg, error) {
	pub, ok := k[docType]
	if !ok {
		return nil, 0, fmt.Errorf("no issuer for %q", docType)
	}
	return pub, oid4vci.COSEES256, nil
}

var multiTypes = []string{"org.example.a", "org.example.b", "org.example.c"}

// multiHarness is a request for given_name from each of multiTypes, as
// the wallet parsed it, and an mdoc of each type.
type multiHarness struct {
	request  Request
	incoming Incoming
	fixtures []testmdoc.Fixture
	keys     issuerKeysByType
}

func newMultiHarness(t *testing.T) multiHarness {
	t.Helper()
	cert, key := testcert.SelfSignedLeaf(t, "mdocdcapi test reader")
	h := multiHarness{keys: issuerKeysByType{}}
	var docs []DocumentRequest
	for _, dt := range multiTypes {
		f := testmdoc.IssueWith(t, func(c *mdoc.Claims) { c.DocType = dt })
		h.fixtures = append(h.fixtures, f)
		h.keys[dt] = f.IssuerKey.Public()
		docs = append(docs, DocumentRequest{DocType: dt, Elements: map[string]map[string]bool{testmdoc.Namespace: {"given_name": false}}})
	}
	var err error
	h.request, err = BuildRequest(RequestParams{Origin: testOrigin, Documents: docs, Readers: []ReaderKey{{Signer: key, Chain: []*x509.Certificate{cert}}}})
	if err != nil {
		t.Fatal(err)
	}
	if h.request.Pending.DocType != "" || len(h.request.Pending.Documents) != 3 {
		t.Fatalf("Pending = %+v, want three Documents", h.request.Pending)
	}
	data, err := json.Marshal(h.request.Data)
	if err != nil {
		t.Fatal(err)
	}
	h.incoming, err = ParseRequest(data, testOrigin)
	if err != nil {
		t.Fatal(err)
	}
	if len(h.incoming.Documents) != 3 {
		t.Fatalf("the wallet saw %d documents, want 3", len(h.incoming.Documents))
	}
	return h
}

func (h multiHarness) answer(i int) Answer {
	return Answer{Document: i, IssuerSigned: h.fixtures[i].IssuerSigned, Holder: h.fixtures[i].DeviceKey, Elements: [][2]string{{testmdoc.Namespace, "given_name"}}}
}

// A document provider answers two of three requested documents in one
// EncryptedResponse; VerifyResponseDocuments verifies both, and runs
// Accept once with both. VerifyResponse, for one document, refuses it.
func TestRespondDocuments(t *testing.T) {
	h := newMultiHarness(t)
	encrypted, err := h.incoming.RespondDocuments(context.Background(), []Answer{h.answer(0), h.answer(2)})
	if err != nil {
		t.Fatal(err)
	}
	accepted := 0
	p := VerifyParams{
		Pending: h.request.Pending, Response: base64.RawURLEncoding.EncodeToString(encrypted), IssuerKeys: h.keys,
		Assurance: verifier.AssuranceDevelopment, NoStatusCheck: true,
		Accept: func(_ context.Context, _ string, r verifier.VerifyResponseResult) error {
			accepted += len(r.Credentials)
			return nil
		},
	}
	vs, err := VerifyResponseDocuments(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	if len(vs) != 2 || vs[0].DocType != multiTypes[0] || vs[1].DocType != multiTypes[2] {
		t.Fatalf("verified %+v, want %s and %s", vs, multiTypes[0], multiTypes[2])
	}
	for _, v := range vs {
		if got := v.NameSpaces[testmdoc.Namespace]; len(got) != 1 || got["given_name"] != "Alice" || v.Missing != nil {
			t.Errorf("%s disclosed %v, missing %v", v.DocType, v.NameSpaces, v.Missing)
		}
	}
	if accepted != 2 {
		t.Errorf("Accept saw %d credentials, want 2 in one call", accepted)
	}
	if _, err := VerifyResponse(context.Background(), p); err == nil || !strings.Contains(err.Error(), "VerifyResponseDocuments") {
		t.Errorf("VerifyResponse of a three-document request: %v", err)
	}
}

// Documents answered in another order than requested come back, and go
// to Accept, in the request's order, each named by its type.
func TestVerifyResponseDocuments_RequestOrder(t *testing.T) {
	h := newMultiHarness(t)
	encrypted, err := h.incoming.RespondDocuments(context.Background(), []Answer{h.answer(2), h.answer(0)})
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	vs, err := VerifyResponseDocuments(context.Background(), VerifyParams{
		Pending: h.request.Pending, Response: base64.RawURLEncoding.EncodeToString(encrypted), IssuerKeys: h.keys,
		Assurance: verifier.AssuranceDevelopment, NoStatusCheck: true,
		Accept: func(_ context.Context, _ string, r verifier.VerifyResponseResult) error {
			for _, c := range r.Credentials {
				ids = append(ids, c.CredentialQueryID)
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{multiTypes[0], multiTypes[2]}
	if len(vs) != 2 || vs[0].DocType != want[0] || vs[1].DocType != want[1] {
		t.Errorf("verified %s, %s, want %v", vs[0].DocType, vs[1].DocType, want)
	}
	if fmt.Sprint(ids) != fmt.Sprint(want) {
		t.Errorf("Accept got CredentialQueryIDs %v, want %v", ids, want)
	}
}

// VerifyResponseDocuments verifies a one-document request's response
// too, as VerifyResponse does.
func TestVerifyResponseDocuments_OneDocument(t *testing.T) {
	h := newHarness(t, bothNames())
	response := respond(t, h.request.Data, testOrigin, h.f)
	vs, err := VerifyResponseDocuments(context.Background(), VerifyParams{
		Pending: h.request.Pending, Response: response, IssuerKeys: fixedIssuerKey{pub: h.f.IssuerKey.Public()},
		Assurance: verifier.AssuranceDevelopment, NoStatusCheck: true,
	})
	if err != nil || len(vs) != 1 || vs[0].DocType != testmdoc.DocType {
		t.Fatalf("VerifyResponseDocuments = %+v, %v", vs, err)
	}
}

func TestRespondDocumentsRefuses(t *testing.T) {
	h := newMultiHarness(t)
	unrequested := h.answer(1)
	unrequested.Elements = [][2]string{{testmdoc.Namespace, "family_name"}}
	noKey := h.answer(1)
	noKey.Holder = nil
	for name, answers := range map[string][]Answer{
		"none":           nil,
		"answered twice": {h.answer(0), h.answer(0)},
		"out of range":   {h.answer(0), {Document: 3, IssuerSigned: h.fixtures[0].IssuerSigned, Holder: h.fixtures[0].DeviceKey, Elements: [][2]string{{testmdoc.Namespace, "given_name"}}}},
		"unrequested":    {h.answer(0), unrequested},
		"no device key":  {h.answer(0), noKey},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := h.incoming.RespondDocuments(context.Background(), answers); err == nil {
				t.Fatal("RespondDocuments succeeded")
			}
		})
	}
}

// countingSigner counts its signatures, running then (if set) after each.
type countingSigner struct {
	crypto.Signer
	signed *int
	then   func()
}

func (s countingSigner) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	*s.signed++
	if s.then != nil {
		s.then()
	}
	return s.Signer.Sign(r, digest, opts)
}

// A credential holding none of the elements chosen for it fails the
// response before any key signs, not after the earlier documents' keys
// have: with user presence, each signature is a prompt.
func TestRespondDocuments_EmptySelectionBeforeAnySignature(t *testing.T) {
	h := newMultiHarness(t)
	signed := 0
	first := h.answer(0)
	first.Holder = countingSigner{Signer: first.Holder, signed: &signed}
	empty := h.answer(1)
	empty.IssuerSigned = empty.IssuerSigned.SelectNameSpaces([][2]string{{"org.example.none", "none"}})
	if _, err := h.incoming.RespondDocuments(context.Background(), []Answer{first, empty}); err == nil || !strings.Contains(err.Error(), "holds none") {
		t.Fatalf("RespondDocuments = %v, want the empty selection refused", err)
	}
	if signed != 0 {
		t.Errorf("%d keys signed before the empty selection was refused, want 0", signed)
	}
}

// An mdoc of another type than its document request asks for is
// refused before any key signs, so a holder can't present one document
// as another; an IssuerAuth that doesn't decode is refused too.
func TestRespondDocuments_DocTypeMismatchBeforeAnySignature(t *testing.T) {
	h := newMultiHarness(t)
	signed := 0
	first := h.answer(0)
	first.Holder = countingSigner{Signer: first.Holder, signed: &signed}
	swapped := h.answer(1)
	swapped.IssuerSigned = h.fixtures[2].IssuerSigned
	if _, err := h.incoming.RespondDocuments(context.Background(), []Answer{first, swapped}); err == nil || !strings.Contains(err.Error(), `the mdoc is a "org.example.c"`) {
		t.Fatalf("RespondDocuments = %v, want the org.example.c mdoc refused for org.example.b", err)
	}
	if signed != 0 {
		t.Errorf("%d keys signed before the mismatch was refused, want 0", signed)
	}
	garbled := h.answer(1)
	garbled.IssuerSigned.IssuerAuth = []byte{0x01}
	if _, err := h.incoming.RespondDocuments(context.Background(), []Answer{garbled}); err == nil || !strings.Contains(err.Error(), "IssuerAuth") {
		t.Fatalf("RespondDocuments = %v, want an undecodable IssuerAuth refused", err)
	}
	// Respond, for one document, checks the same.
	if _, err := h.incoming.Respond(0, h.fixtures[1].IssuerSigned, h.fixtures[1].DeviceKey, [][2]string{{testmdoc.Namespace, "given_name"}}); err == nil {
		t.Fatal("Respond answered org.example.a with an org.example.b mdoc")
	}
}

// Once ctx ends, no further holder key signs.
func TestRespondDocuments_CancelledBetweenKeys(t *testing.T) {
	h := newMultiHarness(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	firstSigned, secondSigned := 0, 0
	first := h.answer(0)
	first.Holder = countingSigner{Signer: first.Holder, signed: &firstSigned, then: cancel}
	second := h.answer(2)
	second.Holder = countingSigner{Signer: second.Holder, signed: &secondSigned}
	if _, err := h.incoming.RespondDocuments(ctx, []Answer{first, second}); !errors.Is(err, context.Canceled) {
		t.Fatalf("RespondDocuments = %v, want context.Canceled", err)
	}
	if firstSigned != 1 || secondSigned != 0 {
		t.Errorf("signed %d then %d, want 1 then 0", firstSigned, secondSigned)
	}
}

func TestBuildRequestDocumentsRefuses(t *testing.T) {
	doc := func(dt string) DocumentRequest {
		return DocumentRequest{DocType: dt, Elements: map[string]map[string]bool{testmdoc.Namespace: {"given_name": false}}}
	}
	many := make([]DocumentRequest, MaxDocRequests+1)
	for i := range many {
		many[i] = doc(fmt.Sprintf("org.example.%d", i))
	}
	for name, p := range map[string]RequestParams{
		"both":       {DocType: testmdoc.DocType, Elements: bothNames(), Documents: []DocumentRequest{doc("org.example.a")}},
		"twice":      {Documents: []DocumentRequest{doc("org.example.a"), doc("org.example.a")}},
		"too many":   {Documents: many},
		"no element": {Documents: []DocumentRequest{doc("org.example.a"), {DocType: "org.example.b"}}},
	} {
		t.Run(name, func(t *testing.T) {
			p.Origin = testOrigin
			if _, err := BuildRequest(p); err == nil {
				t.Fatal("BuildRequest succeeded")
			}
		})
	}
}
