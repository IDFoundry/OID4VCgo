// Package teststatuslist issues CWT Status List Tokens for tests, the
// well-formed one an mdoc's status names and the variants ISO/IEC
// 18013-5 §12.3.6.3 has a relying party refuse, and identifier lists
// (§12.3.6.4) — never for production use. A regular (not _test.go)
// package so more than one package's own tests can share it, as
// internal/testcert is.
package teststatuslist

import (
	"crypto/ecdsa"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/identifierlist"
	"github.com/idfoundry/oid4vcgo/internal/cose"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/statuslist"
)

// Signer is a status list signer: a leaf certificate under its own CA.
type Signer struct {
	CA    *x509.Certificate
	Key   *ecdsa.PrivateKey
	Chain []*x509.Certificate
}

// NewSigner is a Signer under a fresh CA.
func NewSigner(t testing.TB) Signer {
	t.Helper()
	ca, caKey := testcert.CA(t, "teststatuslist CA")
	leaf, key := testcert.Leaf(t, "teststatuslist signer", ca, caKey)
	return Signer{CA: ca, Key: key, Chain: []*x509.Certificate{leaf}}
}

// Variant is how a token departs from a well-formed one.
type Variant int

const (
	// WellFormed is a token with an exp and its x5chain in the
	// protected header.
	WellFormed Variant = iota
	// NoExp is a token without exp.
	NoExp
	// UnprotectedX5Chain is a token whose x5chain is in the unprotected
	// header (RFC 9360 allows it; ISO/IEC 18013-5 §12.3.6.3 doesn't).
	UnprotectedX5Chain
)

// Token is a CWT Status List Token served at uri, signed by s, every
// status in it valid, in form v.
func (s Signer) Token(t testing.TB, uri string, v Variant) []byte {
	t.Helper()
	list, err := statuslist.New(statuslist.Bits1, make([]uint8, 16), "")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	claims := statuslist.TokenClaims{Sub: uri, Iat: now.Add(-time.Minute).Unix(), StatusList: list}
	if v != NoExp {
		exp := now.Add(time.Hour).Unix()
		claims.Exp = &exp
	}
	token, err := statuslist.IssueTokenCWTX5Chain(s.Key, oid4vci.COSEES256, claims, s.Chain)
	if err != nil {
		t.Fatal(err)
	}
	if v != UnprotectedX5Chain {
		return token
	}
	// The same claims, re-signed with the x5chain moved out of the
	// protected header.
	_, _, payload, err := cose.DecodeUnverifiedTagged(token)
	if err != nil {
		t.Fatal(err)
	}
	ders := make([][]byte, len(s.Chain))
	for i, c := range s.Chain {
		ders[i] = c.Raw
	}
	token, err = cose.SignTagged(cose.ES256, s.Key, cose.Headers{Typ: statuslist.CWTTokenMediaType}, cose.Headers{X5Chain: ders}, payload, nil)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

// Serve serves s's token in form v over TLS, until t ends, and returns
// its URI and a client trusting the server.
func (s Signer) Serve(t testing.TB, v Variant) (uri string, client *http.Client) {
	t.Helper()
	uri, _, client = s.ServeLists(t, v)
	return uri, client
}

// IdentifierList is an identifier list (ISO/IEC 18013-5 §12.3.6.4)
// served at uri, signed by s, revoking the MSOs whose identifiers are
// revoked.
func (s Signer) IdentifierList(t testing.TB, uri string, revoked ...[]byte) []byte {
	t.Helper()
	now := time.Now()
	exp := now.Add(time.Hour).Unix()
	claims := identifierlist.TokenClaims{Sub: uri, Iat: now.Add(-time.Minute).Unix(), Exp: &exp, Identifiers: revoked}
	token, err := identifierlist.IssueToken(s.Key, oid4vci.COSEES256, claims, s.Chain, identifierlist.IssueOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return token
}

// ServeLists serves, from one server over TLS until t ends, s's status
// list token in form v and its identifier list revoking revoked, and
// returns their URIs and a client trusting the server.
func (s Signer) ServeLists(t testing.TB, v Variant, revoked ...[]byte) (statusURI, identifierListURI string, client *http.Client) {
	t.Helper()
	var status, identifiers atomic.Pointer[[]byte]
	mux := http.NewServeMux()
	mux.HandleFunc("/statuslists/1", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", statuslist.CWTTokenMediaType)
		_, _ = w.Write(*status.Load())
	})
	mux.HandleFunc("/identifierlists/1", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", identifierlist.MediaType)
		_, _ = w.Write(*identifiers.Load())
	})
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	statusURI, identifierListURI = srv.URL+"/statuslists/1", srv.URL+"/identifierlists/1"
	signedStatus, signedIdentifiers := s.Token(t, statusURI, v), s.IdentifierList(t, identifierListURI, revoked...)
	status.Store(&signedStatus)
	identifiers.Store(&signedIdentifiers)
	return statusURI, identifierListURI, srv.Client()
}
