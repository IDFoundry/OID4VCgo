package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/internal/conformancecert"
	"github.com/idfoundry/oid4vcgo/internal/strictjson"
	"github.com/idfoundry/oid4vcgo/issuer"
	"github.com/idfoundry/oid4vcgo/statuslist"
)

// StatusListsConfig is Config.StatusLists: every Credential issued
// carries a Token Status List reference (draft-ietf-oauth-status-list,
// HAIP 1.0 §6.1), its index drawn at random by a statuslist.Allocator
// and the list served by statuslist.Publisher, as a deployment
// publishes one. SD-JWT VCs name the list at statusListPath, served as
// a JWT when the request names no form, signed by the SD-JWT VC
// issuer's key with its certificate in x5c; mdocs name the same list
// at mdocStatusListPath, served as a CWT when the request names no
// form, signed by MdocSignerKeyPEM, or by the mdoc Document Signer
// when that's unset. A credential keeps one index, read the same way
// at either URI.
type StatusListsConfig struct {
	// BaseURL, if set, is where Relying Parties fetch the lists, in
	// place of Issuer: the credentials' status references, and the
	// tokens' sub, name BaseURL+statusListPath. The lists are still
	// served at statusListPath on the issuer's own listener, for a
	// proxy at BaseURL to reach (interop/waltid/run.sh).
	BaseURL string `json:"base_url,omitempty"`

	// MdocSignerKeyPEM and MdocSignerCertificatePEM, if set, sign the
	// list mdocs reference: an MSO revocation list signer (ISO/IEC
	// 18013-5 Table B.9) under the mdoc's IACA. Set both or neither.
	MdocSignerKeyPEM         string `json:"mdoc_signer_key_pem,omitempty"`
	MdocSignerCertificatePEM string `json:"mdoc_signer_certificate_pem,omitempty"`
}

// The paths the status list is served at, under the Credential Issuer's
// identifier.
const (
	statusListPath     = "/statuslists/1"
	mdocStatusListPath = statusListPath + "/cwt"
)

// statusListSize is how many credentials the list indexes: the
// Allocator stops at half of it (statuslist.DefaultFillLimit), far more
// than a conformance or interop run issues.
const statusListSize = 1 << 16

// statusTokenLifetime bounds a served Status List Token (its exp). No
// ttl is set, so a Relying Party has no lifetime to cache the token
// for: a status changed through statusHandler is what the next fetch
// reads.
const statusTokenLifetime = time.Hour

// maxStatusRequestBytes bounds a statusHandler request.
const maxStatusRequestBytes = 4 << 10

// statusLists is the issuer's one Token Status List: the Allocator that
// hands its indices out and keeps their statuses, and the Publishers
// serving it at both URIs (cwt nil without an mdoc configuration).
type statusLists struct {
	allocator    *statuslist.Allocator
	uri, mdocURI string
	jwt, cwt     *statuslist.Publisher
}

// statusListSigner is a Publisher's signer and its certificate chain.
type statusListSigner struct {
	key   crypto.Signer
	chain []*x509.Certificate
}

// newStatusLists is the list at cfg.Issuer+statusListPath, its indices
// and statuses in store, served signed by sdjwt and, when set, by mdoc
// at mdocStatusListPath. Nil when cfg.StatusLists is unset.
func newStatusLists(cfg Config, store statuslist.IndexStore, sdjwt statusListSigner, mdocSigner *statusListSigner) (*statusLists, error) {
	if cfg.StatusLists == nil {
		return nil, nil
	}
	base := cfg.Issuer
	if cfg.StatusLists.BaseURL != "" {
		base = cfg.StatusLists.BaseURL
	}
	s := &statusLists{uri: base + statusListPath, mdocURI: base + mdocStatusListPath}
	s.allocator = &statuslist.Allocator{
		Lists: []statuslist.AllocatorList{{URI: s.uri, Size: statusListSize}},
		Store: store,
	}
	statuses := s.allocator.Statuses(s.uri)
	publisher := func(uri string, form statuslist.Form, signer statusListSigner) *statuslist.Publisher {
		return &statuslist.Publisher{
			URI: uri, Signer: signer.key, Chain: signer.chain,
			// Both URIs serve the one list the Allocator hands out.
			Statuses: statuses, DefaultForm: form, Lifetime: statusTokenLifetime,
			OnError: func(_ *http.Request, err error) { log.Printf("status list %s: %v", uri, err) },
		}
	}
	s.jwt = publisher(s.uri, statuslist.FormJWT, sdjwt)
	if _, err := s.jwt.Token(context.Background(), false); err != nil {
		return nil, fmt.Errorf("status list: %w", err)
	}
	if mdocSigner != nil {
		s.cwt = publisher(s.mdocURI, statuslist.FormCWT, *mdocSigner)
		if _, err := s.cwt.Token(context.Background(), true); err != nil {
			return nil, fmt.Errorf("mdoc status list: %w", err)
		}
	}
	return s, nil
}

// mdocStatusListSigner is the signer of the list mdocs reference:
// cfg.StatusLists' own MSO revocation list signer, or the mdoc's
// Document Signer, key and certificate, when it names none.
func mdocStatusListSigner(cfg Config, ds *issuer.MdocSigner) (*statusListSigner, error) {
	if ds == nil {
		return nil, nil
	}
	if sl := cfg.StatusLists; sl.MdocSignerKeyPEM != "" {
		key, err := conformancecert.ParseECPrivateKeyPEM(sl.MdocSignerKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("status_lists.mdoc_signer_key_pem: %w", err)
		}
		cert, err := conformancecert.ParseCertificatePEM(sl.MdocSignerCertificatePEM)
		if err != nil {
			return nil, fmt.Errorf("status_lists.mdoc_signer_certificate_pem: %w", err)
		}
		return &statusListSigner{key: key, chain: []*x509.Certificate{cert}}, nil
	}
	chain := make([]*x509.Certificate, 0, len(ds.X5Chain))
	for _, der := range ds.X5Chain {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("mdoc document signer certificate: %w", err)
		}
		chain = append(chain, cert)
	}
	return &statusListSigner{key: ds.Signer, chain: chain}, nil
}

// validateStatusLists checks StatusLists, when set.
func validateStatusLists(cfg Config) error {
	sl := cfg.StatusLists
	if sl == nil {
		return nil
	}
	if (sl.MdocSignerKeyPEM == "") != (sl.MdocSignerCertificatePEM == "") {
		return errors.New("config: status_lists.mdoc_signer_key_pem and status_lists.mdoc_signer_certificate_pem must be set together")
	}
	if sl.MdocSignerKeyPEM != "" && cfg.Mdoc == nil {
		return errors.New("config: status_lists.mdoc_signer_key_pem needs mdoc")
	}
	if sl.BaseURL != "" {
		if u, err := url.Parse(sl.BaseURL); err != nil || u.Scheme != "https" || u.Host == "" || u.Path != "" || u.RawQuery != "" {
			return fmt.Errorf("config: status_lists.base_url %q isn't an https origin", sl.BaseURL)
		}
	}
	return nil
}

// perBatch gives each Credential of a batch its own index (HAIP 1.0
// §6.1), the batch's reserved at once: an SD-JWT VC's status claim
// names the list at uri, an mdoc's MSO status the same index at
// mdocURI.
func (s *statusLists) perBatch(ctx context.Context, batch []*issuer.CredentialInstance) error {
	refs, err := s.allocator.AllocateN(ctx, len(batch))
	if err != nil {
		return err
	}
	for i, c := range batch {
		if c.SDJWTClaims != nil {
			c.SDJWTClaims.Status = refs[i].Claim()
		}
		if c.MdocClaims != nil {
			c.MdocClaims.Status = &mdoc.StatusListRef{Idx: refs[i].Idx, URI: s.mdocURI}
		}
	}
	return nil
}

// route serves the list at its paths on mux.
func (s *statusLists) route(mux *http.ServeMux) {
	mux.Handle("GET "+statusListPath, s.jwt)
	if s.cwt != nil {
		mux.Handle("GET "+mdocStatusListPath, s.cwt)
	}
}

// statusRequest is a statusHandler request: the reference a credential
// carries, at either URI, and the status to give it.
type statusRequest struct {
	URI    string `json:"uri"`
	Idx    uint64 `json:"idx"`
	Status string `json:"status"`
}

// statusHandler changes a credential's status, as an issuer revokes or
// suspends one: POST /status with a statusRequest, whose status is
// VALID, INVALID or SUSPENDED. It sets it through
// statuslist.Allocator.SetStatus, which refuses an index never handed
// out, and has both Publishers sign the list again on the next request
// (Publisher.Invalidate). It's served on the loopback offers listener
// only, beside the offers a harness mints.
func (s *statusLists) statusHandler(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxStatusRequestBytes))
	var req statusRequest
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err != nil || strictjson.Unmarshal(body, &req) != nil || dec.Decode(&statusRequest{}) != nil {
		http.Error(w, "malformed status request", http.StatusBadRequest)
		return
	}
	var status statuslist.StatusType
	switch req.Status {
	case statuslist.StatusValid.String():
		status = statuslist.StatusValid
	case statuslist.StatusInvalid.String():
		status = statuslist.StatusInvalid
	case statuslist.StatusSuspended.String():
		status = statuslist.StatusSuspended
	default:
		http.Error(w, "status must be VALID, INVALID or SUSPENDED", http.StatusBadRequest)
		return
	}
	if req.URI != s.uri && (s.cwt == nil || req.URI != s.mdocURI) {
		http.Error(w, "unknown status list uri", http.StatusBadRequest)
		return
	}
	if err := s.allocator.SetStatus(r.Context(), statuslist.StatusListRef{Idx: req.Idx, URI: s.uri}, status); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.jwt.Invalidate()
	if s.cwt != nil {
		s.cwt.Invalidate()
	}
	log.Printf("status list: index %d set to %s", req.Idx, status)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{"uri": req.URI, "idx": req.Idx, "status": status.String()})
}
