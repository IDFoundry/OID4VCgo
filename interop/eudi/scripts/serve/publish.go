package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/conformancecert"
	"github.com/idfoundry/oid4vcgo/statuslist"
)

// publishedListSize is how many credentials each published list
// indexes; its Allocator stops at half of it.
const publishedListSize = 1 << 12

// publishedTokenLifetime bounds each served Status List Token (its
// exp). It carries no ttl, so a verifier has no lifetime to cache it
// for, and a status set through POST /status is what the next fetch
// reads.
const publishedTokenLifetime = time.Hour

// publishedList is one list served at its path: an SD-JWT VC's,
// served as a JWT by default, or an mdoc's, as a CWT.
type publishedList struct {
	path      string
	allocator *statuslist.Allocator
	publisher *statuslist.Publisher
}

// publishedLists are the run's two lists, by name: "jwt", the SD-JWT
// VC's, signed by its issuer, and "cwt", the mdoc's, signed by its
// Document Signer: what setup's static tokens were, published by
// statuslist instead.
type publishedLists map[string]*publishedList

// signerConfig is the part of a setup wallet config naming a
// credential's issuer and status list.
type signerConfig struct {
	SDJWTKeyPEM   string `json:"credential_issuer_private_key_pem"`
	SDJWTCertPEM  string `json:"credential_issuer_certificate_pem"`
	MdocKeyPEM    string `json:"mdoc_issuer_private_key_pem"`
	MdocCertPEM   string `json:"mdoc_issuer_certificate_pem"`
	StatusListURI string `json:"status_list_uri"`
}

// newPublishedLists builds the two lists from setup's wallet configs in
// dir.
func newPublishedLists(dir string) (publishedLists, error) {
	lists := publishedLists{}
	for name, file := range map[string]string{"jwt": "wallet-sdjwt.json", "cwt": "wallet-mdoc.json"} {
		raw, err := os.ReadFile(filepath.Join(dir, file)) // #nosec G304 -- the operator's own -dir
		if err != nil {
			return nil, err
		}
		var cfg signerConfig
		if err := json.Unmarshal(raw, &cfg); err != nil {
			return nil, fmt.Errorf("%s: %w", file, err)
		}
		keyPEM, certPEM, form := cfg.SDJWTKeyPEM, cfg.SDJWTCertPEM, statuslist.FormJWT
		if name == "cwt" {
			keyPEM, certPEM, form = cfg.MdocKeyPEM, cfg.MdocCertPEM, statuslist.FormCWT
		}
		key, err := conformancecert.ParseECPrivateKeyPEM(keyPEM)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", file, err)
		}
		cert, err := conformancecert.ParseCertificatePEM(certPEM)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", file, err)
		}
		list, err := newPublishedList(cfg.StatusListURI, key, cert, form)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", file, err)
		}
		lists[name] = list
	}
	return lists, nil
}

func newPublishedList(uri string, key crypto.Signer, cert *x509.Certificate, form statuslist.Form) (*publishedList, error) {
	i := strings.Index(strings.TrimPrefix(uri, "https://"), "/")
	if !strings.HasPrefix(uri, "https://") || i < 0 {
		return nil, fmt.Errorf("status_list_uri %q has no https path", uri)
	}
	// The SD-JWT VC's list takes 2 bits a status, so it can say
	// SUSPENDED too; an mdoc's takes 1 (ISO/IEC 18013-5 §12.3.6.5).
	bits := statuslist.Bits2
	if form == statuslist.FormCWT {
		bits = statuslist.Bits1
	}
	allocator := &statuslist.Allocator{
		Lists: []statuslist.AllocatorList{{URI: uri, Size: publishedListSize}},
		Store: &statuslist.MemoryIndexStore{}, Bits: bits,
	}
	publisher := &statuslist.Publisher{
		URI: uri, Signer: key, Chain: []*x509.Certificate{cert}, Bits: bits,
		Statuses: allocator.Statuses(uri), DefaultForm: form, Lifetime: publishedTokenLifetime,
		OnError: func(_ *http.Request, err error) { log.Printf("status list %s: %v", uri, err) },
	}
	if _, err := publisher.Token(context.Background(), form == statuslist.FormCWT); err != nil {
		return nil, err
	}
	return &publishedList{path: uri[len("https://")+i:], allocator: allocator, publisher: publisher}, nil
}

// route serves each list at its path, logging each fetch and the form
// served, as serve logs the documents it serves.
func (l publishedLists) route(mux *http.ServeMux) {
	for _, list := range l {
		path := "GET " + list.path
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			rec := &contentTypeRecorder{ResponseWriter: w}
			list.publisher.ServeHTTP(rec, r)
			log.Printf("served %s", path)
			log.Printf("  as %s, status %d", rec.Header().Get("Content-Type"), rec.status)
		})
	}
}

// contentTypeRecorder keeps the status a handler writes.
type contentTypeRecorder struct {
	http.ResponseWriter
	status int
}

func (r *contentTypeRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func (r *contentTypeRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.ResponseWriter.Write(b)
}

// adminServer serves the issuer's side of the lists on addr, a
// loopback address: POST /allocate?list=jwt|cwt hands out an index
// (statuslist.Allocator.Allocate), answering {"idx": ..., "uri": ...};
// POST /status with {"list": ..., "idx": ..., "status": "VALID" |
// "INVALID" | "SUSPENDED"} sets an index handed out to that status
// (Allocator.SetStatus) and has the list signed again on its next
// fetch (Publisher.Invalidate).
func adminServer(addr string, lists publishedLists) *http.Server {
	host, _, err := net.SplitHostPort(addr)
	if ip := net.ParseIP(host); err != nil || ip == nil || !ip.IsLoopback() {
		log.Fatalf("-admin %q isn't a loopback address", addr)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /allocate", func(w http.ResponseWriter, r *http.Request) {
		list, ok := lists[r.URL.Query().Get("list")]
		if !ok {
			http.Error(w, "list must be jwt or cwt", http.StatusBadRequest)
			return
		}
		ref, err := list.allocator.Allocate(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		log.Printf("allocated index %d of %s", ref.Idx, list.path)
		writeJSON(w, map[string]any{"idx": ref.Idx, "uri": ref.URI})
	})
	mux.HandleFunc("POST /status", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			List   string `json:"list"`
			Idx    uint64 `json:"idx"`
			Status string `json:"status"`
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4<<10))
		dec := json.NewDecoder(bytes.NewReader(body))
		dec.DisallowUnknownFields()
		if err != nil || dec.Decode(&req) != nil {
			http.Error(w, "malformed status request", http.StatusBadRequest)
			return
		}
		list, ok := lists[req.List]
		status, known := map[string]statuslist.StatusType{
			"VALID": statuslist.StatusValid, "INVALID": statuslist.StatusInvalid, "SUSPENDED": statuslist.StatusSuspended,
		}[req.Status]
		if !ok || !known {
			http.Error(w, "list must be jwt or cwt, and status VALID, INVALID or SUSPENDED", http.StatusBadRequest)
			return
		}
		ref := statuslist.StatusListRef{Idx: req.Idx, URI: list.publisher.URI}
		if err := list.allocator.SetStatus(r.Context(), ref, status); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		list.publisher.Invalidate()
		log.Printf("set index %d of %s to %s", req.Idx, list.path, status)
		writeJSON(w, map[string]any{"idx": req.Idx, "uri": ref.URI, "status": status.String()})
	})
	return &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(v)
}
