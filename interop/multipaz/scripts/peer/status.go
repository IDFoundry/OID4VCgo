package main

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/idfoundry/oid4vcgo/statuslist"
)

// statusListSize is how many credentials each of the peer's status
// lists indexes; its Allocator stops at half of it.
const statusListSize = 1 << 12

// statusState is the Token Status Lists the holder's credentials name,
// published as an issuer publishes them: an Allocator hands each
// credential its index and keeps its status, and a Publisher signs the
// list from it on each fetch, by the credential's issuer. They're
// served over TLS on loopback with the peer's localhost certificate,
// for Multipaz's revocation checker to fetch, at /statuslists/<format>:
// the mDL's as a CWT, the PID's as a JWT, when a request names neither.
// The tokens carry no ttl, so a status set with the status_set op is
// what the next fetch reads.
type statusState struct {
	base  string
	mux   *http.ServeMux
	lists map[string]*heldStatus // by credential format
}

// heldStatus is one list and the index of the credential the holder
// holds on it.
type heldStatus struct {
	allocator *statuslist.Allocator
	publisher *statuslist.Publisher
	ref       statuslist.StatusListRef
}

// startStatus serves the status lists on a loopback port with the
// peer's TLS certificate.
func (p *peer) startStatus(certPEM, keyPEM string) error {
	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return err
	}
	listener, err := tls.Listen("tcp", net.JoinHostPort(loopback.String(), "0"), &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	if err != nil {
		return err
	}
	p.status = statusState{
		base:  "https://localhost:" + strconv.Itoa(listener.Addr().(*net.TCPAddr).Port),
		mux:   http.NewServeMux(),
		lists: map[string]*heldStatus{},
	}
	server := &http.Server{Handler: p.status.mux, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		if err := server.Serve(listener); !errors.Is(err, http.ErrServerClosed) {
			log.Printf("status lists: %v", err)
		}
	}()
	return nil
}

// allocateStatus adds the list for format, signed by key with its
// certificate chain, and hands the holder's credential of that format
// its index, which it returns.
func (p *peer) allocateStatus(format string, key crypto.Signer, chain []*x509.Certificate, form statuslist.Form) (statuslist.StatusListRef, error) {
	path := "/statuslists/" + map[string]string{"mso_mdoc": "mdl", "dc+sd-jwt": "pid"}[format]
	uri := p.status.base + path
	allocator := &statuslist.Allocator{
		Lists: []statuslist.AllocatorList{{URI: uri, Size: statusListSize}},
		Store: &statuslist.MemoryIndexStore{},
	}
	publisher := &statuslist.Publisher{
		URI: uri, Signer: key, Chain: chain, Statuses: allocator.Statuses(uri), DefaultForm: form, Lifetime: time.Hour,
		OnError: func(_ *http.Request, err error) { log.Printf("status list %s: %v", path, err) },
	}
	ctx := context.Background()
	if _, err := publisher.Token(ctx, form == statuslist.FormCWT); err != nil {
		return statuslist.StatusListRef{}, err
	}
	ref, err := allocator.Allocate(ctx)
	if err != nil {
		return statuslist.StatusListRef{}, err
	}
	p.status.lists[format] = &heldStatus{allocator: allocator, publisher: publisher, ref: ref}
	p.status.mux.HandleFunc("GET "+path, func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w}
		publisher.ServeHTTP(rec, r)
		// Only what was served: request data stays out of the log.
		log.Printf("status list %s served as %s, %d", path, rec.Header().Get("Content-Type"), rec.status)
	})
	return ref, nil
}

// statusSet sets the status of the holder's credential of req.Format to
// req.Status (VALID, INVALID or SUSPENDED), as its issuer revokes it or
// lifts a revocation, through the Allocator, and has the list signed
// again on its next fetch.
func (p *peer) statusSet(req request) (reply, error) {
	held, ok := p.status.lists[req.Format]
	if !ok {
		return reply{}, fmt.Errorf("no status list for %q", req.Format)
	}
	status, ok := map[string]statuslist.StatusType{
		"VALID": statuslist.StatusValid, "INVALID": statuslist.StatusInvalid, "SUSPENDED": statuslist.StatusSuspended,
	}[req.Status]
	if !ok {
		return reply{}, fmt.Errorf("status %q isn't VALID, INVALID or SUSPENDED", req.Status)
	}
	if err := held.allocator.SetStatus(context.Background(), held.ref, status); err != nil {
		return reply{}, err
	}
	held.publisher.Invalidate()
	log.Printf("status list %s: index %d set to %s", held.ref.URI, held.ref.Idx, status)
	return reply{Claims: map[string]any{"uri": held.ref.URI, "idx": strconv.FormatUint(held.ref.Idx, 10)}}, nil
}

// statusRecorder keeps the status a handler writes.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.ResponseWriter.Write(b)
}
