package statuslist_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"time"

	"github.com/idfoundry/oid4vcgo/statuslist"
)

// A list both SD-JWT VCs and mdocs reference, served from two
// Publishers at two URIs over one set of statuses. A Relying Party
// sending no Accept header gets the form DefaultForm names, so SD-JWT
// VCs reference the JWT list and mdocs the CWT one; a request naming a
// form gets it at either URI. A credential keeps one index, read the
// same way in both lists, and a status change invalidates both.
func ExamplePublisher_bothFormats() {
	signer, chain := statusListSigner()

	// The issuer's statuses: one per index, whichever format it was
	// issued in.
	var mu sync.Mutex
	revoked := make([]uint8, 1024)
	statuses := func(context.Context) ([]uint8, error) {
		mu.Lock()
		defer mu.Unlock()
		return append([]uint8(nil), revoked...), nil
	}

	const base = "https://issuer.example"
	jwtList := &statuslist.Publisher{URI: base + "/statuslists/1", Signer: signer, Chain: chain,
		Statuses: statuses} // DefaultForm zero: FormJWT
	cwtList := &statuslist.Publisher{URI: base + "/statuslists/1/cwt", Signer: signer, Chain: chain,
		Statuses: statuses, DefaultForm: statuslist.FormCWT}
	mux := http.NewServeMux()
	mux.Handle("/statuslists/1", jwtList)
	mux.Handle("/statuslists/1/cwt", cwtList)

	// At issuance: an SD-JWT VC's status names the JWT list, an mdoc's
	// the CWT list.
	sdjwtStatus := statuslist.StatusListRef{Idx: 7, URI: jwtList.URI}
	mdocStatus := statuslist.StatusListRef{Idx: 8, URI: cwtList.URI}
	fmt.Println("SD-JWT VC references", sdjwtStatus.URI)
	fmt.Println("mdoc references", mdocStatus.URI)

	served := func(path string, accept string) string {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		if accept != "" {
			r.Header.Set("Accept", accept)
		}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, r)
		return rec.Header().Get("Content-Type")
	}
	fmt.Println("no Accept, JWT list:", served("/statuslists/1", ""))
	fmt.Println("no Accept, CWT list:", served("/statuslists/1/cwt", ""))
	fmt.Println("CWT asked for, JWT list:", served("/statuslists/1", statuslist.CWTTokenMediaType))

	// Revoking: change the status, then invalidate both Publishers, so
	// neither serves a token signed before the change.
	mu.Lock()
	revoked[mdocStatus.Idx] = 1
	mu.Unlock()
	jwtList.Invalidate()
	cwtList.Invalidate()

	// Output:
	// SD-JWT VC references https://issuer.example/statuslists/1
	// mdoc references https://issuer.example/statuslists/1/cwt
	// no Accept, JWT list: application/statuslist+jwt
	// no Accept, CWT list: application/statuslist+cwt
	// CWT asked for, JWT list: application/statuslist+cwt
}

// statusListSigner returns a P-256 key and its certificate, issued by
// a throwaway CA: in a real deployment, the issuer's status list signer
// and its chain to a root Relying Parties trust.
func statusListSigner() (*ecdsa.PrivateKey, []*x509.Certificate) {
	now := time.Now()
	caKey := must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Example Issuer CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	ca := must(x509.ParseCertificate(must(x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey))))
	key := must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Example Status List Signer"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	leaf := must(x509.ParseCertificate(must(x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey))))
	return key, []*x509.Certificate{leaf}
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}
