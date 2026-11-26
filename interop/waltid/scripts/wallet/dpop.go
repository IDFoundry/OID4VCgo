package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/idfoundry/oid4vcgo/internal/jose"
)

// issueEndpointSuffix is the path a Credential Endpoint's URL ends in
// (its name avoids gosec G101, which takes "cred" for a credential).
const issueEndpointSuffix = "/credential"

// dpopTamperer is the http.RoundTripper -tamper-dpop puts in front of
// the wallet's transport: it signs every Credential Request's DPoP
// proof again with the wallet's DPoP key, its htu naming the issuer's
// Notification Endpoint instead of its Credential Endpoint, as a proof
// made for another request would. Nothing else of the request
// changes; an issuer must refuse it (RFC 9449 §4.3).
type dpopTamperer struct {
	next http.RoundTripper
	keys *keyring

	mu      sync.Mutex
	changed string
}

func (d *dpopTamperer) RoundTrip(req *http.Request) (*http.Response, error) {
	proof := req.Header.Get("DPoP")
	if req.Method != http.MethodPost || !strings.HasSuffix(req.URL.Path, issueEndpointSuffix) || proof == "" {
		return d.next.RoundTrip(req)
	}
	changed, what, err := d.rewrite(proof)
	if err != nil {
		return nil, fmt.Errorf("tamper: DPoP proof: %w", err)
	}
	d.mu.Lock()
	d.changed = what
	d.mu.Unlock()
	req = req.Clone(req.Context())
	req.Header.Set("DPoP", changed)
	return d.next.RoundTrip(req)
}

// rewrite is proof signed again, its htu another endpoint's, and what
// changed.
func (d *dpopTamperer) rewrite(proof string) (string, string, error) {
	header, payload, err := jose.DecodeUnverifiedMax(proof, maxRecordedBody)
	if err != nil {
		return "", "", err
	}
	claims, err := decodeObject(payload)
	if err != nil {
		return "", "", err
	}
	htu, _ := claims["htu"].(string)
	if !strings.HasSuffix(htu, issueEndpointSuffix) {
		return "", "", fmt.Errorf("htu %q isn't a Credential Endpoint", htu)
	}
	other := strings.TrimSuffix(htu, issueEndpointSuffix) + "/notification"
	claims["htu"] = other
	jwkHeader, _ := header["jwk"].(map[string]any)
	pub, err := publicKey(jwkHeader)
	if err != nil {
		return "", "", fmt.Errorf("jwk: %w", err)
	}
	key, ok := d.keys.signerFor(pub)
	if !ok {
		return "", "", errors.New("no key of the wallet's signed it")
	}
	out, err := json.Marshal(claims)
	if err != nil {
		return "", "", err
	}
	delete(header, "alg")
	signed, err := jose.Sign(jose.ES256, key, header, out)
	return signed, "htu " + htu + " → " + other, err
}

// outcome is what the tamperer changed; nil if no Credential Request
// went through it.
func (d *dpopTamperer) outcome() *tampered {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.changed == "" {
		return nil
	}
	return &tampered{Mode: "dpop-htu", Changed: d.changed}
}
