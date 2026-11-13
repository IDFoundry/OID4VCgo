package conformancesuite

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"
)

// ServerCertificate is the TLS certificate the server at rawURL
// presents, read off a connection without verifying it, as one would
// pin it by hand: a locally run suite's nginx certificate is
// self-signed for the Common Name localhost, without the
// subjectAltName Go checks a host name against, so nothing could
// verify it otherwise.
func ServerCertificate(ctx context.Context, rawURL string) (*x509.Certificate, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parse %q: %w", rawURL, err)
	}
	if u.Hostname() == "" {
		return nil, fmt.Errorf("%q names no host", rawURL)
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	host := net.JoinHostPort(u.Hostname(), port)
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 10 * time.Second},
		Config:    &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}, //nolint:gosec // reading the certificate to pin, not trusting the connection
	}
	conn, err := dialer.DialContext(ctx, "tcp", host)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	certs := conn.(*tls.Conn).ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, fmt.Errorf("%s presented no certificate", host)
	}
	return certs[0], nil
}

// PinnedHTTPClient is an HTTP client that accepts a TLS server only
// when it presents pinned as its certificate, for any host name: every
// host the suite is reached by (localhost, localhost.emobix.co.uk, its
// mTLS port) serves the same certificate.
func PinnedHTTPClient(pinned *x509.Certificate) *http.Client {
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS12,
		// Go verifies a chain only for a host name, which the pinned
		// certificate doesn't name, so VerifyConnection does it all.
		InsecureSkipVerify: true, //nolint:gosec // VerifyConnection verifies every handshake instead
		VerifyConnection:   func(cs tls.ConnectionState) error { return verifyPinned(pinned, cs) },
	}}}
}

// verifyPinned accepts cs only when its server presented pinned.
func verifyPinned(pinned *x509.Certificate, cs tls.ConnectionState) error {
	if len(cs.PeerCertificates) == 0 {
		return errors.New("suite tls certificate: the server presented none")
	}
	if !bytes.Equal(cs.PeerCertificates[0].Raw, pinned.Raw) {
		return fmt.Errorf("suite tls certificate: %s presented %q, not the pinned certificate", cs.ServerName, cs.PeerCertificates[0].Subject)
	}
	return nil
}
