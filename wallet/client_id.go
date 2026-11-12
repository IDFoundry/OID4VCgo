package wallet

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// The Client Identifier Prefixes this package accepts (OpenID4VP 1.0
// §5.9.3): x509_hash always, as HAIP 1.0 §5 requires, and x509_san_dns
// only when a caller opts in (Config.AcceptX509SANDNS).
const (
	x509HashPrefix   = "x509_hash:"
	x509SANDNSPrefix = "x509_san_dns:"
)

// maxDNSNameLength is the longest DNS name, in its text form without
// a trailing dot (RFC 1035 §2.3.4).
const maxDNSNameLength = 253

// x509HashClientID is the x509_hash Client Identifier cert stands for
// (OpenID4VP 1.0 §5.9.3): the base64url SHA-256 hash of its DER.
func x509HashClientID(cert *x509.Certificate) string {
	hash := sha256.Sum256(cert.Raw)
	return x509HashPrefix + base64.RawURLEncoding.EncodeToString(hash[:])
}

// bindClientID checks clientID is bound to cert, the signing leaf of a
// Request Object whose signature and chain trust have been verified,
// and returns the DNS name an x509_san_dns clientID names, "" for an
// x509_hash one.
//
// x509_hash (OpenID4VP 1.0 §5.9.3) is bound when it's cert's own hash.
// With acceptSANDNS, x509_san_dns is bound when "the original Client
// Identifier (the part after the x509_san_dns: prefix) MUST be a DNS
// name and match a dNSName Subject Alternative Name (SAN) [RFC5280]
// entry in the leaf certificate" (§5.9.3): compared without regard to
// case (RFC 4343), and exactly, so a wildcard SAN matches no name. A
// certificate name says nothing on its own: only a chain verified to
// the Wallet's trust anchors ties it to the Verifier ("The Wallet MUST
// validate the signature and the trust chain of the X.509
// certificate"), so x509_san_dns is refused under NoVerifierTrust,
// which verifies no chain. Every other Client Identifier, and
// x509_san_dns without acceptSANDNS, is refused as not being cert's
// x509_hash, as before x509_san_dns was supported (§5.9.2: a Wallet
// "may refuse the request" for a prefix it doesn't support).
func bindClientID(clientID string, cert *x509.Certificate, acceptSANDNS bool, trust VerifierTrust) (string, error) {
	hash := x509HashClientID(cert)
	name, isSANDNS := strings.CutPrefix(clientID, x509SANDNSPrefix)
	if !isSANDNS || !acceptSANDNS {
		if clientID != hash {
			return "", fmt.Errorf("client_id %q does not match x5c leaf's own x509_hash %q", clientID, hash)
		}
		return "", nil
	}
	if isNoVerifierTrust(trust) {
		return "", fmt.Errorf("%w: client_id %q: x509_san_dns needs the x5c chain verified to trust anchors, which NoVerifierTrust doesn't do", ErrUntrustedVerifier, clientID)
	}
	if err := checkDNSName(name); err != nil {
		return "", fmt.Errorf("client_id %q: %w", clientID, err)
	}
	for _, san := range cert.DNSNames {
		if strings.EqualFold(san, name) {
			return name, nil
		}
	}
	return "", fmt.Errorf("client_id %q: %q is not a dNSName subject alternative name of the x5c leaf (dNSNames %q)", clientID, name, cert.DNSNames)
}

// checkDNSName refuses a name that isn't a DNS host name (RFC 1123
// §2.1: letters, digits and hyphens, labels of 1 to 63 octets neither
// starting nor ending with a hyphen): an IP address, a wildcard, a
// trailing dot or an empty label among them.
func checkDNSName(name string) error {
	if name == "" || len(name) > maxDNSNameLength || net.ParseIP(name) != nil {
		return fmt.Errorf("%q isn't a DNS name", name)
	}
	for _, label := range strings.Split(name, ".") {
		if !isDNSLabel(label) {
			return fmt.Errorf("%q isn't a DNS name", name)
		}
	}
	return nil
}

func isDNSLabel(label string) bool {
	if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for _, c := range []byte(label) {
		if !isLDH(c) {
			return false
		}
	}
	return true
}

// isLDH reports whether c is a letter, digit or hyphen.
func isLDH(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-'
}

// checkResponseURIHost is OpenID4VP 1.0 §5.9.3's rule for an
// x509_san_dns Client Identifier outside the DC API: "If the Wallet can
// establish trust in the Client Identifier authenticated through the
// certificate, e.g. because the Client Identifier is contained in a
// list of trusted Client Identifiers, it may allow the client to freely
// choose the redirect_uri value. If not, the FQDN of the redirect_uri
// value MUST match the Client Identifier without the prefix
// x509_san_dns:". The Wallet answers at response_uri (the redirect_uri
// prefix reads redirect_uri as "Response URI when Response Mode
// direct_post is used"), and keeps no list of trusted Client
// Identifiers, so the match is always required: otherwise any Verifier
// with a trusted certificate for its own name could have the response
// sent anywhere. dnsName is "" for x509_hash, which has no such rule.
func checkResponseURIHost(responseURI, dnsName string) error {
	if dnsName == "" {
		return nil
	}
	u, err := url.Parse(responseURI)
	if err != nil {
		return fmt.Errorf("response_uri: %w", err)
	}
	if !strings.EqualFold(u.Hostname(), dnsName) {
		return fmt.Errorf("response_uri host %q isn't %q, the x509_san_dns client_id's DNS name (OpenID4VP 1.0 §5.9.3)", u.Hostname(), dnsName)
	}
	return nil
}

// errX509SANDNSNeedsTrustAnchors is New's refusal of
// Config.AcceptX509SANDNS without a VerifierTrust that verifies chains.
var errX509SANDNSNeedsTrustAnchors = errors.New("wallet: config: accept_x509_san_dns needs a VerifierTrust that verifies the x5c chain to trust anchors: X5CVerifierRoots with Roots, or another VerifierTrust, never NoVerifierTrust or none")

// checkAcceptX509SANDNS refuses AcceptX509SANDNS where nothing would
// verify a Verifier's chain: no VerifierTrust, NoVerifierTrust, or an
// X5CVerifierRoots without Roots. x509_hash binds the request to one
// certificate even then; x509_san_dns binds it to a name any
// certificate can carry, so without chain trust it would bind it to
// nothing.
func checkAcceptX509SANDNS(cfg Config) error {
	if !cfg.AcceptX509SANDNS {
		return nil
	}
	switch t := cfg.VerifierTrust.(type) {
	case nil, NoVerifierTrust, *NoVerifierTrust:
		return errX509SANDNSNeedsTrustAnchors
	case X5CVerifierRoots:
		if t.Roots == nil {
			return errX509SANDNSNeedsTrustAnchors
		}
	case *X5CVerifierRoots:
		if t == nil || t.Roots == nil {
			return errX509SANDNSNeedsTrustAnchors
		}
	}
	return nil
}
