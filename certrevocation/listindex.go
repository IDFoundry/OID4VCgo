package certrevocation

import (
	"crypto/sha256"
	"crypto/x509"
	"math/big"
	"runtime"
	"sync"
	"weak"
)

// listIndex is what checking against one parsed CRL finds that depends
// on the list alone, kept so a check of the next chain doesn't find it
// again: whether its form makes it usable at all, the serial numbers it
// revokes, and which issuers' keys its signature verified, or failed
// to verify, under. A Refresher hands out the same parsed lists until
// it replaces them, so on the request path, checking a chain against a
// list of a million entries is a map lookup, not a walk of the entries
// and a signature verification per link.
type listIndex struct {
	// raw is the list's DER the index was built from, by address and
	// length: a list given again with other bytes in place is indexed
	// anew.
	raw     *byte
	rawLen  int
	once    sync.Once
	usable  bool // completeAndDirect and criticalUnderstood
	revoked map[string]struct{}

	mu       sync.Mutex
	verified map[[sha256.Size]byte]bool // issuer certificate → its key verified the list
}

var (
	listIndexesMu sync.Mutex
	listIndexes   = map[weak.Pointer[x509.RevocationList]]*listIndex{}
)

// indexOf is list's index, built on first use and dropped once list is
// unreachable. A list without its DER, built by hand rather than
// parsed, has none: it's checked as it stands each time.
func indexOf(list *x509.RevocationList) *listIndex {
	if len(list.Raw) == 0 {
		return nil
	}
	key := weak.Make(list)
	listIndexesMu.Lock()
	idx, ok := listIndexes[key]
	if !ok || idx.raw != &list.Raw[0] || idx.rawLen != len(list.Raw) {
		if !ok {
			runtime.AddCleanup(list, forgetIndex, key)
		}
		idx = &listIndex{raw: &list.Raw[0], rawLen: len(list.Raw)}
		listIndexes[key] = idx
	}
	listIndexesMu.Unlock()
	idx.once.Do(func() {
		idx.usable = completeAndDirect(list) && criticalUnderstood(list)
		if !idx.usable {
			return
		}
		idx.revoked = make(map[string]struct{}, len(list.RevokedCertificateEntries))
		for _, entry := range list.RevokedCertificateEntries {
			if entry.SerialNumber != nil {
				idx.revoked[serialKey(entry.SerialNumber)] = struct{}{}
			}
		}
	})
	return idx
}

// forgetIndex drops the index of a list no longer reachable.
func forgetIndex(key weak.Pointer[x509.RevocationList]) {
	listIndexesMu.Lock()
	delete(listIndexes, key)
	listIndexesMu.Unlock()
}

// serialKey is n as a map key: its sign, then its magnitude.
func serialKey(n *big.Int) string {
	sign := "+"
	if n.Sign() < 0 {
		sign = "-"
	}
	return sign + string(n.Bytes())
}

// signedBy reports whether list's signature verifies under issuer,
// verifying it once per issuer certificate. One without its DER, built
// by hand rather than parsed, has nothing to tell it apart from another
// by: its answer isn't kept.
func (idx *listIndex) signedBy(list *x509.RevocationList, issuer *x509.Certificate) bool {
	if len(issuer.Raw) == 0 {
		return list.CheckSignatureFrom(issuer) == nil
	}
	key := sha256.Sum256(issuer.Raw)
	idx.mu.Lock()
	ok, done := idx.verified[key]
	idx.mu.Unlock()
	if done {
		return ok
	}
	ok = list.CheckSignatureFrom(issuer) == nil
	idx.mu.Lock()
	if idx.verified == nil {
		idx.verified = map[[sha256.Size]byte]bool{}
	}
	idx.verified[key] = ok
	idx.mu.Unlock()
	return ok
}

// selfSignedAnchors remembers which trust anchors selfSigned found
// self-signed, by certificate, until the certificate is unreachable:
// anchors come from a relying party's roots, the same few certificates
// on every check, and each answer is a signature verification.
var (
	selfSignedMu      sync.Mutex
	selfSignedAnchors = map[weak.Pointer[x509.Certificate]]selfSignedAnswer{}
)

// selfSignedAnswer is selfSigned's answer for the certificate whose DER
// starts at raw.
type selfSignedAnswer struct {
	raw *byte
	yes bool
}

// selfSignedMemo is selfSigned(cert), found once per certificate.
func selfSignedMemo(cert *x509.Certificate) bool {
	if len(cert.Raw) == 0 {
		return selfSigned(cert)
	}
	key := weak.Make(cert)
	selfSignedMu.Lock()
	answer, ok := selfSignedAnchors[key]
	selfSignedMu.Unlock()
	if ok && answer.raw == &cert.Raw[0] {
		return answer.yes
	}
	yes := selfSigned(cert)
	selfSignedMu.Lock()
	if _, ok := selfSignedAnchors[key]; !ok {
		runtime.AddCleanup(cert, forgetSelfSigned, key)
	}
	selfSignedAnchors[key] = selfSignedAnswer{raw: &cert.Raw[0], yes: yes}
	selfSignedMu.Unlock()
	return yes
}

// forgetSelfSigned drops the answer for a certificate no longer
// reachable.
func forgetSelfSigned(key weak.Pointer[x509.Certificate]) {
	selfSignedMu.Lock()
	delete(selfSignedAnchors, key)
	selfSignedMu.Unlock()
}
