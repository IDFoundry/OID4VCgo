package dcql

import (
	"crypto/x509"
	"runtime"
	"slices"
	"sync"
	"weak"
)

// anchorSet is what an AKITrustedAuthoritiesChecker's Anchors give
// every check alike: Validate's answer, and the pool to verify chains
// against. Building them walks every anchor, which for a thousand takes
// milliseconds, so it's done once per Anchors slice, as long as it
// holds the same certificates.
type anchorSet struct {
	anchors []*x509.Certificate // the certificates it was built from
	roots   *x509.CertPool
	err     error
}

var (
	anchorSetsMu sync.Mutex
	// anchorSets is keyed by an Anchors slice's first element, and an
	// entry goes once that slice's array is unreachable.
	anchorSets = map[weak.Pointer[*x509.Certificate]]*anchorSet{}
)

// anchorSetOf is c's anchorSet, c having Anchors and no Roots.
func (c AKITrustedAuthoritiesChecker) anchorSetOf() *anchorSet {
	key := weak.Make(&c.Anchors[0])
	anchorSetsMu.Lock()
	set, ok := anchorSets[key]
	anchorSetsMu.Unlock()
	if ok && slices.Equal(set.anchors, c.Anchors) {
		return set
	}
	set = &anchorSet{anchors: slices.Clone(c.Anchors), err: c.Validate()}
	if set.err == nil {
		set.roots = x509.NewCertPool()
		for _, anchor := range c.Anchors {
			set.roots.AddCert(anchor)
		}
	}
	anchorSetsMu.Lock()
	if _, ok := anchorSets[key]; !ok {
		runtime.AddCleanup(&c.Anchors[0], forgetAnchorSet, key)
	}
	anchorSets[key] = set
	anchorSetsMu.Unlock()
	return set
}

// forgetAnchorSet drops the anchorSet of an Anchors array no longer
// reachable.
func forgetAnchorSet(key weak.Pointer[*x509.Certificate]) {
	anchorSetsMu.Lock()
	delete(anchorSets, key)
	anchorSetsMu.Unlock()
}
