package verifierapp

import (
	"github.com/idfoundry/oid4vcgo/statuslist"
	"github.com/idfoundry/oid4vcgo/verifier"
)

// statusPolicy is how a presented credential's revocation status is
// checked, before the scenario's own checks (Accept) see it: against
// the Token Status List it references, and signed by the credential's
// own issuer (a verifier.StatusPolicy binds the list's signer to the
// credential's issuer key or chain, not just to the roots). Every
// scenario shares one statuslist.Cache, so a list is fetched once per
// its ttl (a minute, the demo issuer's), not once per presentation: a
// revocation applies within that minute, or at once when the issuer
// tells this verifier (DropKeptStatusLists). Each check still verifies
// the kept list for its own credential. A revoked or suspended credential,
// or one whose status can't be established, is refused — the
// presentation isn't accepted. A credential without a status reference
// passes, and is reported as such (statusOf).
func (a *App) statusPolicy() *verifier.StatusPolicy {
	return &verifier.StatusPolicy{Checker: statuslist.Checker{
		// The demo serves its status list on 127.0.0.1; a real Verifier
		// leaves AllowLoopback off, so a credential can't point it at
		// its own machine, and production assurance refuses it.
		Fetcher: statuslist.Fetcher{HTTP: a.cfg.HTTP, AllowLoopback: true},
		Roots:   a.issuerRoots,
		Options: statuslist.VerifyOptions{Now: a.now},
		Cache:   a.statusCache,
	}}
}

// DropKeptStatusLists drops the status lists the verifier kept, so its
// next check of each fetches it afresh: for the demo issuer running
// beside it to call when it revokes a credential
// (issuerapp.Config.OnRevoke).
func (a *App) DropKeptStatusLists() { a.statusCache.Purge() }

// statusOf is what a credential's status was found to be, once the
// status policy passed it: "valid", or "no status reference" for one
// without any.
func statusOf(vc verifier.VerifiedCredential) string {
	if _, _, ok, err := vc.StatusListRef(); !ok && err == nil {
		return "no status reference"
	}
	return "valid"
}
