package issuerapp

import (
	"fmt"
	"log"
	"net/http"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/internal/democrl"
)

// CRLPath is where the issuer's CA serves its Certificate Revocation
// List, relative to IssuerURL: the distribution point its certificates
// name. It's outside /demo/, as the protocol endpoints are: relying
// parties fetch it.
const CRLPath = "/ca.crl"

// CRLHandler serves the CA's CRL, as GET CRLPath does: for the demo to
// serve it at a second address (cmd/demo's plain-http one).
func (a *App) CRLHandler() http.Handler { return a.crl }

// RevokedSigners are the document signers this issuer's CA has revoked
// (RevokeDocumentSigner), oldest first.
func (a *App) RevokedSigners() []democrl.Revoked { return a.crl.Revoked() }

// RevokeDocumentSigner revokes the document signer: its certificate is
// added to the CA's CRL, and a new signer the CA certifies takes its
// place, kept in Config.StateDir when set. Credentials issued from then
// on are signed by the new one, as are the status lists; those the
// revoked one signed are refused by every relying party that has
// fetched the CA's CRL since.
func (a *App) RevokeDocumentSigner() error {
	a.signerMu.Lock()
	defer a.signerMu.Unlock()
	old := a.current()
	key, cert, err := issueSigner(a.now(), documentSignerName, a.id.caCert, a.id.caKey, a.crlURL, mdoc.MDLDocumentSignerEKU)
	if err != nil {
		return err
	}
	next, err := a.newSigning(key, cert)
	if err != nil {
		return err
	}
	id := a.id
	id.documentSigner, id.documentSignerCert = key, cert
	if a.cfg.StateDir != "" {
		// Saved first: a restart never brings back the revoked signer.
		if err := saveIdentity(a.cfg.StateDir, id); err != nil {
			return err
		}
	}
	a.id = id
	a.signing.Store(next)
	if err := a.crl.Revoke(old.cert); err != nil {
		return fmt.Errorf("issuerapp: the new document signer is in use, but the old one couldn't be revoked: %w", err)
	}
	return nil
}

// handleRevokeSigner revokes the document signer. A cross-origin form
// post is refused, as handleRevoke refuses one.
func (a *App) handleRevokeSigner(w http.ResponseWriter, r *http.Request) {
	if origin := r.Header.Get("Origin"); origin != "" && origin != a.cfg.IssuerURL {
		a.writeHTMLError(w, http.StatusForbidden, "cross-origin revocation refused")
		return
	}
	if err := a.RevokeDocumentSigner(); err != nil {
		log.Printf("issuerapp: revoke the document signer: %v", err)
		a.writeHTMLError(w, http.StatusInternalServerError, "the document signer couldn't be revoked")
		return
	}
	if a.cfg.OnSignerRevoked != nil {
		a.cfg.OnSignerRevoked()
	}
	http.Redirect(w, r, "/demo/status#signer", http.StatusSeeOther)
}

// signerInfo is the document signer as the status page shows it.
type signerInfo struct {
	Serial   string
	NotAfter string
}

func (a *App) signerInfo() signerInfo {
	cert := a.current().cert
	return signerInfo{Serial: cert.SerialNumber.String(), NotAfter: cert.NotAfter.UTC().Format("2006-01-02")}
}
