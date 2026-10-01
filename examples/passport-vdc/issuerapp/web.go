package issuerapp

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/internal/demoqr"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/passport"
	"github.com/idfoundry/oid4vcgo/issuer"
)

// maxUploadBytes bounds an uploaded passport file — a gmrtd portable
// file with a facial image is typically well under 100 KiB.
const maxUploadBytes = 2 << 20

// Offer is a Credential Offer for one verified passport.
type Offer struct {
	// URI is the openid-credential-offer:// deep link to hand to a
	// Wallet (as a link or QR code).
	URI string
	// IssuerState is the offer's issuer_state — the transaction ID.
	IssuerState string
	// ConfirmationCode is shown with the offer and must be entered at
	// the issuer's approval step, so the offer link alone can't be
	// redeemed.
	ConfirmationCode string
}

// CreateTransaction records an already-verified passport and returns
// a Credential Offer for it in both formats. The upload page calls it
// after passport.Verify; tests call it directly with synthetic
// Evidence.
func (a *App) CreateTransaction(ctx context.Context, e passport.Evidence) (Offer, error) {
	return a.createTransaction(ctx, e, false)
}

// CreateTransactionForReview is CreateTransaction for a passport an
// operator must review first: its credentials are deferred (OID4VCI 1.0
// §9) until a decision on the /review page (Review).
func (a *App) CreateTransactionForReview(ctx context.Context, e passport.Evidence) (Offer, error) {
	return a.createTransaction(ctx, e, true)
}

func (a *App) createTransaction(ctx context.Context, e passport.Evidence, review bool) (Offer, error) {
	configIDs := []string{MdocConfigurationID, SDJWTConfigurationID}
	txID, code, err := a.transactions.put(e, configIDs, review)
	if err != nil {
		return Offer{}, err
	}
	result, err := a.issuer.CreateCredentialOffer(ctx, issuer.CreateCredentialOfferRequest{
		CredentialConfigurationIDs: configIDs,
		Grants: &oid4vci.Grants{
			AuthorizationCode: &oid4vci.GrantAuthorizationCode{IssuerState: txID},
		},
	})
	if err != nil {
		return Offer{}, fmt.Errorf("issuerapp: credential offer: %w", err)
	}
	return Offer{URI: result.URI, IssuerState: txID, ConfirmationCode: code}, nil
}

func (a *App) routes(credentialHandler, deferredHandler, notificationHandler http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", a.handleUploadPage)
	mux.HandleFunc("POST /passport", a.handleUpload)

	mux.HandleFunc("GET /.well-known/oauth-authorization-server", a.handleASMetadata)
	mux.HandleFunc("GET /.well-known/openid-configuration", a.handleASMetadata)
	mux.HandleFunc("GET /jwks", a.handleJWKS)
	mux.HandleFunc("POST /par", a.handlePAR)
	mux.HandleFunc("GET /authorize", a.handleAuthorize)
	mux.HandleFunc("POST /authorize/decision", a.handleDecision)
	mux.HandleFunc("POST /token", a.handleToken)

	mux.HandleFunc("GET /.well-known/openid-credential-issuer", a.issuerMetadataHandler())
	mux.HandleFunc("GET "+VCTPath, a.handleVCTMetadata)
	mux.HandleFunc("POST /nonce", a.handleNonce)
	mux.Handle("POST /credential", credentialHandler)
	mux.Handle("POST /deferred_credential", deferredHandler)
	mux.Handle("POST /notification", notificationHandler)
	mux.HandleFunc("GET /review", a.handleReviewPage)
	mux.HandleFunc("POST /review/decision", a.handleReviewDecision)

	mux.Handle("GET "+StatusListPath, a.statusPublisher())
	mux.HandleFunc("GET /status", a.handleStatusPage)
	mux.HandleFunc("POST /status/revoke", a.handleRevoke)
	return mux
}

const pageHead = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Passport → Digital Credential (demo)</title>
<style>
body{font-family:system-ui,sans-serif;max-width:40rem;margin:2rem auto;padding:0 1rem;line-height:1.5}
table{border-collapse:collapse}th,td{text-align:left;padding:.25rem .75rem .25rem 0;vertical-align:top}
code{word-break:break-all}.ok{color:#1a7f37}.warn{color:#9a6700}.note{color:#57606a;font-size:.9em}
</style>
</head>
<body>
`

const pageFoot = `
</body>
</html>
`

var uploadTemplate = template.Must(template.New("upload").Parse(pageHead + `
<h1>Passport → Digital Credential</h1>
<p>Upload a gmrtd portable passport file. It's verified against the issuing country's signatures, then offered to your wallet as both an <code>mso_mdoc</code> and a <code>dc+sd-jwt</code> credential.</p>
<form method="post" action="/passport" enctype="multipart/form-data">
<input type="file" name="passport" accept=".gmrtd" required>
<p><label><input type="checkbox" name="review" value="1"> Hold for an operator's review — the wallet waits, and polls, until you decide on the <a href="/review">review page</a></label></p>
<button>Verify passport</button>
</form>
<p class="note">Demo only. The passport is held in memory until the offer expires and is never stored.</p>
<p><a href="/status">Issued credentials and revocation</a></p>
` + pageFoot))

type offerPage struct {
	Evidence      passport.Evidence
	Expired       bool // the passport is past its expiry date
	Offer         Offer
	QR            template.URL
	WebWalletLink string
}

var offerTemplate = template.Must(template.New("offer").Funcs(template.FuncMap{
	"date": func(e passport.Evidence) string {
		if !e.Identity.BirthDate.Known() {
			return "not asserted (the MRZ birth year is ambiguous)"
		}
		return e.Identity.BirthDate.Date.Format("2006-01-02")
	},
}).Parse(pageHead + `
<h1>Passport verified</h1>
<ul>
<li class="ok">✓ Passive Authentication — issuing country's signature and data-group hashes</li>
<li>Chip authentication evidence in the file: {{.Evidence.Checks.ChipAuthenticity}} <span class="note">— recorded when the chip was read, so it can be replayed: it doesn't show that you hold the passport</span></li>
</ul>
<table>
<tr><th>Name</th><td>{{.Evidence.Identity.FamilyName}}, {{.Evidence.Identity.GivenNames}}{{if .Evidence.Identity.NamesFromMRZ}} <span class="note">(from MRZ)</span>{{end}}</td></tr>
<tr><th>Date of birth</th><td>{{date .Evidence}}</td></tr>
<tr><th>Nationality</th><td>{{.Evidence.Identity.Nationality}}</td></tr>
<tr><th>Issuing country</th><td>{{.Evidence.Identity.IssuingCountry}}</td></tr>
<tr><th>Expires</th><td>{{.Evidence.Identity.ExpiryDate.Format "2006-01-02"}}{{if .Expired}} <span class="note">— expired: the data is still country-signed, and the credential says when it expired</span>{{end}}</td></tr>
</table>
<h2>Credential offer</h2>
<p>Confirmation code: <strong style="font-size:1.4em;letter-spacing:.15em">{{.Offer.ConfirmationCode}}</strong><br><span class="note">Enter it when the issuer asks you to approve. The offer can be redeemed once, by one wallet.</span></p>
{{if .WebWalletLink}}<p><a href="{{.WebWalletLink}}"><strong>Open in web wallet</strong></a></p>{{end}}
<p><a href="{{.Offer.URI}}">Open in wallet app</a> (on this device)</p>
{{if .QR}}<p>Or scan with a wallet on another device:<br><img src="{{.QR}}" alt="QR code of the credential offer" width="296"></p>{{end}}
<p class="note">Or pass this offer to the demo CLI wallet:</p>
<p><code>{{.Offer.URI}}</code></p>
<p class="warn">This proves the passport data is authentic, not that you hold the passport — see the demo README.</p>
` + pageFoot))

func (a *App) handleUploadPage(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = uploadTemplate.Execute(w, nil)
}

func (a *App) handleUpload(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadBytes)
	file, _, err := r.FormFile("passport")
	if err != nil {
		writeHTMLError(w, http.StatusBadRequest, "no passport file uploaded, or it's larger than 2 MiB")
		return
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(file)
	if err != nil {
		writeHTMLError(w, http.StatusBadRequest, "couldn't read the uploaded file")
		return
	}

	e, err := passport.Verify(data, a.cfg.CSCAPool, a.now())
	switch {
	case errors.Is(err, passport.ErrNotTrusted):
		writeHTMLError(w, http.StatusUnprocessableEntity, "the passport's signatures didn't verify against the trusted CSCA certificates")
		return
	case err != nil:
		writeHTMLError(w, http.StatusBadRequest, "not a readable gmrtd portable passport file")
		return
	}

	offer, err := a.createTransaction(r.Context(), e, r.FormValue("review") != "")
	switch {
	case errors.Is(err, errTooManyTransactions):
		writeHTMLError(w, http.StatusServiceUnavailable, "too many passports are awaiting issuance — try again in a few minutes")
		return
	case err != nil:
		writeHTMLError(w, http.StatusInternalServerError, "couldn't create a credential offer")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store") // the offer is a bearer secret, next to the passport's identity
	page := offerPage{Evidence: e, Offer: offer, Expired: e.Identity.ExpiredAt(a.now())}
	if qr, err := demoqr.DataURI(offer.URI); err == nil {
		page.QR = qr
	}
	if a.cfg.WebWalletURL != "" {
		page.WebWalletLink = a.cfg.WebWalletURL + "/receive?offer=" + url.QueryEscape(offer.URI)
	}
	_ = offerTemplate.Execute(w, page)
}

var errorTemplate = template.Must(template.New("error").Parse(pageHead + `
<h1>Something went wrong</h1>
<p>{{.}}</p>
<p><a href="/">Start again</a></p>
` + pageFoot))

func writeHTMLError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = errorTemplate.Execute(w, message)
}
