package issuerapp

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"time"

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
	// redeemed. For a pre-authorized offer it's the PIN (tx_code) the
	// wallet sends with the pre-authorized code instead.
	ConfirmationCode string
	// PreAuthorized reports a pre-authorized code offer: no browser
	// approval, the wallet redeems it with the PIN.
	PreAuthorized bool
	// KeptForRefresh reports a passport kept for refresh
	// (OfferOptions.KeepForRefresh).
	KeptForRefresh bool
}

// CreateTransaction records an already-verified passport and returns
// a Credential Offer for it in both formats. The upload page calls it
// after passport.Verify; tests call it directly with synthetic
// Evidence.
func (a *App) CreateTransaction(ctx context.Context, e passport.Evidence) (Offer, error) {
	return a.CreateOffer(ctx, e, OfferOptions{})
}

// CreateTransactionForReview is CreateTransaction for a passport an
// operator must review first: its credentials are deferred (OID4VCI 1.0
// §9) until a decision on the /review page (Review).
func (a *App) CreateTransactionForReview(ctx context.Context, e passport.Evidence) (Offer, error) {
	return a.CreateOffer(ctx, e, OfferOptions{Review: true})
}

// CreatePreAuthorizedTransaction is CreateTransaction "at the counter":
// the offer carries a pre-authorized code (OID4VCI 1.0 §3.5), which the
// wallet redeems at the token endpoint with the PIN (Offer.ConfirmationCode)
// and its Wallet Attestation, with no approval step in a browser.
func (a *App) CreatePreAuthorizedTransaction(ctx context.Context, e passport.Evidence) (Offer, error) {
	return a.CreateOffer(ctx, e, OfferOptions{PreAuthorized: true})
}

// OfferOptions are how an upload is offered.
type OfferOptions struct {
	// Review defers issuance until an operator decides
	// (CreateTransactionForReview).
	Review bool
	// PreAuthorized offers a pre-authorized code with a PIN, not an
	// authorization (CreatePreAuthorizedTransaction).
	PreAuthorized bool
	// KeepForRefresh keeps the passport for KeepForRefresh after its
	// first credential is issued, and gives the wallet a refresh token
	// (OID4VCI 1.0 §13.5) to fetch fresh copies with until then — for an
	// authorization, if it asks for one (offline_access). The wallet
	// revoking that token, or Forget, drops the passport sooner. It
	// can't be combined with Review.
	KeepForRefresh bool
}

// KeepForRefresh is how long a passport kept for refresh is kept after
// its first credential is issued, and how long its refresh token lasts.
const KeepForRefresh = 24 * time.Hour

// errReviewAndKeep is returned by CreateOffer for OfferOptions with both
// Review and KeepForRefresh.
var errReviewAndKeep = errors.New("issuerapp: a passport held for review can't also be kept for refresh")

// CreateOffer is CreateTransaction with opts.
func (a *App) CreateOffer(ctx context.Context, e passport.Evidence, opts OfferOptions) (Offer, error) {
	if opts.Review && opts.KeepForRefresh {
		return Offer{}, errReviewAndKeep
	}
	configIDs := []string{MdocConfigurationID, SDJWTConfigurationID}
	txID, code, err := a.transactions.put(e, configIDs, opts.Review, opts.KeepForRefresh)
	if err != nil {
		return Offer{}, err
	}
	if opts.PreAuthorized {
		// The PIN stands in for the approval step: the transaction is
		// claimed now, and only the pre-authorized code, with the PIN,
		// reaches it.
		if err := a.transactions.claim(txID, code); err != nil {
			return Offer{}, err
		}
		uri, err := a.preAuthorizedOffer(ctx, txID, code, configIDs)
		if err != nil {
			return Offer{}, err
		}
		return Offer{URI: uri, IssuerState: txID, ConfirmationCode: code, PreAuthorized: true, KeptForRefresh: opts.KeepForRefresh}, nil
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
	return Offer{URI: result.URI, IssuerState: txID, ConfirmationCode: code, KeptForRefresh: opts.KeepForRefresh}, nil
}

func (a *App) routes(credentialHandler, deferredHandler, notificationHandler http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", a.handleUploadPage)
	mux.HandleFunc("POST /passport", a.handleUpload)
	if a.cfg.AllowSampleDocument {
		mux.HandleFunc("POST /sample", a.handleSample)
	}

	mux.HandleFunc("GET /.well-known/oauth-authorization-server", a.handleASMetadata)
	mux.HandleFunc("GET /.well-known/openid-configuration", a.handleASMetadata)
	mux.HandleFunc("GET /jwks", a.handleJWKS)
	mux.HandleFunc("POST /par", a.handlePAR)
	mux.HandleFunc("GET /authorize", a.handleAuthorize)
	mux.HandleFunc("POST /authorize/decision", a.handleDecision)
	mux.HandleFunc("POST /token", a.handleToken)
	mux.HandleFunc("POST /revoke", a.handleTokenRevocation)

	mux.HandleFunc("GET /.well-known/openid-credential-issuer", a.issuerMetadataHandler())
	mux.HandleFunc("GET "+VCTPath, a.handleVCTMetadata)
	mux.HandleFunc("POST /nonce", a.handleNonce)
	mux.Handle("POST /credential", credentialHandler)
	mux.Handle("POST /deferred_credential", deferredHandler)
	mux.Handle("POST /notification", notificationHandler)
	mux.HandleFunc("GET /review", a.handleReviewPage)
	mux.HandleFunc("POST /review/decision", a.handleReviewDecision)
	mux.HandleFunc("GET /kept", a.handleKeptPage)
	mux.HandleFunc("POST /kept/forget", a.handleForget)

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
input.code{display:block;margin-top:.4em;font:1.8em ui-monospace,monospace;letter-spacing:.35em;width:7ch;padding:.3em .5em;border:2px solid #57606a;border-radius:6px}
button{font-size:1.05em;padding:.5em 1.1em;margin:.2em .4em .2em 0}
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
<p><label><input type="checkbox" name="counter" value="1"> Issue at the counter — a pre-authorized code with a PIN, no approval in the browser (OID4VCI's other grant)</label></p>
<p><label><input type="checkbox" name="review" value="1"> Hold for an operator's review — the wallet waits, and polls, until you decide on the <a href="/review">review page</a></label></p>
<p><label><input type="checkbox" name="keep" value="1"> Keep for refresh (24 hours) — your wallet can get fresh copies of the credentials without you until then. The issuer keeps this passport's data until it expires, or until your wallet deletes the credentials (<a href="/kept">kept passports</a>)</label></p>
<button>Verify passport</button>
{{if .AllowSample}}<button formaction="/sample" formnovalidate>Issue gmrtd's sample passport without checking it</button>{{end}}
</form>
{{if .AllowSample}}<p class="note">No passport to hand? The second button simulates an issuer that skipped Passive Authentication: it issues gmrtd's sample passport — ICAO worked-example data no country signed — as an ordinary passport credential. A verifier trusting this issuer accepts it; one that re-verifies the passport file doesn't.</p>{{end}}
<p class="note">Demo only. The passport is held in memory until the offer expires, or kept for refresh, and is never stored.</p>
<p><a href="/status">Issued credentials and revocation</a></p>
` + pageFoot))

type offerPage struct {
	Evidence      passport.Evidence
	Expired       bool // the passport is past its expiry date
	Offer         Offer
	QR            template.URL
	WebWalletLink string
	// AppLink is the offer as a link a wallet app on this device opens:
	// its openid-credential-offer: URL, which html/template won't put in
	// an href by itself.
	AppLink template.URL
}

var offerTemplate = template.Must(template.New("offer").Funcs(template.FuncMap{
	"date": func(e passport.Evidence) string {
		if !e.Identity.BirthDate.Known() {
			return "not asserted (the MRZ birth year is ambiguous)"
		}
		return e.Identity.BirthDate.Date.Format("2006-01-02")
	},
}).Parse(pageHead + `
{{if .Evidence.Checks.PassiveAuthentication}}<h1>Passport verified</h1>
<ul>
<li class="ok">✓ Passive Authentication — issuing country's signature and data-group hashes</li>{{else}}<h1>Sample passport — issued without checking</h1>
<ul>
<li class="warn">✗ Passive Authentication skipped — this simulates an issuer that didn't check. It's gmrtd's sample document: ICAO worked-example data no country signed (issuing country "UTO"). Its credentials look like any passport's: a verifier trusting this issuer accepts them, and only re-verifying the passport file shows the country never signed the data.</li>{{end}}
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
{{if .Offer.PreAuthorized}}<p>PIN: <strong style="font-size:1.4em;letter-spacing:.15em">{{.Offer.ConfirmationCode}}</strong><br><span class="note">Give it to the holder separately from the offer: their wallet sends it with the offer's pre-authorized code. There's no approval step; the offer can be redeemed once, by one wallet.</span></p>
{{else}}<p>Confirmation code: <strong style="font-size:1.4em;letter-spacing:.15em">{{.Offer.ConfirmationCode}}</strong><br><span class="note">Enter it when the issuer asks you to approve. The offer can be redeemed once, by one wallet.</span></p>{{end}}
{{if .Offer.KeptForRefresh}}<p class="note">Kept for refresh: the issuer keeps this passport's data for 24 hours after it first issues a credential, so your wallet can get fresh copies, then deletes it. Deleting the credentials in your wallet, or <a href="/kept">forgetting it</a>, deletes it sooner.</p>{{end}}
{{if .WebWalletLink}}<p><a href="{{.WebWalletLink}}"><strong>Open in web wallet</strong></a></p>{{end}}
{{if .AppLink}}<p><a href="{{.AppLink}}">Open in wallet app</a> (on this device)</p>{{end}}
{{if .QR}}<p>Or scan with a wallet on another device:<br><img src="{{.QR}}" alt="QR code of the credential offer" width="296"></p>{{end}}
<p class="note">Or pass this offer to the demo CLI wallet:</p>
<p><code>{{.Offer.URI}}</code></p>
{{if .Evidence.Checks.PassiveAuthentication}}<p class="warn">This proves the passport data is authentic, not that you hold the passport — see the demo README.</p>{{end}}
` + pageFoot))

func (a *App) handleUploadPage(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = uploadTemplate.Execute(w, struct{ AllowSample bool }{a.cfg.AllowSampleDocument})
}

// handleSample offers gmrtd's sample passport (Config.AllowSampleDocument)
// with the upload form's options, without checking it.
func (a *App) handleSample(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadBytes)
	e, err := passport.SampleDocument(a.now())
	if err != nil {
		writeHTMLError(w, http.StatusInternalServerError, "couldn't load gmrtd's sample passport")
		return
	}
	a.offer(w, r, e)
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

	a.offer(w, r, e)
}

// offer creates a transaction for e, with the upload form's options, and
// shows its credential offer.
func (a *App) offer(w http.ResponseWriter, r *http.Request, e passport.Evidence) {
	offer, err := a.CreateOffer(r.Context(), e, OfferOptions{
		Review: r.FormValue("review") != "", PreAuthorized: r.FormValue("counter") != "", KeepForRefresh: r.FormValue("keep") != "",
	})
	switch {
	case errors.Is(err, errReviewAndKeep):
		writeHTMLError(w, http.StatusBadRequest, "a passport held for review can't also be kept for refresh — choose one")
		return
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
	page.AppLink = appLink(offer.URI)
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

// appLink is uri as an href, when it's a Credential Offer link
// (openid-credential-offer:): the one scheme the page links to besides
// https.
func appLink(uri string) template.URL {
	if u, err := url.Parse(uri); err != nil || u.Scheme != "openid-credential-offer" {
		return ""
	}
	return template.URL(uri) // #nosec G203 -- only an openid-credential-offer: URL the issuer made, checked above
}
