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
	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/credential"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/internal/demoqr"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/internal/demoui"
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
	// The pages people use — uploading a passport, and the operator's
	// review, status and kept-passport pages — are all under /demo/, so
	// one access rule (Cloudflare Access on the path, say) can guard
	// them; everything else is the OpenID4VCI and OAuth surface wallets
	// and verifiers call, which must stay reachable.
	mux.HandleFunc("GET /{$}", redirectToDemo)
	mux.HandleFunc("GET /demo/{$}", a.handleUploadPage)
	mux.HandleFunc("POST /demo/passport", a.handleUpload)
	if a.cfg.AllowSampleDocument {
		mux.HandleFunc("POST /demo/sample", a.handleSample)
	}
	// A browser can land on a form's target with a GET: Cloudflare
	// Access, after a login, sends the visitor back to the URL it
	// interrupted, a form post's included. Each goes to its form's page.
	mux.HandleFunc("GET /demo/passport", redirectTo("/demo/"))
	mux.HandleFunc("GET /demo/sample", redirectTo("/demo/"))
	mux.HandleFunc("GET /demo/review/decision", redirectTo("/demo/review"))
	mux.HandleFunc("GET /demo/kept/forget", redirectTo("/demo/kept"))
	mux.HandleFunc("GET /demo/status/revoke", redirectTo("/demo/status"))

	mux.HandleFunc("GET /.well-known/oauth-authorization-server", a.handleASMetadata)
	mux.HandleFunc("GET /.well-known/openid-configuration", a.handleASMetadata)
	mux.HandleFunc("GET /jwks", a.handleJWKS)
	mux.HandleFunc("POST /par", a.handlePAR)
	mux.HandleFunc("GET /authorize", a.handleAuthorize)
	mux.HandleFunc("POST /authorize/decision", a.handleDecision)
	mux.HandleFunc("POST /token", a.handleToken)
	mux.HandleFunc("POST /revoke", a.handleTokenRevocation)

	mux.Handle("GET /.well-known/openid-credential-issuer", a.metadataHandler)
	mux.HandleFunc("GET "+VCTPath, a.handleVCTMetadata)
	mux.HandleFunc("POST /nonce", a.handleNonce)
	mux.Handle("POST /credential", credentialHandler)
	mux.Handle("POST /deferred_credential", deferredHandler)
	mux.Handle("POST /notification", notificationHandler)
	mux.HandleFunc("GET /demo/review", a.handleReviewPage)
	mux.HandleFunc("POST /demo/review/decision", a.handleReviewDecision)
	mux.HandleFunc("GET /demo/kept", a.handleKeptPage)
	mux.HandleFunc("POST /demo/kept/forget", a.handleForget)

	jwtList, cwtList := a.statusPublishers()
	mux.Handle("GET "+StatusListPath, jwtList)
	mux.Handle("GET "+MdocStatusListPath, cwtList)
	mux.HandleFunc("GET /demo/status", a.handleStatusPage)
	mux.HandleFunc("POST /demo/status/revoke", a.handleRevoke)
	return mux
}

// redirectToDemo sends a visitor to the pages under /demo/.
func redirectToDemo(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/demo/", http.StatusSeeOther)
}

// redirectTo sends a visitor to page.
func redirectTo(page string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, page, http.StatusSeeOther)
	}
}

// pageFuncs are the functions the issuer's pages use.
var pageFuncs = template.FuncMap{
	"birthDate": func(e passport.Evidence) string {
		if !e.Identity.BirthDate.Known() {
			return "not asserted (the MRZ birth year is ambiguous)"
		}
		return e.Identity.BirthDate.Date.Format(demoui.DateLayout)
	},
	"words":      func(t time.Time) string { return t.Format(demoui.DateLayout) },
	"formatName": formatName,
}

// formatName is a credential format as people read it.
func formatName(format string) string {
	switch format {
	case mdoc.CredentialFormat:
		return "mdoc"
	case sdjwtvc.CredentialFormat:
		return "SD-JWT VC"
	}
	return format
}

type uploadPage struct {
	Header      demoui.Header
	AllowSample bool
}

var uploadTemplate = parsePage("upload", pageHead+`</head><body>
{{template "site-header" .Header}}
<main>
<h1>Turn your passport into a digital credential</h1>
<p class="lead">Upload the file your passport reader saved from the chip. The issuer checks the issuing country's signatures on it, then offers it to your wallet as two credentials: an ISO mdoc and an SD-JWT VC.</p>
<form id="upload" method="post" action="/demo/passport" enctype="multipart/form-data" class="card">
<label class="dropzone" id="dropzone"><span class="icon" aria-hidden="true">📄</span>
<strong>Choose your passport file</strong>
<span class="note">or drop it here — a gmrtd portable passport file (<code>.gmrtd</code>), up to 2 MiB</span>
<span class="file-name" id="file-name" aria-live="polite"></span>
<input type="file" name="passport" accept=".gmrtd" required aria-describedby="file-name">
</label>
<fieldset class="choices">
<legend>How to issue it</legend>
<label class="choice"><input type="checkbox" name="counter" value="1"><span><strong>Issue at the counter</strong><span class="note">Your wallet gets a PIN instead of you approving in the browser — OID4VCI's pre-authorized code.</span></span></label>
<label class="choice"><input type="checkbox" name="review" value="1" data-excludes="keep"><span><strong>Hold for an operator's review</strong><span class="note">The wallet waits, and checks back, until someone decides on the <a href="/demo/review">review page</a>.</span></span></label>
<label class="choice"><input type="checkbox" name="keep" value="1" data-excludes="review"><span><strong>Keep for refresh (24 hours)</strong><span class="note">Your wallet can fetch fresh copies without you until then; the issuer keeps the passport data that long, or until your wallet deletes the credentials (<a href="/demo/kept">kept passports</a>).</span></span></label>
<p class="note" id="exclusive-note">A passport held for review can't also be kept for refresh: choose one.</p>
</fieldset>
<button class="btn">Verify passport</button>
</form>
{{if .AllowSample}}<section class="card" aria-labelledby="sample-heading">
<h2 id="sample-heading"><span aria-hidden="true">🧪</span> No passport to hand?</h2>
<p>Issue gmrtd's sample passport — ICAO worked-example data no country signed — with the options above. It simulates an issuer that skipped Passive Authentication: a verifier trusting this issuer accepts the credentials; one that re-verifies the passport file doesn't.</p>
<button form="upload" formaction="/demo/sample" formnovalidate class="btn secondary">Issue the sample passport without checking it</button>
</section>{{end}}
<p class="note">Demo only. The passport is held in memory until the offer expires, or kept for refresh, and is never stored.</p>
</main>
<script>
(function () {
	var zone = document.getElementById("dropzone"), input = zone.querySelector("input"), name = document.getElementById("file-name");
	function show() { name.textContent = input.files.length ? "Selected: " + input.files[0].name : ""; }
	input.addEventListener("change", show);
	["dragenter", "dragover"].forEach(function (t) { zone.addEventListener(t, function () { zone.classList.add("dragover"); }); });
	["dragleave", "drop"].forEach(function (t) { zone.addEventListener(t, function () { zone.classList.remove("dragover"); }); });
	zone.addEventListener("drop", function () { setTimeout(show, 0); });
	// Review and keep for refresh exclude each other.
	var form = document.getElementById("upload");
	form.querySelectorAll("input[data-excludes]").forEach(function (box) {
		var other = form.querySelector("input[name=" + box.getAttribute("data-excludes") + "]");
		box.addEventListener("change", function () {
			if (box.checked) other.checked = false;
			other.disabled = box.checked;
		});
	});
})();
</script>
`+pageFoot)

type offerPage struct {
	Header        demoui.Header
	Evidence      passport.Evidence
	Expired       bool // the passport is past its expiry date
	Portrait      template.URL
	Offer         Offer
	QR            template.URL
	WebWalletLink string
	// AppLink is the offer as a link a wallet app on this device opens:
	// its openid-credential-offer: URL, which html/template won't put in
	// an href by itself.
	AppLink template.URL
}

var offerTemplate = parsePage("offer", pageHead+`</head><body>
{{template "site-header" .Header}}
<main>
{{if .Evidence.Checks.PassiveAuthentication}}<section class="verdict approved">
<p class="mark" aria-hidden="true">✓</p>
<div><h1 id="verdict" tabindex="-1">Passport verified</h1>
<p class="badges"><span class="badge ok">✓ Country-signed</span> <span class="badge">Chip authentication: {{.Evidence.Checks.ChipAuthenticity}}</span></p>
<p>Passive Authentication passed: the issuing country's signature and every data group's hash.</p></div>
</section>{{else}}<section class="verdict caution">
<p class="mark" aria-hidden="true">⚠</p>
<div><h1 id="verdict" tabindex="-1">Sample passport — issued without checking</h1>
<p class="badges"><span class="badge warn">⚠ Sample — not checked</span> <span class="badge">Chip authentication: {{.Evidence.Checks.ChipAuthenticity}}</span></p>
<p>Passive Authentication was skipped, to simulate an issuer that didn't check. This is gmrtd's sample document: ICAO worked-example data no country signed (issuing country "UTO"). Its credentials look like any passport's: a verifier trusting this issuer accepts them, and only re-verifying the passport file shows the country never signed the data.</p></div>
</section>{{end}}
<p class="note">Chip authentication evidence is recorded when the chip is read, so it can be replayed: it doesn't show that you hold the passport.</p>
<section class="card person" aria-labelledby="identity-heading">
<h2 id="identity-heading">{{.Evidence.Identity.GivenNames}} {{.Evidence.Identity.FamilyName}}</h2>
<div class="person-body">
{{if .Portrait}}<img src="{{.Portrait}}" alt="Portrait from the passport's chip" class="portrait">{{end}}
<table class="claims">
<tr><th scope="row">Family name</th><td>{{.Evidence.Identity.FamilyName}}</td></tr>
<tr><th scope="row">Given names</th><td>{{.Evidence.Identity.GivenNames}}{{if .Evidence.Identity.NamesFromMRZ}} <span class="note">(from the MRZ)</span>{{end}}</td></tr>
<tr><th scope="row">Date of birth</th><td>{{birthDate .Evidence}}</td></tr>
<tr><th scope="row">Nationality</th><td>{{.Evidence.Identity.Nationality}}</td></tr>
<tr><th scope="row">Issuing country</th><td>{{.Evidence.Identity.IssuingCountry}}</td></tr>
<tr><th scope="row">Passport expiry</th><td>{{words .Evidence.Identity.ExpiryDate}}{{if .Expired}} <span class="badge bad">Expired</span>{{end}}</td></tr>
</table>
</div>
{{if .Expired}}<p class="note">The passport has expired. Its data is still country-signed, and the credential says when it expired.</p>{{end}}
</section>
<section class="card respond" aria-labelledby="send-heading">
<h2 id="send-heading">Send to your wallet</h2>
<div class="options">
{{if .QR}}<section class="option opt-qr" aria-labelledby="opt-qr">
<h3 id="opt-qr"><span aria-hidden="true">📷</span> Scan with a phone</h3>
<img src="{{.QR}}" alt="QR code of the credential offer, for a wallet on another device" class="qr" width="296" height="296">
<p class="note">Scan it with your wallet app, or the phone's camera.</p>
</section>{{end}}
{{if or .AppLink .WebWalletLink}}<section class="option opt-device" aria-labelledby="opt-device">
<h3 id="opt-device"><span aria-hidden="true">📲</span> Use a wallet on this device</h3>
<p class="actions">{{if .AppLink}}<a href="{{.AppLink}}" class="btn">Open in wallet app</a>{{end}}
{{if .WebWalletLink}}<a href="{{.WebWalletLink}}" target="_blank" class="btn secondary">Open in web wallet</a>{{end}}</p>
</section>{{end}}
</div>
<details class="cli">
<summary>For the demo CLI wallet</summary>
<p>Give it this offer, as <code>go run ./cmd/wallet receive -state .demo-state '…'</code>:</p>
<p><code id="offer-link">{{.Offer.URI}}</code></p>
<p><button type="button" class="btn secondary" data-copy="offer-link" data-copy-status="offer-link-status" hidden>Copy offer</button> <span id="offer-link-status" class="note" role="status"></span></p>
</details>
</section>
<section class="card" aria-labelledby="code-heading">
{{if .Offer.PreAuthorized}}<h2 id="code-heading">PIN</h2>
<p>Your wallet asks for this PIN once it has the offer, and sends it with the offer's pre-authorized code. There's no approval step.</p>
<details class="reveal"><summary class="btn secondary">Show the PIN</summary>
<p class="code-display"><span class="visually-hidden">PIN: </span><span id="offer-code">{{.Offer.ConfirmationCode}}</span></p>
<p><button type="button" class="btn secondary" data-copy="offer-code" data-copy-status="offer-code-status" hidden>Copy PIN</button> <span id="offer-code-status" class="note" role="status"></span></p>
</details>
<p class="note">Give it to the holder separately from the offer. Anyone who sees both the offer and the PIN can redeem it — once, with one wallet.</p>
{{else}}<h2 id="code-heading">Confirmation code</h2>
<p>Enter it when the issuer asks you to approve, once your wallet has the offer.</p>
<details class="reveal"><summary class="btn secondary">Show the confirmation code</summary>
<p class="code-display"><span class="visually-hidden">Confirmation code: </span><span id="offer-code">{{.Offer.ConfirmationCode}}</span></p>
<p><button type="button" class="btn secondary" data-copy="offer-code" data-copy-status="offer-code-status" hidden>Copy code</button> <span id="offer-code-status" class="note" role="status"></span></p>
</details>
<p class="note">Keep it separate from the offer: anyone who sees both can redeem it — once, with one wallet.</p>{{end}}
</section>
{{if .Offer.KeptForRefresh}}<p class="note">Kept for refresh: the issuer keeps this passport's data for 24 hours after it first issues a credential, so your wallet can get fresh copies, then deletes it. Deleting the credentials in your wallet, or <a href="/demo/kept">forgetting it</a>, deletes it sooner.</p>{{end}}
{{if .Evidence.Checks.PassiveAuthentication}}<p class="note">This proves the passport data is authentic, not that you hold the passport — see the demo README.</p>{{end}}
<p><a href="/demo/">Upload another passport</a></p>
</main>
`+demoui.CopyScript+`
<script>document.getElementById("verdict").focus();</script>
`+pageFoot)

func (a *App) handleUploadPage(w http.ResponseWriter, _ *http.Request) {
	renderPage(w, http.StatusOK, uploadTemplate, uploadPage{Header: a.header(pathUpload), AllowSample: a.cfg.AllowSampleDocument}, false)
}

// handleSample offers gmrtd's sample passport (Config.AllowSampleDocument)
// with the upload form's options, without checking it.
func (a *App) handleSample(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadBytes)
	e, err := passport.SampleDocument(a.now())
	if err != nil {
		a.writeHTMLError(w, http.StatusInternalServerError, "couldn't load gmrtd's sample passport")
		return
	}
	a.offer(w, r, e)
}

func (a *App) handleUpload(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadBytes)
	file, _, err := r.FormFile("passport")
	if err != nil {
		a.writeHTMLError(w, http.StatusBadRequest, "no passport file uploaded, or it's larger than 2 MiB")
		return
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(file)
	if err != nil {
		a.writeHTMLError(w, http.StatusBadRequest, "couldn't read the uploaded file")
		return
	}

	e, err := passport.Verify(data, a.cfg.CSCAPool, a.now())
	switch {
	case errors.Is(err, passport.ErrNotTrusted):
		a.writeHTMLError(w, http.StatusUnprocessableEntity, "the passport's signatures didn't verify against the trusted CSCA certificates")
		return
	case err != nil:
		a.writeHTMLError(w, http.StatusBadRequest, "not a readable gmrtd portable passport file")
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
		a.writeHTMLError(w, http.StatusBadRequest, "a passport held for review can't also be kept for refresh — choose one")
		return
	case errors.Is(err, errTooManyTransactions):
		a.writeHTMLError(w, http.StatusServiceUnavailable, "too many passports are awaiting issuance — try again in a few minutes")
		return
	case err != nil:
		a.writeHTMLError(w, http.StatusInternalServerError, "couldn't create a credential offer")
		return
	}
	page := offerPage{Header: a.header(""), Evidence: e, Offer: offer, Expired: e.Identity.ExpiredAt(a.now())}
	if uri, ok := credential.PortraitDataURI(map[string]any{credential.Portrait: e.Portrait}); ok {
		page.Portrait = template.URL(uri) // #nosec G203 -- built by PortraitDataURI from decoded JPEG bytes
	}
	if qr, err := demoqr.DataURI(offer.URI); err == nil {
		page.QR = qr
	}
	page.AppLink = appLink(offer.URI)
	if a.cfg.WebWalletURL != "" {
		page.WebWalletLink = a.cfg.WebWalletURL + "/receive?offer=" + url.QueryEscape(offer.URI)
	}
	// The offer is a bearer secret, next to the passport's identity.
	renderPage(w, http.StatusOK, offerTemplate, page, true)
}

type errorPage struct {
	Header  demoui.Header
	Message string
}

var errorTemplate = parsePage("error", pageHead+`</head><body>
{{template "site-header" .Header}}
<main>
<section class="verdict refused">
<p class="mark" aria-hidden="true">✗</p>
<div><h1>Something went wrong</h1>
<p>{{.Message}}</p></div>
</section>
<p class="actions"><a href="/demo/" class="btn">Start again</a></p>
</main>
`+pageFoot)

// writeHTMLError shows message on an error page. It names no page under
// /demo/ as current, and counts nothing: holders see it too, from the
// approval step.
func (a *App) writeHTMLError(w http.ResponseWriter, status int, message string) {
	h := siteHeader()
	h.Nav = []demoui.Link{{Href: pathUpload, Label: "Upload a passport"}}
	renderPage(w, status, errorTemplate, errorPage{Header: h, Message: message}, true)
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
