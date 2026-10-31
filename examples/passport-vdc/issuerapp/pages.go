package issuerapp

import (
	"html/template"
	"net/http"
	"strconv"

	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/internal/demoui"
)

// HTTP header names and values the pages use.
const (
	headerContentType  = "Content-Type"
	contentTypeHTML    = "text/html; charset=utf-8"
	headerCacheControl = "Cache-Control"
	noStore            = "no-store"
)

// pageHead starts every page; pageFoot ends it.
var pageHead = demoui.Head("Passport → Digital Credential (demo)")

const pageFoot = demoui.Foot

// The pages under /demo/, which the header links.
const (
	pathUpload = "/demo/"
	pathReview = "/demo/review"
	pathKept   = "/demo/kept"
	pathStatus = "/demo/status"
)

// siteHeader is the issuer's header, without navigation: the approval
// page's, which holders reach from their wallet.
func siteHeader() demoui.Header {
	return demoui.Header{Icon: "🪪", Title: "Passport issuer", Subtitle: "Passport → Digital Credential · an OID4VCgo demo"}
}

// header is the header of the issuer's pages under /demo/, linking
// them all, the page at current marked, with how many issuances await
// review. The count says nothing about any passport.
func (a *App) header(current string) demoui.Header {
	h := siteHeader()
	review := ""
	if n := a.pendingReviews(); n > 0 {
		review = strconv.Itoa(n)
	}
	h.NavLabel = "Issuer pages"
	h.Nav = []demoui.Link{
		{Href: pathUpload, Label: "Upload"},
		{Href: pathReview, Label: "Review", Count: review},
		{Href: pathKept, Label: "Kept"},
		{Href: pathStatus, Label: "Issued credentials"},
	}
	return h.WithCurrent(current)
}

// parsePage parses a page template, which can use the shared header.
func parsePage(name, body string) *template.Template {
	return demoui.Parse(name, pageFuncs, body)
}

// renderPage writes an HTML page, never cached when noCache is set: a
// page with passport data, a credential offer, or a code.
func renderPage(w http.ResponseWriter, status int, t *template.Template, data any, noCache bool) {
	w.Header().Set(headerContentType, contentTypeHTML)
	if noCache {
		w.Header().Set(headerCacheControl, noStore)
	}
	w.WriteHeader(status)
	_ = t.Execute(w, data)
}
