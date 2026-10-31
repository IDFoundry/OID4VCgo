// Package demoui is what the passport-vdc demo's pages share: one
// stylesheet (light and dark, from CSS custom properties), the header
// every page starts with, small scripts that enhance a page without
// being needed for it to work, and the readable labels and values the
// pages show a credential's claims by.
//
// Everything is inline: the pages load nothing from anywhere else.
package demoui

import (
	"html"
	"html/template"
)

// Head starts a page titled title: the doctype, the meta tags and the
// stylesheet. The page closes the head itself, after anything it adds
// there.
func Head(title string) string {
	return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>` + html.EscapeString(title) + `</title>
<style>
` + Style + `</style>
`
}

// Foot ends a page.
const Foot = `
</body>
</html>
`

// Header is a page's header: an icon, a title and a subtitle, with
// badges after the subtitle and the site's navigation.
type Header struct {
	Icon, Title, Subtitle string
	Badges                []Badge
	// Nav links the site's pages; NavLabel names the navigation for
	// screen readers.
	Nav      []Link
	NavLabel string
}

// Badge is a small labelled pill. Class is "", "ok", "bad" or "warn".
type Badge struct{ Text, Class string }

// Link is one navigation link. Count, when set, is shown next to it
// (a number of items waiting, say); Current marks the page shown.
type Link struct {
	Href, Label, Count string
	Current            bool
}

// WithCurrent is h with the link to href marked as the page shown.
func (h Header) WithCurrent(href string) Header {
	nav := make([]Link, len(h.Nav))
	for i, l := range h.Nav {
		l.Current = l.Href == href
		nav[i] = l
	}
	h.Nav = nav
	return h
}

// headerTemplate renders a Header: {{template "site-header" .}}.
const headerTemplate = `{{define "site-header"}}<header class="site{{if gt (len .Nav) 1}} site-multi{{end}}">
<span class="rp-icon" aria-hidden="true">{{.Icon}}</span>
<div><p class="rp-name">{{.Title}}</p><p class="rp-sub">{{.Subtitle}}{{range .Badges}} · <span class="badge{{with .Class}} {{.}}{{end}}">{{.Text}}</span>{{end}}</p></div>
{{if .Nav}}<nav class="site-nav" aria-label="{{if .NavLabel}}{{.NavLabel}}{{else}}Site{{end}}">{{range .Nav}}<a href="{{.Href}}"{{if .Current}} aria-current="page"{{end}}>{{.Label}}{{with .Count}} <span class="count">{{.}}</span>{{end}}</a>{{end}}</nav>{{end}}
</header>{{end}}`

// Parse parses a page template named name from body, which can use
// {{template "site-header" .Header}}, with funcs.
func Parse(name string, funcs template.FuncMap, body string) *template.Template {
	return template.Must(template.New(name).Funcs(funcs).Parse(headerTemplate + body))
}

// CopyScript makes each <button data-copy="ID" data-copy-status="ID"
// hidden> copy the text of the element named by data-copy, reporting
// in the one named by data-copy-status. The buttons stay hidden where
// the browser can't copy (or without JavaScript).
const CopyScript = `<script>
(function () {
	if (!navigator.clipboard) return;
	document.querySelectorAll("button[data-copy]").forEach(function (button) {
		button.hidden = false;
		button.addEventListener("click", function () {
			var status = document.getElementById(button.getAttribute("data-copy-status"));
			navigator.clipboard.writeText(document.getElementById(button.getAttribute("data-copy")).textContent.trim()).then(
				function () { status.textContent = "Copied."; },
				function () { status.textContent = "Couldn't copy: select it instead."; });
		});
	});
})();
</script>`
