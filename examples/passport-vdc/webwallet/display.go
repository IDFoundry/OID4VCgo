package webwallet

import (
	"html/template"
	"slices"
	"strings"
	"time"

	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/credential"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/internal/demoui"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/walletapp"
)

// card is how a stored credential is shown: whose it is, its holder's
// claims by readable label, and apart the credential's own and the raw
// ones (demoui.DisplayRows).
type card struct {
	Path       string
	Format     string
	Holder     string
	ReceivedAt time.Time
	Rows, Raw  []demoui.ClaimRow
	// Portrait is the holder's photo as a data: URL, shown as an image
	// rather than a claim row.
	Portrait template.URL
	Error    string
}

// cardFor decodes a stored credential for display. It's the holder's
// own credential, so it's read without re-verifying the issuer.
func cardFor(s walletapp.Stored) card {
	c := card{Path: s.Path, Format: s.Format, ReceivedAt: s.ReceivedAt}
	claims, err := walletapp.ReadClaims(s.Format, s.Credential)
	if err != nil {
		c.Error = "couldn't read this credential"
		return c
	}
	c.Holder = walletapp.HolderName(claims)
	c.Portrait = portraitOf(claims)
	c.Rows, c.Raw = demoui.DisplayRows(s.Format, claims)
	return c
}

// portraitOf is the portrait claims carry, as a data: URL, or "".
func portraitOf(claims map[string]any) template.URL {
	if uri, ok := credential.PortraitDataURI(claims); ok {
		return template.URL(uri) // #nosec G203 -- built by PortraitDataURI from decoded JPEG bytes
	}
	return ""
}

// optionsFor are a request's options as the consent page shows them:
// each with its holder's portrait, from the stored credentials, and what
// it discloses by label (each once) and by claim path: what's asked
// for, what the credential discloses whatever is asked for, and what
// the verifier says it will keep.
func optionsFor(options []walletapp.Option, stored []walletapp.Stored) []consentOption {
	portraits := map[string]template.URL{}
	for _, s := range stored {
		if claims, err := walletapp.ReadClaims(s.Format, s.Credential); err == nil {
			portraits[s.Path] = portraitOf(claims)
		}
	}
	out := make([]consentOption, 0, len(options))
	for _, o := range options {
		v := consentOption{Ref: o.Ref, Holder: o.Holder, Format: o.Format, Portrait: portraits[o.CredentialID]}
		v.Labels, v.Paths = pathLabels(o.Format, o.Claims)
		v.AlsoLabels, v.AlsoPaths = pathLabels(o.Format, o.AlwaysDisclosed)
		v.RetainedLabels, _ = pathLabels(o.Format, o.Retained)
		out = append(out, v)
	}
	return out
}

// pathLabels are paths' labels, each once, and the paths themselves,
// for display.
func pathLabels(format string, paths [][]string) (labels, shown []string) {
	for _, p := range paths {
		if l := demoui.PathLabel(format, p); !slices.Contains(labels, l) {
			labels = append(labels, l)
		}
		shown = append(shown, strings.Join(p, " › "))
	}
	return labels, shown
}
