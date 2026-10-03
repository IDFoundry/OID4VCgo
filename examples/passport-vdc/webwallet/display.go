package webwallet

import (
	"encoding/base64"
	"fmt"
	"html/template"
	"sort"
	"strings"

	"github.com/fxamacker/cbor/v2"

	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/credential"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/walletapp"
)

// card is how a stored credential is shown.
type card struct {
	Path   string
	Format string
	Title  string
	Claims [][2]string // label, value
	Raw    [][2]string // the passport file: name, size
	// Portrait is the holder's photo as a data: URL, shown as an image
	// rather than a claim row.
	Portrait template.URL
	Error    string
}

// hiddenClaims are SD-JWT/registered claims not worth showing a holder.
var hiddenClaims = map[string]bool{"_sd": true, "_sd_alg": true, "cnf": true, "vct": true, "iss": true, "iat": true, "exp": true, "nbf": true, "status": true}

// cardFor decodes a stored credential for display. It's the holder's
// own credential, so it's read without re-verifying the issuer.
func cardFor(s walletapp.Stored) card {
	c := card{Path: s.Path, Format: s.Format, Title: "Passport credential"}
	var claims map[string]any
	var err error
	claims, err = walletapp.ReadClaims(s.Format, s.Credential)
	if err != nil {
		c.Error = "couldn't read this credential"
		return c
	}

	if uri, ok := credential.PortraitDataURI(claims); ok {
		c.Portrait = template.URL(uri) // #nosec G203 -- built by PortraitDataURI from decoded JPEG bytes
	}
	keys := make([]string, 0, len(claims))
	for k := range claims {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if hiddenClaims[k] || k == credential.Portrait || k == credential.SDJWTPicture {
			continue
		}
		v := claims[k]
		if k == credential.PassportFile {
			c.Raw = append(c.Raw, [2]string{k, rawSize(v)})
			continue
		}
		c.Claims = append(c.Claims, [2]string{label(k), display(v)})
	}
	return c
}

// label turns a claim name into a heading.
func label(k string) string {
	s := strings.ReplaceAll(k, "_", " ")
	return strings.ToUpper(s[:1]) + s[1:]
}

func display(v any) string {
	switch x := v.(type) {
	case cbor.Tag:
		return fmt.Sprint(x.Content)
	case []any:
		parts := make([]string, len(x))
		for i, e := range x {
			parts[i] = display(e)
		}
		return strings.Join(parts, ", ")
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, len(keys))
		for i, k := range keys {
			parts[i] = k + ": " + display(x[k])
		}
		return strings.Join(parts, "; ")
	default:
		return fmt.Sprint(x)
	}
}

// rawSize describes the passport file: bytes in an mdoc, base64url
// text in an SD-JWT.
func rawSize(v any) string {
	switch x := v.(type) {
	case []byte:
		return fmt.Sprintf("%d bytes", len(x))
	case string:
		return fmt.Sprintf("%d bytes", base64.RawURLEncoding.DecodedLen(len(x)))
	default:
		return "present"
	}
}
