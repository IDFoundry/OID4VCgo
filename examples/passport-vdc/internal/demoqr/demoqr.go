// Package demoqr renders the passport-vdc demo's QR codes, for handing
// a credential offer or presentation request to a wallet on another
// device.
package demoqr

import (
	"encoding/base64"
	"fmt"
	"html/template"

	"rsc.io/qr"
)

// DataURI encodes text as a QR code and returns it as a PNG data: URI,
// typed for use as an <img src> in an html/template.
func DataURI(text string) (template.URL, error) {
	code, err := qr.Encode(text, qr.M)
	if err != nil {
		return "", fmt.Errorf("demoqr: %w", err)
	}
	code.Scale = 4
	// #nosec G203 -- a data: URI of PNG bytes this function just encoded
	return template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(code.PNG())), nil
}
