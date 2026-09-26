package webwallet

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/fxamacker/cbor/v2"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/walletapp"
)

// card is how a stored credential is shown.
type card struct {
	Path   string
	Format string
	Title  string
	Claims [][2]string // label, value
	Raw    [][2]string // raw ICAO data groups: name, size
	Error  string
}

// hiddenClaims are SD-JWT/registered claims not worth showing a holder.
var hiddenClaims = map[string]bool{"_sd": true, "_sd_alg": true, "cnf": true, "vct": true, "iss": true, "iat": true, "exp": true, "nbf": true, "status": true}

// cardFor decodes a stored credential for display. It's the holder's
// own credential, so it's read without re-verifying the issuer.
func cardFor(s walletapp.Stored) card {
	c := card{Path: s.Path, Format: s.Format, Title: "Passport credential"}
	var claims map[string]any
	var err error
	switch s.Format {
	case "dc+sd-jwt":
		claims, err = sdjwtClaims(s.Credential)
	case "mso_mdoc":
		claims, err = mdocClaims(s.Credential)
	default:
		err = fmt.Errorf("unknown format %q", s.Format)
	}
	if err != nil {
		c.Error = "couldn't read this credential"
		return c
	}

	keys := make([]string, 0, len(claims))
	for k := range claims {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if hiddenClaims[k] {
			continue
		}
		v := claims[k]
		if strings.HasPrefix(k, "icao_") {
			c.Raw = append(c.Raw, [2]string{k, rawSize(v)})
			continue
		}
		c.Claims = append(c.Claims, [2]string{label(k), display(v)})
	}
	return c
}

func sdjwtClaims(compact string) (map[string]any, error) {
	pres, err := sdjwtvc.Parse(compact)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(pres.IssuerJWT, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("malformed issuer JWT")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, err
	}
	alg := sdjwtvc.DefaultHashAlg
	if a, ok := payload["_sd_alg"].(string); ok {
		alg = sdjwtvc.HashAlg(a)
	}
	return sdjwtvc.ResolveDisclosures(payload, alg, pres.Disclosures)
}

func mdocClaims(encoded string) (map[string]any, error) {
	wire, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	signed, err := mdoc.UnmarshalIssuerSigned(wire)
	if err != nil {
		return nil, err
	}
	out := map[string]any{}
	for _, items := range signed.NameSpaces {
		for _, it := range items {
			out[it.ElementIdentifier] = it.ElementValue
		}
	}
	return out, nil
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

// rawSize describes a raw data group: bytes in an mdoc, base64url text
// in an SD-JWT.
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
