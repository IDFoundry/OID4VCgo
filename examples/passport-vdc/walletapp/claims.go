package walletapp

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/credential"
)

// ReadClaims decodes a stored credential of format for display: an
// SD-JWT VC's claims with every disclosure resolved, or an mdoc's
// element identifier → value, across its namespaces. It's the holder's
// own credential, checked when it was received, so it isn't verified
// again.
func ReadClaims(format, stored string) (map[string]any, error) {
	switch format {
	case "dc+sd-jwt":
		return sdjwtClaims(stored)
	case "mso_mdoc":
		return mdocClaims(stored)
	}
	return nil, fmt.Errorf("unknown format %q", format)
}

// HolderName is the name a passport credential's claims give, given
// names first: how a wallet with several people's passports tells them
// apart. "" when the claims carry none.
func HolderName(claims map[string]any) string {
	var parts []string
	for _, k := range []string{credential.GivenName, credential.FamilyName} {
		if s, ok := claims[k].(string); ok && s != "" {
			parts = append(parts, s)
		}
	}
	return strings.Join(parts, " ")
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
