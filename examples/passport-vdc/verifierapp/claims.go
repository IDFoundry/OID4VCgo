package verifierapp

import (
	"encoding/json"
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/credential"
)

// The result page shows disclosed claims by these labels, in both
// formats: the mdoc's element names and the SD-JWT VC's claim names
// (see credential's names). expiry_date is the one name that means
// something different in each (claimLabel).
var claimLabels = map[string]string{
	credential.FamilyName:           "Family name",
	credential.GivenName:            "Given names",
	credential.BirthDate:            "Date of birth",
	credential.SDJWTBirthDate:       "Date of birth",
	credential.Sex:                  "Sex",
	credential.Nationality:          "Nationality",
	credential.SDJWTNationalities:   "Nationality",
	credential.IssuingCountry:       "Issuing country",
	credential.DocumentNumber:       "Passport number",
	credential.TravelDocumentNumber: "Passport number",
	credential.PassportExpiryDate:   "Passport expiry",
	credential.NamesFromMRZ:         "Names from the MRZ only",
	credential.Portrait:             "Photo",
	credential.SDJWTPicture:         "Photo",
	credential.PassportFile:         "Passport file (chip data)",
	credential.IssuingAuthority:     "Credential issued by",
	credential.IssueDate:            "Credential issued",
	credential.SDJWTAgeEqualOrOver:  "Age",
	// An SD-JWT VC's own claims, which every presentation carries.
	"vct":    "Credential type",
	"exp":    "Credential expiry",
	"iat":    "Credential issued",
	"nbf":    "Credential valid from",
	"iss":    "Issuer",
	"cnf":    "Holder key",
	"status": "Status list entry",
}

// claimOrder puts the claims that say who the holder is first, in this
// order; the rest follow by label.
var claimOrder = []string{
	credential.FamilyName, credential.GivenName, credential.BirthDate, credential.SDJWTBirthDate,
	credential.SDJWTAgeEqualOrOver, credential.Nationality, credential.SDJWTNationalities, credential.Sex,
	credential.DocumentNumber, credential.TravelDocumentNumber, credential.IssuingCountry,
	credential.PassportExpiryDate, credential.NamesFromMRZ,
}

// credentialClaims are the claims about the credential rather than the
// holder: what every SD-JWT VC carries, and the mdoc's own validity.
// The result page collapses them with the raw data.
var credentialClaims = map[string]bool{
	"vct": true, "exp": true, "iat": true, "nbf": true, "iss": true, "cnf": true, "status": true,
	credential.IssuingAuthority: true, credential.IssueDate: true,
}

const ageOverPrefix = "age_over_"

// claimLabel is a claim's label on the result page: key is a flattened
// claim name in format's credential.
func claimLabel(format, key string) string {
	if key == credential.ExpiryDate {
		if format == "mso_mdoc" {
			return "Credential expiry" // the mobile document's own (ISO/IEC TS 23220-2)
		}
		return "Passport expiry"
	}
	if n, ok := strings.CutPrefix(key, ageOverPrefix); ok {
		if age, err := strconv.Atoi(n); err == nil {
			return "Over " + strconv.Itoa(age)
		}
	}
	if l, ok := claimLabels[key]; ok {
		return l
	}
	return key
}

// claimRow is one disclosed claim as the result page shows it.
type claimRow struct{ Label, Value string }

// displayRows renders a credential's disclosed claims for the result
// page: the holder's, important ones first, with readable values; and,
// apart, the credential's own and the raw ones (bytes, long encoded
// text, structures), which the page collapses. The portrait is shown as
// an image instead (see requestPageFor).
func displayRows(format string, claims map[string]any) (rows, raw []claimRow) {
	keys := make([]string, 0, len(claims))
	for k := range claims {
		if k != credential.Portrait && k != credential.SDJWTPicture {
			keys = append(keys, k)
		}
	}
	sortClaims(format, keys)
	for _, k := range keys {
		label := claimLabel(format, k)
		if k == credential.SDJWTAgeEqualOrOver {
			if ages, ok := claims[k].(map[string]any); ok {
				rows = append(rows, ageRows(ages)...)
				continue
			}
		}
		if n, ok := strings.CutPrefix(k, ageOverPrefix); ok {
			if over, isBool := claims[k].(bool); isBool {
				rows = append(rows, claimRow{"Age", ageValue(n, over)})
				continue
			}
		}
		value, isRaw := formatClaim(format, k, claims[k])
		if isRaw || credentialClaims[k] || format == "mso_mdoc" && k == credential.ExpiryDate {
			raw = append(raw, claimRow{label, value})
			continue
		}
		rows = append(rows, claimRow{label, value})
	}
	return rows, raw
}

// sortClaims sorts format's claim names keys by claimOrder, then label.
func sortClaims(format string, keys []string) {
	rank := func(k string) int {
		if strings.HasPrefix(k, ageOverPrefix) {
			k = credential.SDJWTAgeEqualOrOver
		}
		if i := slices.Index(claimOrder, k); i >= 0 {
			return i
		}
		return len(claimOrder)
	}
	slices.SortFunc(keys, func(a, b string) int {
		if c := rank(a) - rank(b); c != 0 {
			return c
		}
		return strings.Compare(claimLabel(format, a), claimLabel(format, b))
	})
}

// ageRows are an SD-JWT VC's age_equal_or_over claims, youngest first.
func ageRows(ages map[string]any) []claimRow {
	var rows []claimRow
	for _, n := range ageThresholds(ages) {
		if over, ok := ages[n].(bool); ok {
			rows = append(rows, claimRow{"Age", ageValue(n, over)})
		}
	}
	return rows
}

// ageThresholds are an age_equal_or_over claim's ages, youngest first.
func ageThresholds(ages map[string]any) []string {
	thresholds := make([]string, 0, len(ages))
	for n := range ages {
		thresholds = append(thresholds, n)
	}
	slices.SortFunc(thresholds, func(a, b string) int {
		x, _ := strconv.Atoi(a)
		y, _ := strconv.Atoi(b)
		return x - y
	})
	return thresholds
}

func ageValue(threshold string, over bool) string {
	n, _ := strconv.Atoi(threshold)
	if over {
		return fmt.Sprintf("✓ Over %d", n)
	}
	return fmt.Sprintf("✗ Under %d", n)
}

// maxShown is how long a text value is shown as itself; a longer one is
// raw encoded data (the passport file as base64url, say).
const maxShown = 200

// formatClaim is v, claim key's value in format's credential, as text,
// and whether it's raw data the page collapses.
func formatClaim(format, key string, v any) (string, bool) {
	switch key {
	case credential.Sex:
		return sexOf(v), false
	case "exp", "iat", "nbf":
		if t, ok := unixTime(v); ok {
			return t.UTC().Format("2 January 2006, 15:04 UTC"), false
		}
	}
	switch x := v.(type) {
	case bool:
		if x {
			return "✓ Yes", false
		}
		return "✗ No", false
	case []byte:
		return fmt.Sprintf("%d bytes", len(x)), true
	case string:
		if len(x) > maxShown {
			return fmt.Sprintf("%d characters (base64url)", len(x)), true
		}
		if d, ok := formatDate(x); ok {
			return d, false
		}
		return x, false
	case cbor.Tag:
		if s, ok := x.Content.(string); ok {
			if d, ok := formatDate(s); ok {
				return d, false
			}
			return s, false
		}
	case time.Time:
		return x.UTC().Format("2 January 2006"), false
	case []any:
		parts := make([]string, 0, len(x))
		for _, e := range x {
			s, raw := formatClaim(format, "", e)
			if raw {
				return encoded(v), true
			}
			parts = append(parts, s)
		}
		return strings.Join(parts, ", "), false
	case map[string]any:
		// ISO/IEC TS 23220-2's birth_date: the date, and which of its
		// digits aren't known.
		if d, ok := x[credential.BirthDate]; ok && key == credential.BirthDate {
			s, _ := formatClaim(format, "", d)
			if _, approximate := x["approximate_mask"]; approximate {
				s += " (approximate)"
			}
			return s, false
		}
	case map[any]any:
		if d, ok := x[credential.BirthDate]; ok && key == credential.BirthDate {
			s, _ := formatClaim(format, "", d)
			if _, approximate := x["approximate_mask"]; approximate {
				s += " (approximate)"
			}
			return s, false
		}
	}
	return encoded(v), true
}

// encoded is a structured value as JSON, or its size when that's long.
func encoded(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprint(v)
	}
	if len(b) > maxShown {
		return fmt.Sprintf("%d characters (JSON)", len(b))
	}
	return string(b)
}

// formatDate is a full-date (YYYY-MM-DD) in words.
func formatDate(s string) (string, bool) {
	t, err := time.Parse(time.DateOnly, s)
	if err != nil {
		return "", false
	}
	return t.Format("2 January 2006"), true
}

// unixTime reads a JWT NumericDate.
func unixTime(v any) (time.Time, bool) {
	switch x := v.(type) {
	case float64:
		if math.IsNaN(x) || math.IsInf(x, 0) {
			return time.Time{}, false
		}
		return time.Unix(int64(x), 0), true
	case int64:
		return time.Unix(x, 0), true
	case json.Number:
		n, err := x.Int64()
		return time.Unix(n, 0), err == nil
	}
	return time.Time{}, false
}

// sexOf is the sex claim in words: an mdoc's ISO/IEC 5218 code, or an
// SD-JWT VC's MRZ letter.
func sexOf(v any) string {
	switch fmt.Sprint(v) {
	case "1", "M":
		return "Male"
	case "2", "F":
		return "Female"
	case "0", "X", "<", "":
		return "Unspecified"
	}
	return fmt.Sprint(v)
}

// requested is one claim a scenario asked for, and whether the
// credential disclosed it.
type requested struct {
	Label    string
	Received bool
}

// askedFor is what query asked of format's credential, by label, each
// with whether claims (the credential's disclosed claims, flattened)
// has it.
func askedFor(query dcql.Query, format string, claims map[string]any) []requested {
	id := sdjwtQueryID
	if format == "mso_mdoc" {
		id = mdocQueryID
	}
	var out []requested
	for _, cq := range query.Credentials {
		if cq.ID != id {
			continue
		}
		for _, cl := range cq.Claims {
			out = append(out, requestedClaim(format, cl.Path, claims))
		}
	}
	return out
}

// requestedClaim is the claim at path in format's credential: an mdoc's
// path is a namespace and an element, an SD-JWT VC's a claim name and,
// for age_equal_or_over, the age.
func requestedClaim(format string, path dcql.Path, claims map[string]any) requested {
	var keys []string
	for _, p := range path {
		if !p.IsKey() {
			break
		}
		keys = append(keys, p.Key())
	}
	if format == "mso_mdoc" && len(keys) > 0 {
		keys = keys[1:] // the namespace: flattened away
	}
	if len(keys) == 0 {
		return requested{Label: "(unnamed claim)"}
	}
	v, ok := claims[keys[0]]
	label := claimLabel(format, keys[0])
	if keys[0] == credential.SDJWTAgeEqualOrOver && len(keys) > 1 {
		label = "Over " + keys[1]
		ages, _ := v.(map[string]any)
		_, ok = ages[keys[1]]
	}
	return requested{Label: label, Received: ok}
}

// received are the labels of the holder's claims disclosed (not the
// credential's own, which every presentation carries), each once.
func received(format string, claims map[string]any) []string {
	var out []string
	add := func(l string) {
		if !slices.Contains(out, l) {
			out = append(out, l)
		}
	}
	keys := make([]string, 0, len(claims))
	for k := range claims {
		keys = append(keys, k)
	}
	sortClaims(format, keys)
	for _, k := range keys {
		switch {
		case credentialClaims[k] || format == "mso_mdoc" && k == credential.ExpiryDate:
		case k == credential.SDJWTAgeEqualOrOver:
			if ages, ok := claims[k].(map[string]any); ok {
				for _, n := range ageThresholds(ages) {
					add("Over " + n)
				}
			}
		default:
			add(claimLabel(format, k))
		}
	}
	return out
}
