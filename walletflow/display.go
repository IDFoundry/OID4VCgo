package walletflow

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/internal/certchain"
	"github.com/idfoundry/oid4vcgo/internal/displaytext"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"math"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/statuslist"
)

// Logo is an image the issuer names for display: its URI, https or a
// data: image, and alternative text. An https URI naming an IP address
// or a local name (a single label, or one under localhost, local,
// home.arpa, internal or lan) is dropped: loading it would have the
// phone reach into its own network for whoever wrote the metadata. The
// URI is the issuer's: loading it tells the issuer, or whoever serves
// it, that the holder is looking, so an app should fetch it once — when
// the holder accepts the credential, not on the offer's preview — and
// keep it.
type Logo struct {
	URI     string
	AltText string
}

// Display is how to show a credential, from the issuer's metadata
// (OpenID4VCI 1.0 §12.2.4) in the holder's preferred language
// (Config.Locales): the issuer's name and logo, and the credential's
// name, description, logo and colours. Each is empty when the issuer
// doesn't say.
type Display struct {
	IssuerName      string
	IssuerLogo      *Logo
	Name            string
	Description     string
	Logo            *Logo
	BackgroundColor string
	TextColor       string
}

// displayFor is configID's Display under metadata, in locales'
// language.
func displayFor(metadata oid4vci.Metadata, configID string, locales []string) Display {
	var d Display
	if i := bestLocale(len(metadata.Display), func(i int) string { return metadata.Display[i].Locale }, locales); i >= 0 {
		d.IssuerName = displayText(metadata.Display[i].Name, maxDisplayName)
		d.IssuerLogo = logoOf(metadata.Display[i].Logo)
	}
	cm := metadata.CredentialConfigurationsSupported[configID].CredentialMetadata
	if cm == nil {
		return d
	}
	if i := bestLocale(len(cm.Display), func(i int) string { return cm.Display[i].Locale }, locales); i >= 0 {
		c := cm.Display[i]
		d.Name, d.Description, d.Logo = displayText(c.Name, maxDisplayName), displayText(c.Description, maxDisplayDescription), logoOf(c.Logo)
		d.BackgroundColor, d.TextColor = displayColor(c.BackgroundColor), displayColor(c.TextColor)
	}
	return d
}

// The longest display texts kept, in runes: an issuer's name or a
// credential's (and a logo's alt text), and a description.
const (
	maxDisplayName        = 200
	maxDisplayDescription = 1000
)

// displayText is s, from an issuer's metadata, fit to show the holder
// (displaytext.Clean): no control, line separator or invisible format
// characters, and at most limit runes.
func displayText(s string, limit int) string { return displaytext.Clean(s, limit) }

// displayColor is c, an issuer's background_color or text_color
// (OpenID4VCI 1.0 §12.2.4: a CSS color), if it's a hex color or a
// named one, or rgb()/hsl() of numbers, "" otherwise: nothing else
// reaches the app's styling.
func displayColor(c string) string {
	if displayColorPattern.MatchString(c) {
		return c
	}
	return ""
}

var displayColorPattern = regexp.MustCompile(`^(#([0-9A-Fa-f]{3,4}|[0-9A-Fa-f]{6}|[0-9A-Fa-f]{8})|[A-Za-z]{3,20}|(rgb|rgba|hsl|hsla)\([0-9.%, /deg]{1,40}\))$`)

// bestLocale picks, among n display entries with the given locales, the
// one for the first of prefs it has — exactly, then by language — else
// one without a locale, else the first; -1 when there are none.
func bestLocale(n int, locale func(int) string, prefs []string) int {
	if n == 0 {
		return -1
	}
	language := func(tag string) string { l, _, _ := strings.Cut(strings.ToLower(tag), "-"); return l }
	for _, pref := range prefs {
		if i := firstIndex(n, func(i int) bool { return strings.EqualFold(locale(i), pref) }); i >= 0 {
			return i
		}
		if i := firstIndex(n, func(i int) bool { return locale(i) != "" && language(locale(i)) == language(pref) }); i >= 0 {
			return i
		}
	}
	if i := firstIndex(n, func(i int) bool { return locale(i) == "" }); i >= 0 {
		return i
	}
	return 0
}

// firstIndex is the first of 0..n-1 that match is true for, or -1.
func firstIndex(n int, match func(int) bool) int {
	for i := range n {
		if match(i) {
			return i
		}
	}
	return -1
}

// logoOf is l as a Logo, when its URI is one an app may load: https
// from a public host name, or a data: image. Anything else — http, a
// custom scheme, an IP address or a local name (localLogoHost) — is
// dropped.
func logoOf(l *oid4vci.Logo) *Logo {
	if l == nil {
		return nil
	}
	u, err := url.Parse(l.URI)
	switch {
	case err != nil:
		return nil
	case u.Scheme == "https" && u.Host != "" && !localLogoHost(u.Hostname()),
		// A raster image only: SVG can carry script, which a web view
		// showing the logo would run.
		u.Scheme == "data" && strings.HasPrefix(u.Opaque, "image/") && !strings.HasPrefix(strings.ToLower(u.Opaque), "image/svg"):
		return &Logo{URI: l.URI, AltText: displayText(l.AltText, maxDisplayName)}
	}
	return nil
}

// localLogoHost is whether host, a logo URI's, names something on the
// phone's own network rather than a public name: an IP address; a
// single label (router, a search-domain name); or a name under a
// special-use or local-only domain, localDomains. A host whose last
// label is a number is an IPv4 address to a WHATWG URL parser (as
// 2130706433 or 0x7f.1 are 127.0.0.1), so it counts as one. A public
// name whose DNS answers a private address can't be told apart without
// resolving it.
func localLogoHost(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if _, err := netip.ParseAddr(host); err == nil || !strings.Contains(host, ".") {
		return true
	}
	for _, d := range localDomains {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	last := host[strings.LastIndex(host, ".")+1:]
	return last != "" && (strings.Trim(last, "0123456789") == "" || strings.HasPrefix(last, "0x"))
}

// localDomains are the domains whose names only a local network
// resolves: localhost (RFC 6761 §6.3), local (mDNS, RFC 6762),
// home.arpa (RFC 8375), internal (reserved for private use by ICANN)
// and lan, a common home-router default.
var localDomains = []string{"localhost", "local", "home.arpa", "internal", "lan"}

// Credential status values, in CredentialStatus.Value.
const (
	StatusValid     = "valid"
	StatusInvalid   = "invalid"
	StatusSuspended = "suspended"
	// StatusUnknown is an mdoc whose MSO names an identifier list
	// (ISO/IEC 18013-5 §12.3.6.4), which the wallet can't check, or a
	// credential whose status names no mechanism the wallet knows (an
	// SD-JWT VC status claim with no status_list, an MSO status with
	// neither status_list nor identifier_list), and either no status
	// list or one on which it's valid: that mechanism may still revoke
	// it.
	StatusUnknown = "unknown"
)

// CredentialStatus is a credential's revocation status, as the wallet
// last found it in the issuer's status list (Wallet.CheckStatus): Value
// is StatusValid, StatusInvalid (revoked), StatusSuspended, another
// status the list defines as "0x" and its value, or StatusUnknown;
// empty when never checked.
type CredentialStatus struct {
	Value     string
	CheckedAt time.Time
}

// CheckStatus fetches the issuer's status list for the credential id
// names, checks it's signed by a certificate chaining to the issuer
// roots the credential was received under (IssuerRoots, or an mdoc's),
// and records the credential's status in it: the stored credential is
// returned with its Status. A credential without a status has
// nothing to check, and is returned as it is, as is an expired one: it
// isn't valid whatever its status, so its status list isn't fetched
// (draft-ietf-oauth-status-list §8.3). An mdoc naming an identifier
// list (ISO/IEC 18013-5 §12.3.6.4), which the wallet can't check, is
// StatusUnknown, unless a status list it names too says it's revoked,
// suspended or another status than valid; so is a credential whose
// status names no mechanism the wallet knows, rather than one with
// nothing to check. The status list tells the
// issuer nothing about which credential is checked: it's one list for
// many credentials (the Token Status List's herd privacy).
func (w *Wallet) CheckStatus(ctx context.Context, id string) (StoredCredential, error) {
	c, err := w.deps.Credentials.Get(ctx, id)
	if err != nil {
		return StoredCredential{}, fmt.Errorf("walletflow: credential: %w", err)
	}
	now := w.deps.Clock()
	live := liveStatusRefs(c, now)
	listed := uncheckedStatus(c, now)
	if len(live) == 0 && !listed {
		return c, nil
	}
	status := statuslist.StatusValid
	if len(live) > 0 {
		if status, err = w.checkStatusLists(ctx, c, live); err != nil {
			return StoredCredential{}, fmt.Errorf("walletflow: credential %q's status: %w", id, err)
		}
	}
	value := statusValue(status)
	if listed && status == statuslist.StatusValid {
		value = StatusUnknown
	}
	// Recorded on the credential as it is now: a presentation or a
	// refresh may have changed it meanwhile. A refreshed one references
	// another status list entry, which this didn't check.
	w.credMu.Lock()
	defer w.credMu.Unlock()
	cur, err := w.deps.Credentials.Get(ctx, id)
	if err != nil {
		return StoredCredential{}, fmt.Errorf("walletflow: credential: %w", err)
	}
	if !slices.Equal(statusRefs(cur), statusRefs(c)) || uncheckedStatus(cur, now) != listed {
		return cur, nil
	}
	cur.Status = CredentialStatus{Value: value, CheckedAt: now.UTC()}
	if err := w.deps.Credentials.Put(ctx, cur); err != nil {
		return StoredCredential{}, fmt.Errorf("walletflow: store credential %q's status: %w", id, err)
	}
	return cur, nil
}

// checkStatusLists is the status of c's copies on the status list
// entries live, their issuer's.
func (w *Wallet) checkStatusLists(ctx context.Context, c StoredCredential, live []statuslist.StatusListRef) (statuslist.StatusType, error) {
	// The roots the credential itself was checked against on receipt.
	roots, _ := w.cfg.issuerTrust(c.Format, c.DocType)
	checker := statuslist.Checker{
		Fetcher: statuslist.Fetcher{HTTP: w.deps.HTTP, AllowLoopback: w.cfg.Development},
		Roots:   roots,
		Options: statuslist.VerifyOptions{Now: w.deps.Clock, Revocation: w.cfg.StatusRevocation},
	}
	// Its status is its issuer's to sign, or one of its Status Issuers',
	// not another issuer's under IssuerRoots.
	if c.StatusListCWT {
		var err error
		if checker, err = mdocStatusChecker(checker, c.Credential); err != nil {
			return 0, err
		}
	} else {
		iss, _ := c.Claims["iss"].(string)
		checker.Options = statusOptionsFor(checker.Options, iss, signerKey(c.Credential), w.cfg.StatusIssuers[iss])
	}
	return checkCopies(ctx, checker, live, c.StatusListCWT)
}

// uncheckedStatus reports whether a copy of c not yet expired at now
// has a status the wallet can't check: an mdoc's identifier list
// (mdocStatus), or a status naming no mechanism the wallet knows — an
// MSO status with neither member, an SD-JWT VC status claim with no
// status_list. Either may still revoke it.
func uncheckedStatus(c StoredCredential, now time.Time) bool {
	for _, cp := range c.AllCopies() {
		if copyLive(c, cp, now) && copyStatusUnchecked(c.Format, cp.Credential) {
			return true
		}
	}
	return false
}

// copyStatusUnchecked reports whether credential, one copy in format,
// has a status the wallet can't check (uncheckedStatus). A copy that
// doesn't parse was checked on receipt, so it isn't one.
func copyStatusUnchecked(format, credential string) bool {
	switch format {
	case mdoc.CredentialFormat:
		status, err := mdocStatus(credential)
		return err == nil && status != nil && (status.IdentifierList != nil || status.StatusList == nil)
	case sdjwtvc.CredentialFormat:
		payload, err := sdjwtvcPayload(credential)
		if err != nil {
			return false
		}
		raw, present := payload["status"]
		status, isObject := raw.(map[string]any)
		_, hasList := status["status_list"]
		return present && (!isObject || !hasList)
	}
	return false
}

// copyLive reports whether copy cp of c hasn't yet expired at now: its
// own ValidUntil, or for a copy stored before copies kept theirs, c's.
func copyLive(c StoredCredential, cp CredentialCopy, now time.Time) bool {
	until := cp.ValidUntil
	if until.IsZero() {
		until = c.ValidUntil
	}
	return until.IsZero() || now.Before(until)
}

// statusRef is the status list entry copy cp of c references, nil for
// none: its own, or for a copy stored before copies kept theirs, c's.
func statusRef(c StoredCredential, cp CredentialCopy) *statuslist.StatusListRef {
	if cp.StatusList != nil {
		return cp.StatusList
	}
	return c.StatusList
}

// statusRefs are the status list entries c's copies reference.
func statusRefs(c StoredCredential) []statuslist.StatusListRef {
	var refs []statuslist.StatusListRef
	for _, cp := range c.AllCopies() {
		if ref := statusRef(c, cp); ref != nil {
			refs = append(refs, *ref)
		}
	}
	return refs
}

// liveStatusRefs are the distinct status list entries of c's copies
// not yet expired at now: an expired copy's status no longer matters.
func liveStatusRefs(c StoredCredential, now time.Time) []statuslist.StatusListRef {
	var refs []statuslist.StatusListRef
	for _, cp := range c.AllCopies() {
		ref := statusRef(c, cp)
		if ref == nil || !copyLive(c, cp, now) || slices.Contains(refs, *ref) {
			continue
		}
		refs = append(refs, *ref)
	}
	return refs
}

// checkCopies is the status of the copies whose entries are refs: the
// most severe among them, as the holder would want to know a copy was
// revoked even while the others aren't. A list several copies share is
// fetched and verified once.
func checkCopies(ctx context.Context, checker statuslist.Checker, refs []statuslist.StatusListRef, cwt bool) (statuslist.StatusType, error) {
	worst := statuslist.StatusValid
	lists := map[string]statuslist.StatusList{}
	for _, ref := range refs {
		var status statuslist.StatusType
		if list, ok := lists[ref.URI]; ok {
			if ref.Idx > math.MaxInt {
				return 0, fmt.Errorf("statuslist: index %d is out of bounds", ref.Idx)
			}
			v, err := list.Status(int(ref.Idx))
			if err != nil {
				return 0, err
			}
			status = statuslist.StatusType(v)
		} else {
			s, claims, err := checker.Check(ctx, ref, cwt)
			if err != nil {
				return 0, err
			}
			status, lists[ref.URI] = s, claims.StatusList
		}
		if severity(status) > severity(worst) {
			worst = status
		}
	}
	return worst, nil
}

// severity orders statuses by how much they matter to the holder:
// revoked, then suspended, then an application-specific value, then
// valid.
func severity(s statuslist.StatusType) int {
	switch s {
	case statuslist.StatusValid:
		return 0
	case statuslist.StatusInvalid:
		return 3
	case statuslist.StatusSuspended:
		return 2
	}
	return 1
}

func statusValue(s statuslist.StatusType) string {
	switch s {
	case statuslist.StatusValid:
		return StatusValid
	case statuslist.StatusInvalid:
		return StatusInvalid
	case statuslist.StatusSuspended:
		return StatusSuspended
	}
	return fmt.Sprintf("0x%02x", uint8(s))
}

// statusOptionsFor is opts for checking issuer's status list: signed
// with issuerKey, the key that signed the credential, or by a
// certificate naming issuer, or one naming one of statusIssuers
// (certchain.CheckIssuerName).
func statusOptionsFor(opts statuslist.VerifyOptions, issuer string, issuerKey crypto.PublicKey, statusIssuers []string) statuslist.VerifyOptions {
	if len(statusIssuers) == 0 || issuer == "" {
		opts.Issuer, opts.IssuerKey = issuer, issuerKey
		return opts
	}
	opts.LeafPolicy = func(leaf *x509.Certificate, _ [][]*x509.Certificate) error {
		if certchain.SameKey(leaf.PublicKey, issuerKey) || certchain.CheckIssuerName(leaf, issuer) == nil {
			return nil
		}
		for _, s := range statusIssuers {
			if certchain.CheckIssuerName(leaf, s) == nil {
				return nil
			}
		}
		return fmt.Errorf("the status list's signer is neither %q nor one of its Status Issuers", issuer)
	}
	// A Status Issuer's token may carry its own iss.
	opts.Issuer = ""
	return opts
}

// signerKey is the key in an SD-JWT VC's x5c leaf, verified when the
// credential was received; nil when it has none.
func signerKey(credential string) crypto.PublicKey {
	issuerJWT, _, _ := strings.Cut(credential, "~")
	header, _, err := jose.DecodeUnverified(issuerJWT)
	if err != nil {
		return nil
	}
	ders, err := certchain.X5CDERsFromHeader(header)
	if err != nil || len(ders) == 0 {
		return nil
	}
	leaf, err := x509.ParseCertificate(ders[0])
	if err != nil {
		return nil
	}
	return leaf.PublicKey
}

// mdocStatusChecker is checker for a stored mdoc's revocation list,
// whose signer must be trusted as ISO/IEC 18013-5 §12.3.6 says
// (mdoc.StatusTrust): through the Certificate its MSO's status names,
// or else under the CA that signed its document signer. Both are read
// from the credential, verified when it was received.
func mdocStatusChecker(checker statuslist.Checker, credential string) (statuslist.Checker, error) {
	issuerSigned, err := storedIssuerSigned(credential)
	if err != nil {
		return checker, err
	}
	status, path, err := mdoc.IssuerAuthStatus(issuerSigned)
	if err != nil {
		return checker, err
	}
	var ref *mdoc.StatusListRef
	if status != nil {
		ref = status.StatusList
	}
	trust, err := mdoc.StatusTrust(ref, path)
	if err != nil {
		return checker, err
	}
	if trust.Roots != nil {
		checker.Roots = trust.Roots
	} else {
		checker.Options.LeafPolicy = trust.LeafPolicy
	}
	checker.Options.RequireExp = true
	checker.Options.X5ChainProtectedOnly = true
	return checker, nil
}

// storedIssuerSigned is credential, a stored mdoc, decoded.
func storedIssuerSigned(credential string) (mdoc.IssuerSigned, error) {
	raw, err := base64.RawURLEncoding.DecodeString(credential)
	if err != nil {
		return mdoc.IssuerSigned{}, fmt.Errorf("decode credential: %w", err)
	}
	return mdoc.UnmarshalIssuerSigned(raw)
}

// mdocStatus is the status its MSO gives credential, a stored mdoc: nil
// for none.
func mdocStatus(credential string) (*mdoc.Status, error) {
	issuerSigned, err := storedIssuerSigned(credential)
	if err != nil {
		return nil, err
	}
	mso, err := mdoc.IssuerAuthMSO(issuerSigned)
	if err != nil {
		return nil, err
	}
	return mso.Status, nil
}
