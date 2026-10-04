package walletflow

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/statuslist"
)

// Logo is an image the issuer names for display: its URI, https or a
// data: image, and alternative text.
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
		d.IssuerName = metadata.Display[i].Name
		d.IssuerLogo = logoOf(metadata.Display[i].Logo)
	}
	cm := metadata.CredentialConfigurationsSupported[configID].CredentialMetadata
	if cm == nil {
		return d
	}
	if i := bestLocale(len(cm.Display), func(i int) string { return cm.Display[i].Locale }, locales); i >= 0 {
		c := cm.Display[i]
		d.Name, d.Description, d.Logo = c.Name, c.Description, logoOf(c.Logo)
		d.BackgroundColor, d.TextColor = c.BackgroundColor, c.TextColor
	}
	return d
}

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

// logoOf is l as a Logo, when its URI is one an app may load: https, or
// a data: image. Anything else — http, a custom scheme — is dropped.
func logoOf(l *oid4vci.Logo) *Logo {
	if l == nil {
		return nil
	}
	u, err := url.Parse(l.URI)
	switch {
	case err != nil:
		return nil
	case u.Scheme == "https" && u.Host != "",
		u.Scheme == "data" && strings.HasPrefix(u.Opaque, "image/"):
		return &Logo{URI: l.URI, AltText: l.AltText}
	}
	return nil
}

// Credential status values, in CredentialStatus.Value.
const (
	StatusValid     = "valid"
	StatusInvalid   = "invalid"
	StatusSuspended = "suspended"
)

// CredentialStatus is a credential's revocation status, as the wallet
// last found it in the issuer's status list (Wallet.CheckStatus): Value
// is StatusValid, StatusInvalid (revoked), StatusSuspended, or another
// status the list defines as "0x" and its value; empty when never
// checked.
type CredentialStatus struct {
	Value     string
	CheckedAt time.Time
}

// CheckStatus fetches the issuer's status list for the credential id
// names, checks it's signed by a certificate chaining to IssuerRoots,
// and records the credential's status in it: the stored credential is
// returned with its Status. A credential without a status list has
// nothing to check, and is returned as it is. The status list tells the
// issuer nothing about which credential is checked: it's one list for
// many credentials (the Token Status List's herd privacy).
func (w *Wallet) CheckStatus(ctx context.Context, id string) (StoredCredential, error) {
	c, err := w.deps.Credentials.Get(ctx, id)
	if err != nil {
		return StoredCredential{}, fmt.Errorf("walletflow: credential: %w", err)
	}
	if c.StatusList == nil {
		return c, nil
	}
	checker := statuslist.Checker{
		Fetcher: statuslist.Fetcher{HTTP: w.deps.HTTP, AllowLoopback: w.cfg.Development},
		Roots:   w.cfg.IssuerRoots,
		Options: statuslist.VerifyOptions{Now: w.deps.Clock},
	}
	status, _, err := checker.Check(ctx, *c.StatusList, c.StatusListCWT)
	if err != nil {
		return StoredCredential{}, fmt.Errorf("walletflow: credential %q's status: %w", id, err)
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
	if cur.StatusList == nil || *cur.StatusList != *c.StatusList {
		return cur, nil
	}
	cur.Status = CredentialStatus{Value: statusValue(status), CheckedAt: w.deps.Clock().UTC()}
	if err := w.deps.Credentials.Put(ctx, cur); err != nil {
		return StoredCredential{}, fmt.Errorf("walletflow: store credential %q's status: %w", id, err)
	}
	return cur, nil
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
