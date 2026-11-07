package walletprovider

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/idfoundry/oid4vcgo/walletprovider/androidkey"
)

// AndroidAppsFlag is a repeatable command-line flag of
// ServiceConfig.AndroidApps, each package:sha256[,sha256...]: an
// Android app's package and the SHA-256 of every certificate it's
// signed with, in hex (colons allowed, as apksigner and keytool print
// them).
type AndroidAppsFlag []androidkey.AllowedApp

// AndroidAppsUsage is AndroidAppsFlag's usage text.
const AndroidAppsUsage = "package:sha256[,sha256...] — an Android app (its package and every signing certificate's SHA-256, hex) whose keys the library's own /v1/ protocol attests; repeatable"

// String implements flag.Value.
func (f *AndroidAppsFlag) String() string {
	var apps []string
	for _, a := range *f {
		apps = append(apps, a.Package)
	}
	return strings.Join(apps, " ")
}

// Set implements flag.Value, adding one app.
func (f *AndroidAppsFlag) Set(v string) error {
	pkg, digests, ok := strings.Cut(v, ":")
	if !ok || pkg == "" || digests == "" {
		return fmt.Errorf("want package:sha256[,sha256...], got %q", v)
	}
	app := androidkey.AllowedApp{Package: pkg}
	for _, d := range strings.Split(digests, ",") {
		raw, err := hex.DecodeString(strings.ReplaceAll(d, ":", ""))
		if err != nil || len(raw) != 32 {
			return fmt.Errorf("%q isn't a SHA-256 digest in hex", d)
		}
		app.SigningCertificateDigests = append(app.SigningCertificateDigests, raw)
	}
	*f = append(*f, app)
	return nil
}

// IOSAppsFlag is a repeatable command-line flag of
// ServiceConfig.IOSApps, each an App ID: an iOS app's team ID and
// bundle ID, TEAMID.bundle.id.
type IOSAppsFlag []string

// IOSAppsUsage is IOSAppsFlag's usage text.
const IOSAppsUsage = "TEAMID.bundle.id — an iOS app (its App ID: team ID and bundle ID) whose keys the library's own /v1/ protocol attests with App Attest, development environment included; repeatable. Turns off the demo protocol outside /v1/, which attests any caller"

// String implements flag.Value.
func (f *IOSAppsFlag) String() string { return strings.Join(*f, " ") }

// Set implements flag.Value, adding one app.
func (f *IOSAppsFlag) Set(v string) error {
	team, bundle, ok := strings.Cut(v, ".")
	if !ok || len(team) != 10 || strings.ToUpper(team) != team || bundle == "" || strings.ContainsAny(v, " \t") {
		return fmt.Errorf("want TEAMID.bundle.id (a 10-character team ID, then the bundle ID), got %q", v)
	}
	*f = append(*f, v)
	return nil
}
