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
