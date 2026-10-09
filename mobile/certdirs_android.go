package mobile

import "os"

// Go loaded as an Android app's library starts with an empty
// environment (its runtime is given no envp), so the app can't set
// SSL_CERT_DIR for it: this does, before anything verifies a
// certificate (crypto/x509 loads the system roots on first use).
func init() {
	if os.Getenv("SSL_CERT_DIR") == "" {
		_ = os.Setenv("SSL_CERT_DIR", androidCertDir(dirExists))
	}
}
