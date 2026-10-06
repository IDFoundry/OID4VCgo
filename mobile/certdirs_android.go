package mobile

import "os"

// androidCertDirs is where Android keeps its CA certificates: Android
// 14's updatable store (the Conscrypt APEX) first, then the system one,
// which Android 14 no longer updates. Go itself reads only the system
// directory there (golang/go#71258).
const androidCertDirs = "/apex/com.android.conscrypt/cacerts:/system/etc/security/cacerts"

// Go loaded as an Android app's library starts with an empty
// environment (its runtime is given no envp), so the app can't set
// SSL_CERT_DIR for it: this does, before anything verifies a
// certificate (crypto/x509 loads the system roots on first use).
func init() {
	if os.Getenv("SSL_CERT_DIR") == "" {
		_ = os.Setenv("SSL_CERT_DIR", androidCertDirs)
	}
}
