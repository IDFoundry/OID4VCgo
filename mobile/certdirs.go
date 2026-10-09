package mobile

// Android keeps its CA certificates in the system directory, which
// Android 14 stopped updating, and from Android 14 in the updatable
// Conscrypt APEX. Go itself reads only the system directory there
// (golang/go#71258).
const (
	androidAPEXCertDir   = "/apex/com.android.conscrypt/cacerts"
	androidSystemCertDir = "/system/etc/security/cacerts"
)

// androidCertDir is the one store Android trusts: the APEX's where it
// exists, else the system's. Not both: Go trusts every directory in
// SSL_CERT_DIR, so a CA an APEX update removes would stay trusted from
// the frozen system copy.
func androidCertDir(exists func(string) bool) string {
	if exists(androidAPEXCertDir) {
		return androidAPEXCertDir
	}
	return androidSystemCertDir
}
