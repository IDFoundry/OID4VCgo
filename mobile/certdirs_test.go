package mobile

import "testing"

func TestAndroidCertDir(t *testing.T) {
	apex := func(path string) bool { return path == androidAPEXCertDir }
	none := func(string) bool { return false }
	if got := androidCertDir(apex); got != androidAPEXCertDir {
		t.Errorf("with the APEX store: %q, want only %q", got, androidAPEXCertDir)
	}
	if got := androidCertDir(none); got != androidSystemCertDir {
		t.Errorf("without it: %q, want %q", got, androidSystemCertDir)
	}
}
