//go:build !mobiletest

package mobile

// IsTestBuild reports whether this framework was built with the
// mobiletest tag, carrying TestEnv: an app should refuse to run on one.
func IsTestBuild() bool { return false }
