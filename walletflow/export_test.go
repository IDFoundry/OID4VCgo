package walletflow

// Terminating reports that Terminate has been called on p, for a test
// to wait until it waits on Respond.
func Terminating(p *ProximityPresentation) bool { return p.terminating.Load() }
