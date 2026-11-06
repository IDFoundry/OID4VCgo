package walletflow

// Terminating reports that Terminate has been called on p, for a test
// to wait until it waits on Respond.
func Terminating(p *ProximityPresentation) bool { return p.terminating.Load() }

// OrderAnswers is orderAnswers over requests of docTypes, with no
// per-answer check, for a test of the rules across answers that no
// request built by this repository's readers can reach: those ask for
// each document type once.
func OrderAnswers(answers []MdocAnswer, docTypes ...string) ([]MdocAnswer, error) {
	return orderAnswers(answers, func(i int) string { return docTypes[i] }, func(MdocAnswer) error { return nil })
}
