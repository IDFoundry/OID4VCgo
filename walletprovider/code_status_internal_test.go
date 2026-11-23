package walletprovider

import "testing"

// CodeStatus is the status the Handler answers each code a client acts
// on with, so a client keying its action on both agrees with the
// Handler.
func TestCodeStatus_IsTheHandlers(t *testing.T) {
	for err, code := range map[error]string{
		ErrRegistrationExpired:   CodeRegistrationExpired,
		ErrInstanceKeyExpired:    CodeInstanceKeyExpired,
		ErrInstanceKeyRegistered: CodeInstanceKeyRegistered,
		ErrEvidenceRequired:      CodeEvidenceRequired,
		ErrInstanceRevoked:       "instance_revoked",
		ErrRateLimited:           CodeRateLimited,
	} {
		got := refusal(err)
		if got.code != code || got.status != CodeStatus(code) {
			t.Errorf("%v: the Handler answers %d %s, CodeStatus(%s) = %d", err, got.status, got.code, code, CodeStatus(code))
		}
	}
	if got := CodeStatus("evidence_rejected"); got != 0 {
		t.Errorf("CodeStatus(evidence_rejected) = %d, want 0", got)
	}
}
