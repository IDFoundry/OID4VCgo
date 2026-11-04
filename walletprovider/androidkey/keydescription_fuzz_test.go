package androidkey_test

import (
	"errors"
	"testing"

	"github.com/idfoundry/oid4vcgo/walletprovider/androidkey"
)

// FuzzParseKeyDescription: any input parses or is refused with
// ErrMalformed, without panicking, and what parses keeps the schema's
// bounds.
func FuzzParseKeyDescription(f *testing.F) {
	for _, name := range []string{"ec_tee_chain.pem", "ec_strongbox_chain.pem"} {
		f.Add(extensionOf(f, readChain(f, name)[0]))
	}
	good := goodSpec(f)
	f.Add(good.encode(f))
	good.version = 2
	good.hw = replace(good.hw, 704, derSeq(f, derOctets(f, nil), []byte{0x01, 0x01, 0x01}, derEnum(f, 1)))
	f.Add(good.encode(f))
	f.Add([]byte{0x30, 0x00})
	f.Fuzz(func(t *testing.T, der []byte) {
		kd, err := androidkey.ParseKeyDescription(der)
		if err != nil {
			if !errors.Is(err, androidkey.ErrMalformed) {
				t.Errorf("error %v doesn't wrap ErrMalformed", err)
			}
			return
		}
		if !validLevel(kd.AttestationSecurityLevel) || !validLevel(kd.KeyMintSecurityLevel) ||
			len(kd.AttestationChallenge) > androidkey.MaxChallengeBytes || kd.AttestationVersion < 1 || kd.KeyMintVersion < 1 {
			t.Errorf("parsed %+v", kd)
		}
		for _, l := range []androidkey.AuthorizationList{kd.SoftwareEnforced, kd.HardwareEnforced} {
			if rot := l.RootOfTrust; rot != nil && (rot.VerifiedBootState < androidkey.Verified || rot.VerifiedBootState > androidkey.Failed) {
				t.Errorf("boot state %d", rot.VerifiedBootState)
			}
		}
	})
}

func validLevel(l androidkey.SecurityLevel) bool {
	return l >= androidkey.Software && l <= androidkey.StrongBox
}
