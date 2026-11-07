package appattest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/idfoundry/oid4vcgo/walletprovider"
)

// vectorKeys are the P-256 keys whose private scalars are the bytes 1
// to 32, and the same with the last byte 0x21: the client data test
// vectors' keys, which mobile/WALLET_PROVIDER.md lists too.
func vectorKeys(t *testing.T) []crypto.PublicKey {
	t.Helper()
	d := make([]byte, 32)
	for i := range d {
		d[i] = byte(i + 1)
	}
	k1, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), d)
	if err != nil {
		t.Fatal(err)
	}
	d[31] = 0x21
	k2, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), d)
	if err != nil {
		t.Fatal(err)
	}
	return []crypto.PublicKey{&k1.PublicKey, &k2.PublicKey}
}

// The challenge of the vectors: the bytes 0 to 31, base64url.
const vectorChallenge = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"

func TestClientDataVectors(t *testing.T) {
	keys := vectorKeys(t)
	for _, tc := range []struct {
		purpose walletprovider.Purpose
		keys    []crypto.PublicKey
		data    string
		hash    string
	}{
		{
			purpose: walletprovider.PurposeRegistration, keys: keys[:1],
			data: "OID4VCgo-WalletProvider-AppAttest/1\nregistration\n" + vectorChallenge + "\n" +
				"6UoWwDCkLjV0J-pQG8c0THxbVhBcpR0AZDift1Yl5DM\n",
			hash: "659141d12dbf4b9421adb6a080d4245a01ead653218a6289376baa869a8f477f",
		},
		{
			purpose: walletprovider.PurposeHolder, keys: keys,
			data: "OID4VCgo-WalletProvider-AppAttest/1\nholder\n" + vectorChallenge + "\n" +
				"6UoWwDCkLjV0J-pQG8c0THxbVhBcpR0AZDift1Yl5DM\n6rpgUp9sT-ItA87f0SCoStuYFvCFUFrnT9HqUF0sY_8\n",
			hash: "3ba79d8b12988b5db62d590f308d273093573803711f21315bb2b3e504b1b38c",
		},
	} {
		data, err := ClientData(tc.purpose, vectorChallenge, tc.keys)
		if err != nil {
			t.Fatal(err)
		}
		if string(data) != tc.data {
			t.Errorf("%s: client data %q, want %q", tc.purpose, data, tc.data)
		}
		hash, err := ClientDataHash(tc.purpose, vectorChallenge, tc.keys)
		if err != nil {
			t.Fatal(err)
		}
		if got := hex.EncodeToString(hash); got != tc.hash {
			t.Errorf("%s: hash %s, want %s", tc.purpose, got, tc.hash)
		}
	}
}

func TestClientDataRefuses(t *testing.T) {
	keys := vectorKeys(t)
	for name, f := range map[string]func() ([]byte, error){
		"no keys":            func() ([]byte, error) { return ClientData(walletprovider.PurposeHolder, vectorChallenge, nil) },
		"no purpose":         func() ([]byte, error) { return ClientData("", vectorChallenge, keys) },
		"no challenge":       func() ([]byte, error) { return ClientData(walletprovider.PurposeHolder, "", keys) },
		"a two-line purpose": func() ([]byte, error) { return ClientData("holder\nregistration", vectorChallenge, keys) },
		"a two-line challenge": func() ([]byte, error) {
			return ClientData(walletprovider.PurposeHolder, vectorChallenge+"\n"+vectorChallenge, keys)
		},
		"a key without a JWK": func() ([]byte, error) {
			return ClientData(walletprovider.PurposeHolder, vectorChallenge, []crypto.PublicKey{"key"})
		},
		"the hash of nothing": func() ([]byte, error) { return ClientDataHash(walletprovider.PurposeHolder, vectorChallenge, nil) },
	} {
		if _, err := f(); !errors.Is(err, ErrConfig) {
			t.Errorf("%s: %v, want ErrConfig", name, err)
		}
	}
}
