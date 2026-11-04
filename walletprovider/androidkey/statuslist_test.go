package androidkey_test

import (
	"math/big"
	"testing"

	"github.com/idfoundry/oid4vcgo/walletprovider/androidkey"
)

func TestParseStatusList(t *testing.T) {
	l := statusFixture(t)
	if l.Len() != 4 {
		t.Errorf("Len = %d", l.Len())
	}
	for serial, want := range map[string]androidkey.StatusEntry{
		"f00d":             {Status: androidkey.StatusRevoked, Reason: "KEY_COMPROMISE"},
		"beef":             {Status: androidkey.StatusSuspended, Reason: "SOFTWARE_FLAW", Comment: "Suspended until the fix ships"},
		"2c8cdddfd5e03bfc": {Status: androidkey.StatusRevoked, Reason: "KEY_COMPROMISE", Comment: "Key stored on unsecure system", Expires: "2020-11-13"},
	} {
		n, _ := new(big.Int).SetString(serial, 16)
		if got, ok := l.Lookup(n); !ok || got != want {
			t.Errorf("%s: %+v, %v; want %+v", serial, got, ok, want)
		}
	}
	if _, ok := l.Lookup(big.NewInt(1)); ok {
		t.Error("serial 1 is listed")
	}
	if _, ok := l.Lookup(nil); ok {
		t.Error("a nil serial is listed")
	}
	// Keys are canonicalised: upper case and leading zeros name the same
	// serial.
	l, err := androidkey.ParseStatusList([]byte(`{"entries":{"00F00D":{"status":"REVOKED"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := l.Lookup(big.NewInt(0xf00d)); !ok {
		t.Error("00F00D isn't f00d")
	}
	if l, err := androidkey.ParseStatusList([]byte(`{"entries":{}}`)); err != nil || l.Len() != 0 {
		t.Errorf("empty list: %v, %v", l, err)
	}

	for name, doc := range map[string]string{
		"not JSON":         `{`,
		"no entries":       `{}`,
		"entries null":     `{"entries":null}`,
		"entries an array": `{"entries":[]}`,
		"key not hex":      `{"entries":{"xyz":{"status":"REVOKED"}}}`,
		"negative key":     `{"entries":{"-1":{"status":"REVOKED"}}}`,
		"no status":        `{"entries":{"01":{"reason":"KEY_COMPROMISE"}}}`,
		"duplicate key":    `{"entries":{"01":{"status":"REVOKED"},"01":{"status":"REVOKED"}}}`,
		"status a number":  `{"entries":{"01":{"status":1}}}`,
	} {
		if _, err := androidkey.ParseStatusList([]byte(doc)); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
}
