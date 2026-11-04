package androidkey

import (
	"context"
	"errors"
	"fmt"
	"math/big"

	"github.com/idfoundry/oid4vcgo/internal/strictjson"
)

// maxStatusEntries bounds how many entries a list may hold.
const maxStatusEntries = 1 << 20

// Status values a StatusEntry can have. Verify refuses a certificate
// with any entry, whatever its status.
const (
	StatusRevoked   = "REVOKED"
	StatusSuspended = "SUSPENDED"
)

// StatusEntry is one certificate's entry in Google's attestation status
// list. Reason is KEY_COMPROMISE, CA_COMPROMISE, SUPERSEDED,
// SOFTWARE_FLAW or UNSPECIFIED.
type StatusEntry struct {
	Status  string `json:"status"`
	Reason  string `json:"reason,omitempty"`
	Comment string `json:"comment,omitempty"`
	Expires string `json:"expires,omitempty"`
}

// StatusList is a parsed attestation status list: the certificates
// Google has revoked or suspended, by serial number.
//
// A *StatusList is itself a StatusProvider that always returns itself:
// for a list the caller fetches and refreshes on its own, which is then
// responsible for keeping it current.
type StatusList struct {
	entries map[string]StatusEntry
}

// ParseStatusList parses the JSON Google serves at DefaultStatusURL:
//
//	{"entries": {"<serial, lowercase hex>": {"status": "REVOKED", "reason": "KEY_COMPROMISE"}, ...}}
//
// A document with no "entries" object, a key that isn't hexadecimal,
// or an entry without a status is refused, as is a member name given
// twice.
func ParseStatusList(data []byte) (*StatusList, error) {
	var doc struct {
		Entries *map[string]StatusEntry `json:"entries"`
	}
	if err := strictjson.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("androidkey: status list: %w", err)
	}
	if doc.Entries == nil {
		return nil, errors.New("androidkey: status list: no entries object")
	}
	if len(*doc.Entries) > maxStatusEntries {
		return nil, fmt.Errorf("androidkey: status list: more than %d entries", maxStatusEntries)
	}
	l := &StatusList{entries: make(map[string]StatusEntry, len(*doc.Entries))}
	for k, e := range *doc.Entries {
		serial, ok := new(big.Int).SetString(k, 16)
		if !ok || serial.Sign() < 0 {
			return nil, fmt.Errorf("androidkey: status list: key %q isn't a hexadecimal serial number", k)
		}
		if e.Status == "" {
			return nil, fmt.Errorf("androidkey: status list: entry %s has no status", k)
		}
		// Keyed canonically, so "0A" and "a" name one certificate.
		l.entries[serialKey(serial)] = e
	}
	return l, nil
}

// Len is how many certificates the list names.
func (l *StatusList) Len() int { return len(l.entries) }

// Lookup returns the entry for the certificate with serial number
// serial, if the list has one.
func (l *StatusList) Lookup(serial *big.Int) (StatusEntry, bool) {
	if serial == nil {
		return StatusEntry{}, false
	}
	e, ok := l.entries[serialKey(serial)]
	return e, ok
}

// Current returns l.
func (l *StatusList) Current(context.Context) (*StatusList, error) { return l, nil }

// StatusProvider gives Verify the attestation status list to check a
// chain against. Current returns a list that is current by the
// provider's own standard, or an error when it has none.
type StatusProvider interface {
	Current(ctx context.Context) (*StatusList, error)
}

// serialKey is how the status list keys a serial number: lowercase
// hexadecimal without leading zeros.
func serialKey(serial *big.Int) string { return serial.Text(16) }
