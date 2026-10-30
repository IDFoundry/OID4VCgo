package sqlstore

import (
	"encoding/json"
	"errors"
	"fmt"
)

// Sealer seals and opens the records a DB writes: an AEAD, such as
// verifier.AESGCMSealer, or a call to a key management service. Open
// must refuse sealed data altered in any way, or sealed with other
// additionalData: that's what binds each record to its table and key.
// verifier.TransactionSealer is the same interface, so one sealer can
// serve both a DB and the verifier's TransactionCodec.
type Sealer interface {
	Seal(plaintext, additionalData []byte) ([]byte, error)
	Open(sealed, additionalData []byte) ([]byte, error)
}

// A stored record starts with one of these, saying how the rest is
// encoded.
const (
	recordJSON   byte = 1 // JSON
	recordSealed byte = 2 // JSON, sealed with the DB's Sealer
)

// ErrRecordFormat is what a store returns, wrapped, for a record it
// can't read: written by a DB with a Sealer and read by one without,
// or the reverse; sealed under another key; or altered.
var ErrRecordFormat = errors.New("sqlstore: unreadable record")

// recordAD binds a sealed record to its table and key.
func recordAD(table, key string) []byte {
	return []byte("oid4vcgo sqlstore record v1\x00" + table + "\x00" + key)
}

// encodeRecord encodes v, as JSON, as table's record keyed by
// key.
func (d *DB) encodeRecord(table, key string, v any) ([]byte, error) {
	plain, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("sqlstore: encode %s record: %w", table, err)
	}
	if d.sealer == nil {
		return append([]byte{recordJSON}, plain...), nil
	}
	sealed, err := d.sealer.Seal(plain, recordAD(table, key))
	if err != nil {
		return nil, fmt.Errorf("sqlstore: seal %s record: %w", table, err)
	}
	return append([]byte{recordSealed}, sealed...), nil
}

// decodeRecord decodes table's record keyed by key into v.
func (d *DB) decodeRecord(table, key string, data []byte, v any) error {
	if len(data) == 0 {
		return fmt.Errorf("%w: empty %s record", ErrRecordFormat, table)
	}
	body := data[1:]
	switch {
	case data[0] == recordJSON && d.sealer == nil:
	case data[0] == recordSealed && d.sealer != nil:
		opened, err := d.sealer.Open(body, recordAD(table, key))
		if err != nil {
			return fmt.Errorf("%w: open %s record: %v", ErrRecordFormat, table, err)
		}
		body = opened
	case data[0] == recordJSON || data[0] == recordSealed:
		return fmt.Errorf("%w: the %s record is sealed: %t, and the DB has a Sealer: %t", ErrRecordFormat, table, data[0] == recordSealed, d.sealer != nil)
	default:
		return fmt.Errorf("%w: %s record format %d", ErrRecordFormat, table, data[0])
	}
	if err := json.Unmarshal(body, v); err != nil {
		return fmt.Errorf("%w: decode %s record: %v", ErrRecordFormat, table, err)
	}
	return nil
}
