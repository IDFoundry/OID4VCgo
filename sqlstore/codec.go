package sqlstore

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
)

// Sealer seals and opens the records a DB writes: an AEAD, such as
// sealing.AESGCMSealer, or a call to a key management service. Open
// must refuse sealed data altered in any way, or sealed with other
// additionalData: that's what binds each record to its table and key,
// and to the DB's Options.SealContext.
// sealing.Sealer (verifier.TransactionSealer) is the same interface, so
// one sealer can serve both a DB and the verifier's TransactionCodec.
type Sealer interface {
	Seal(plaintext, additionalData []byte) ([]byte, error)
	Open(sealed, additionalData []byte) ([]byte, error)
}

// A stored record starts with one of these, saying how the rest is
// encoded.
const (
	recordJSON   byte = 1 // JSON
	recordSealed byte = 2 // JSON, sealed with the DB's Sealer
	// recordSealedInContext is JSON sealed with the DB's Sealer by a DB
	// with a SealContext, which its additional data binds too.
	recordSealedInContext byte = 3
)

// ErrRecordFormat is what a store returns, wrapped, for a record it
// can't read: written by a DB with a Sealer and read by one without,
// or the reverse; sealed in another SealContext, or without one by a
// DB with one (unless Options.ReadWithoutSealContext); sealed under
// another key; or altered.
var ErrRecordFormat = errors.New("sqlstore: unreadable record")

// recordAD binds a sealed record to its table and key, and, when
// sealContext isn't empty, to that: the record of a DB with that
// SealContext (recordSealedInContext), each part length-prefixed. The
// v1 form, of a record sealed without one (recordSealed), needs no
// prefixes: a table's name and a key hold no NUL byte.
func recordAD(sealContext, table, key string) []byte {
	if sealContext == "" {
		return []byte("oid4vcgo sqlstore record v1\x00" + table + "\x00" + key)
	}
	ad := []byte("oid4vcgo sqlstore record v2")
	for _, part := range []string{sealContext, table, key} {
		ad = binary.BigEndian.AppendUint32(ad, uint32(len(part))) //nolint:gosec // G115: a SealContext, table name or key is far shorter than 4 GiB
		ad = append(ad, part...)
	}
	return ad
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
	format := recordSealed
	if d.sealContext != "" {
		format = recordSealedInContext
	}
	sealed, err := d.sealer.Seal(plain, recordAD(d.sealContext, table, key))
	if err != nil {
		return nil, fmt.Errorf("sqlstore: seal %s record: %w", table, err)
	}
	return append([]byte{format}, sealed...), nil
}

// decodeRecord decodes table's record keyed by key into v.
func (d *DB) decodeRecord(table, key string, data []byte, v any) error {
	if len(data) == 0 {
		return fmt.Errorf("%w: empty %s record", ErrRecordFormat, table)
	}
	body := data[1:]
	if data[0] != recordJSON {
		opened, err := d.openRecord(table, key, data)
		if err != nil {
			return err
		}
		body = opened
	} else if d.sealer != nil {
		return fmt.Errorf("%w: the %s record isn't sealed, and the DB has a Sealer", ErrRecordFormat, table)
	}
	if err := json.Unmarshal(body, v); err != nil {
		return fmt.Errorf("%w: decode %s record: %v", ErrRecordFormat, table, err)
	}
	return nil
}

// openRecord opens data, table's sealed record keyed by key, as d
// reads it: a record sealed in a SealContext only in d's own, and one
// sealed without, only by a DB without one, or with
// ReadWithoutSealContext.
func (d *DB) openRecord(table, key string, data []byte) ([]byte, error) {
	var sealContext string
	switch format := data[0]; {
	case format != recordSealed && format != recordSealedInContext:
		return nil, fmt.Errorf("%w: %s record format %d", ErrRecordFormat, table, format)
	case d.sealer == nil:
		return nil, fmt.Errorf("%w: the %s record is sealed, and the DB has no Sealer", ErrRecordFormat, table)
	case format == recordSealedInContext && d.sealContext == "":
		return nil, fmt.Errorf("%w: the %s record is sealed in a SealContext, and the DB has none", ErrRecordFormat, table)
	case format == recordSealed && d.sealContext != "" && !d.readWithoutSealContext:
		return nil, fmt.Errorf("%w: the %s record is sealed without a SealContext, and the DB has one (see Options.ReadWithoutSealContext and BindRecords)", ErrRecordFormat, table)
	case format == recordSealedInContext:
		sealContext = d.sealContext
	}
	opened, err := d.sealer.Open(data[1:], recordAD(sealContext, table, key))
	if err != nil {
		return nil, fmt.Errorf("%w: open %s record: %v", ErrRecordFormat, table, err)
	}
	return opened, nil
}
