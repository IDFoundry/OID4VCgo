package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/idfoundry/oid4vcgo/statuslist"
)

// StatusListTokenStore is a statuslist.TokenStore: the Status List
// Tokens the replicas serving a list share (statuslist.Publisher.Tokens,
// and identifierlist.Publisher.Tokens), one row per list and form. A
// list's version is raised, in the same transaction, by every change
// of one of its statuses through this database's StatusIndices — by a
// trigger, so whatever changes a status raises it. A list whose
// statuses aren't kept there, an identifier list say, stays at version
// zero, and its token is signed anew by time alone (see
// statuslist.TokenStore). StatusIndexStore.Delete deletes a list's
// tokens and version with its indices.
//
// Claim is one INSERT … ON CONFLICT DO UPDATE … WHERE the lease is free,
// ended or the holder's own, so of two replicas claiming one lease one
// gets it, across every process sharing the database. A lease's end is
// the claiming replica's clock: replicas' clocks are assumed to agree
// to well within a lease, which lasts 35 seconds. Tokens aren't secret — a Publisher
// serves them to anyone — so the rows aren't sealed.
type StatusListTokenStore struct{ d *DB }

var _ statuslist.TokenStore = (*StatusListTokenStore)(nil)

// StatusListTokens returns d's statuslist.TokenStore.
func (d *DB) StatusListTokens() *StatusListTokenStore { return &StatusListTokenStore{d} }

// Head implements statuslist.TokenStore.
func (s *StatusListTokenStore) Head(ctx context.Context, uri string, form statuslist.Form) (statuslist.TokenHead, error) {
	if !storableKeys(uri) {
		return statuslist.TokenHead{}, errUnstorableKey
	}
	var head statuslist.TokenHead
	var version, signedAt, exp sql.NullInt64
	err := s.d.db.QueryRowContext(ctx, s.d.sql.statusTokenHead, uri, uri, int64(form)).Scan(&head.Version, &version, &signedAt, &exp)
	if err != nil {
		return statuslist.TokenHead{}, fmt.Errorf("sqlstore: read the %v token of %s: %w", form, uri, err)
	}
	if version.Valid {
		head.Stored = true
		head.Token = statuslist.StoredToken{Version: version.Int64, SignedAt: time.UnixMilli(signedAt.Int64), Exp: time.UnixMilli(exp.Int64)}
	}
	return head, nil
}

// Token implements statuslist.TokenStore.
func (s *StatusListTokenStore) Token(ctx context.Context, uri string, form statuslist.Form) (statuslist.StoredToken, bool, error) {
	if !storableKeys(uri) {
		return statuslist.StoredToken{}, false, errUnstorableKey
	}
	var token statuslist.StoredToken
	var signedAt, exp int64
	switch err := s.d.db.QueryRowContext(ctx, s.d.sql.statusTokenGet, uri, int64(form)).Scan(&token.Bytes, &token.Version, &signedAt, &exp); {
	case errors.Is(err, sql.ErrNoRows):
		return statuslist.StoredToken{}, false, nil
	case err != nil:
		return statuslist.StoredToken{}, false, fmt.Errorf("sqlstore: read the %v token of %s: %w", form, uri, err)
	}
	token.SignedAt, token.Exp = time.UnixMilli(signedAt), time.UnixMilli(exp)
	return token, true, nil
}

// Claim implements statuslist.TokenStore: one INSERT … ON CONFLICT DO
// UPDATE, which changes nothing while another holder's lease runs.
func (s *StatusListTokenStore) Claim(ctx context.Context, uri string, form statuslist.Form, holder string, now, until time.Time) (bool, error) {
	if !storableKeys(uri, holder) {
		return false, errUnstorableKey
	}
	var n int64
	err := s.d.writeOne(ctx, func(q querier) error {
		res, err := q.ExecContext(ctx, s.d.sql.statusTokenClaim, uri, int64(form), holder, until.UnixMilli(), now.UnixMilli())
		if err != nil {
			return err
		}
		n, err = res.RowsAffected()
		return err
	})
	if err != nil {
		return false, fmt.Errorf("sqlstore: claim the %v token lease of %s: %w", form, uri, err)
	}
	return n > 0, nil
}

// Put implements statuslist.TokenStore: the token's INSERT … ON
// CONFLICT DO UPDATE, which leaves a newer token as it is, and the
// lease's release, in one transaction.
func (s *StatusListTokenStore) Put(ctx context.Context, uri string, form statuslist.Form, holder string, token statuslist.StoredToken) error {
	if !storableKeys(uri, holder) {
		return errUnstorableKey
	}
	if len(token.Bytes) == 0 {
		return fmt.Errorf("sqlstore: the %v token of %s is empty", form, uri)
	}
	err := s.d.write(ctx, func(q querier) error {
		if _, err := q.ExecContext(ctx, s.d.sql.statusTokenPut, uri, int64(form), token.Bytes, token.Version, token.SignedAt.UnixMilli(), token.Exp.UnixMilli()); err != nil {
			return err
		}
		_, err := q.ExecContext(ctx, s.d.sql.statusTokenRelease, uri, int64(form), holder)
		return err
	})
	if err != nil {
		return fmt.Errorf("sqlstore: store the %v token of %s: %w", form, uri, err)
	}
	return nil
}
