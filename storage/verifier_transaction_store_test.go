package storage_test

import (
	"context"
	"errors"
	"testing"

	"github.com/idfoundry/oid4vcgo/storage"
	"github.com/idfoundry/oid4vcgo/verifier"
)

func TestVerifierTransactionStore(t *testing.T) {
	ctx := context.Background()
	s := storage.NewVerifierTransactionStore()
	if err := s.Create(ctx, verifier.Transaction{ID: "t1", KeyID: "k1", Status: verifier.TransactionPending}); err != nil {
		t.Fatal(err)
	}
	for name, tx := range map[string]verifier.Transaction{"reused ID": {ID: "t1", KeyID: "k2"}, "reused key ID": {ID: "t2", KeyID: "k1"}, "no ID": {}} {
		if err := s.Create(ctx, tx); err == nil {
			t.Errorf("Create with a %s: accepted", name)
		}
	}
	if id, err := s.IDByKeyID(ctx, "k1"); err != nil || id != "t1" {
		t.Errorf("IDByKeyID = %q, %v", id, err)
	}

	boom := errors.New("abort")
	if err := s.Update(ctx, "t1", func(tx *verifier.Transaction) error { tx.LastError = "unsaved"; return boom }); !errors.Is(err, boom) {
		t.Errorf("aborted Update: %v", err)
	}
	if tx, _ := s.Get(ctx, "t1"); tx.LastError != "" {
		t.Error("an aborted Update was saved")
	}

	setCode := func(code string) {
		if err := s.Update(ctx, "t1", func(tx *verifier.Transaction) error { tx.ResponseCodeHash = code; return nil }); err != nil {
			t.Fatal(err)
		}
	}
	setCode("c1")
	if id, err := s.IDByResponseCode(ctx, "c1"); err != nil || id != "t1" {
		t.Errorf("IDByResponseCode = %q, %v", id, err)
	}
	setCode("")
	if _, err := s.IDByResponseCode(ctx, "c1"); !errors.Is(err, verifier.ErrTransactionUnknown) {
		t.Error("a cleared response code still resolves")
	}
	for name, err := range map[string]error{
		"Get":              func() error { _, err := s.Get(ctx, "nope"); return err }(),
		"Update":           s.Update(ctx, "nope", func(*verifier.Transaction) error { return nil }),
		"IDByKeyID":        func() error { _, err := s.IDByKeyID(ctx, ""); return err }(),
		"IDByResponseCode": func() error { _, err := s.IDByResponseCode(ctx, ""); return err }(),
	} {
		if !errors.Is(err, verifier.ErrTransactionUnknown) {
			t.Errorf("%s of an unknown transaction: %v", name, err)
		}
	}
}
