package storage_test

import (
	"context"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/issuer"
	"github.com/idfoundry/oid4vcgo/storage"
)

func testCredentialOfferRecord() issuer.CredentialOfferRecord {
	return issuer.CredentialOfferRecord{
		Reference: "ref-1",
		Offer: oid4vci.CredentialOffer{
			CredentialIssuer:           "https://issuer.example.com",
			CredentialConfigurationIDs: []string{"IdentityCredential"},
			Grants: &oid4vci.Grants{
				PreAuthorizedCode: &oid4vci.GrantPreAuthorizedCode{
					PreAuthorizedCode: "abc123",
					TxCode:            &oid4vci.TxCode{Length: 4},
				},
			},
		},
		ExpiresAt: time.Now().Add(time.Hour),
	}
}

func TestCredentialOfferStore_StoreThenGet(t *testing.T) {
	s := storage.NewCredentialOfferStore()
	ctx := context.Background()
	record := testCredentialOfferRecord()

	if err := s.Store(ctx, record); err != nil {
		t.Fatalf("Store: %v", err)
	}
	got, err := s.Get(ctx, "ref-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Offer.CredentialIssuer != record.Offer.CredentialIssuer {
		t.Errorf("CredentialIssuer = %q, want %q", got.Offer.CredentialIssuer, record.Offer.CredentialIssuer)
	}
	if got.Offer.Grants == nil || got.Offer.Grants.PreAuthorizedCode == nil || got.Offer.Grants.PreAuthorizedCode.PreAuthorizedCode != "abc123" {
		t.Errorf("Grants = %+v", got.Offer.Grants)
	}
}

func TestCredentialOfferStore_GetIsRepeatable(t *testing.T) {
	s := storage.NewCredentialOfferStore()
	ctx := context.Background()
	if err := s.Store(ctx, testCredentialOfferRecord()); err != nil {
		t.Fatalf("Store: %v", err)
	}
	if _, err := s.Get(ctx, "ref-1"); err != nil {
		t.Fatalf("Get (first): %v", err)
	}
	if _, err := s.Get(ctx, "ref-1"); err != nil {
		t.Fatalf("Get (second): %v", err)
	}
}

func TestCredentialOfferStore_GetRejectsUnknownReference(t *testing.T) {
	s := storage.NewCredentialOfferStore()
	if _, err := s.Get(context.Background(), "no-such-reference"); err == nil {
		t.Fatalf("Get = nil error, want error")
	}
}
