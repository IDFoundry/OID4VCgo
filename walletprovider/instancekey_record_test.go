package walletprovider_test

import (
	"context"
	"errors"
	"testing"

	"github.com/idfoundry/oid4vcgo/walletprovider"
	"github.com/idfoundry/oid4vcgo/walletprovider/walletprovidertest"
)

// hookedInstanceKeys is an InstanceKeyStore whose Get fails with
// getErr while it's set, and whose Create runs beforeCreate first, then
// fails with createErr if that's set.
type hookedInstanceKeys struct {
	walletprovider.InstanceKeyStore
	getErr       error
	createErr    error
	beforeCreate func(walletprovider.InstanceKey)
}

func (s *hookedInstanceKeys) Get(ctx context.Context, thumbprint string) (walletprovider.InstanceKey, error) {
	if s.getErr != nil {
		return walletprovider.InstanceKey{}, s.getErr
	}
	return s.InstanceKeyStore.Get(ctx, thumbprint)
}

func (s *hookedInstanceKeys) Create(ctx context.Context, k walletprovider.InstanceKey) error {
	if s.beforeCreate != nil {
		s.beforeCreate(k)
	}
	if s.createErr != nil {
		return s.createErr
	}
	return s.InstanceKeyStore.Create(ctx, k)
}

// TestInstanceKeyRecordStoreRaces: recording a new instance key copes
// with the store failing, and with a concurrent request recording the
// key first: for the same instance it gets that record, for another
// it's refused.
func TestInstanceKeyRecordStoreRaces(t *testing.T) {
	errDown := errors.New("store down")
	// recordFirst has a concurrent request record the key, for the
	// instance owner, before Create.
	recordFirst := func(t *testing.T, s *hookedInstanceKeys, owner string, then func()) {
		s.beforeCreate = func(k walletprovider.InstanceKey) {
			k.InstanceID = owner
			if err := s.InstanceKeyStore.Create(context.Background(), k); err != nil {
				t.Error(err)
			}
			if then != nil {
				then()
			}
		}
	}
	cases := map[string]struct {
		hook func(t *testing.T, s *hookedInstanceKeys, own, other string)
		want error
	}{
		"reading fails": {func(_ *testing.T, s *hookedInstanceKeys, _, _ string) { s.getErr = errDown }, errDown},
		"storing fails": {func(_ *testing.T, s *hookedInstanceKeys, _, _ string) { s.createErr = errDown }, errDown},
		"recorded meanwhile for the instance": {func(t *testing.T, s *hookedInstanceKeys, own, _ string) {
			recordFirst(t, s, own, nil)
		}, nil},
		"recorded meanwhile for another instance": {func(t *testing.T, s *hookedInstanceKeys, _, other string) {
			recordFirst(t, s, other, nil)
		}, walletprovider.ErrInstanceKeyRegistered},
		"reading the concurrent record fails": {func(t *testing.T, s *hookedInstanceKeys, own, _ string) {
			recordFirst(t, s, own, func() { s.getErr = errDown })
		}, errDown},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			var store *hookedInstanceKeys
			h := newHarness(t, func(_ *walletprovider.Config, d *walletprovider.Dependencies) {
				store = &hookedInstanceKeys{InstanceKeyStore: d.InstanceKeys}
				d.InstanceKeys = store
			})
			in, _ := h.register(kindTEE)
			other, _ := h.register(kindTEE)
			tc.hook(t, store, in.ID, other.ID)
			key := newKey(t)
			_, err := h.walletAttestation(in.ID, &key.PublicKey, kindTEE)
			if tc.want == nil && err != nil || tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("WalletAttestation = %v, want %v", err, tc.want)
			}
		})
	}
}

// TestInstanceKeyEvidenceMustVouchForKey: evidence for an instance key
// that passes but doesn't vouch for the key records nothing.
func TestInstanceKeyEvidenceMustVouchForKey(t *testing.T) {
	h := newHarness(t, func(_ *walletprovider.Config, d *walletprovider.Dependencies) {
		d.Evidence = append(d.Evidence, misbehavingVerifier{kind: "keyless", report: func(in walletprovider.EvidenceInput) walletprovider.VerifiedEvidence {
			ev := walletprovider.VerifiedEvidence{Platform: walletprovidertest.FakePlatform}
			if in.Purpose == walletprovider.PurposeRegistration {
				ev.Keys = []walletprovider.AttestedKey{{Key: in.Keys[0], SecurityLevel: walletprovider.SecurityLevelSoftware, Binding: walletprovider.KeyBindingAttested}}
			}
			return ev
		}})
	})
	in, _ := h.register("keyless")
	key := newKey(t)
	if _, err := h.walletAttestation(in.ID, &key.PublicKey, "keyless"); !errors.Is(err, walletprovider.ErrEvidenceRejected) {
		t.Fatalf("WalletAttestation with evidence vouching for no key = %v, want ErrEvidenceRejected", err)
	}
	if _, err := h.deps.InstanceKeys.Get(context.Background(), h.thumbprint(&key.PublicKey)); !errors.Is(err, walletprovider.ErrNotFound) {
		t.Fatalf("the refused instance key's record: %v, want ErrNotFound", err)
	}
}
