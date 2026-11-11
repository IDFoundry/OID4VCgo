package walletprovider

import (
	"context"
	"errors"
	"fmt"

	"github.com/idfoundry/oid4vcgo/statuslist"
)

// stateError is nil for an active instance, and the error a request
// for one in state s fails with otherwise.
func stateError(s State) error {
	switch s {
	case StateActive:
		return nil
	case StateRevoked:
		return fmt.Errorf("%w: %w", ErrInstanceNotActive, ErrInstanceRevoked)
	default:
		return fmt.Errorf("%w: %s", ErrInstanceNotActive, s)
	}
}

// Suspend suspends an active or suspended instance: the provider issues
// it nothing, and the status of each of its instance keys becomes
// SUSPENDED, until Resume. reason is recorded. It refuses a revoked
// instance with ErrInstanceRevoked.
func (p *Provider) Suspend(ctx context.Context, id, reason string) error {
	return p.transition(ctx, id, StateSuspended, reason)
}

// Resume makes a suspended instance active again, the status of each of
// its instance keys VALID. It refuses a revoked instance with
// ErrInstanceRevoked; resuming an active one only sets the statuses
// again.
func (p *Provider) Resume(ctx context.Context, id string) error {
	return p.transition(ctx, id, StateActive, "")
}

// Revoke revokes an instance — the installation — for good: the
// provider issues it nothing, and the status of each of its instance
// keys becomes INVALID, so issuers refuse every attestation it was
// issued, for every issuance, at their next status check. reason is
// recorded. Revoking a revoked instance only sets the statuses again.
func (p *Provider) Revoke(ctx context.Context, id, reason string) error {
	return p.transition(ctx, id, StateRevoked, reason)
}

// transition moves the instance to state, then sets the status of each
// of its instance keys to match: at its Status and PreviousStatus, on
// the lists still served (no live attestation names another). The
// state is stored first: should setting a status fail, the provider
// already refuses the instance, and repeating the call sets the
// statuses again. A key recorded or moved while the statuses are set
// is one whose request saw the instance still active after its record
// changed (WalletAttestation, KeyAttestation), so it's listed here, or
// no attestation names its new index.
//
// A concurrent transition may store another state while the statuses
// are set: each then sets them for its own state, in whatever order
// their writes land. So once they're set, the instance is read again,
// and while its state isn't the one they were set for, they're set for
// the state it has — the last transition to store a state sets its
// statuses last, and a revoked instance's keys end INVALID.
func (p *Provider) transition(ctx context.Context, id string, state State, reason string) error {
	if err := p.update(ctx, id, func(in *Instance) error {
		if in.State == StateRevoked && state != StateRevoked {
			return ErrInstanceRevoked
		}
		if in.State == StateRevoked {
			// Keep the reason it was first revoked for.
			reason = in.Reason
		}
		in.State, in.Reason = state, reason
		return nil
	}); err != nil {
		return err
	}
	for range maxUpdateAttempts {
		if err := p.setKeyStatuses(ctx, id, keyStatus[state]); err != nil {
			return err
		}
		in, err := p.getInstance(ctx, id)
		if err != nil {
			return err
		}
		if in.State == state {
			return nil
		}
		state = in.State
	}
	return fmt.Errorf("walletprovider: setting the instance's key statuses: %w after %d attempts", ErrConflict, maxUpdateAttempts)
}

// keyStatus is the status of an instance's keys in each state.
var keyStatus = map[State]statuslist.StatusType{
	StateActive: statuslist.StatusValid, StateSuspended: statuslist.StatusSuspended, StateRevoked: statuslist.StatusInvalid,
}

// setKeyStatuses sets the status of each instance key of the instance
// id to status: at its Status and PreviousStatus, on the lists still
// served.
func (p *Provider) setKeyStatuses(ctx context.Context, id string, status statuslist.StatusType) error {
	now := p.now()
	after := ""
	for {
		page, err := p.deps.InstanceKeys.List(ctx, id, after, listPageSize)
		if err != nil {
			return fmt.Errorf("walletprovider: listing the instance's keys: %w", err)
		}
		for _, k := range page {
			for _, ref := range []statuslist.StatusListRef{k.Status, k.PreviousStatus} {
				if err := p.setStatus(ctx, ref, status, now); err != nil {
					return err
				}
			}
		}
		if len(page) < listPageSize {
			return nil
		}
		after = page[len(page)-1].Thumbprint
	}
}

// listPageSize is how many instances RevokeWhere, or instance keys
// transition, reads at a time.
const listPageSize = 100

// RevokeWhere revokes every instance not yet revoked that match
// selects — every instance of an app version, say, every one whose
// device didn't boot verified, or, from its EvidenceFacts, every one
// whose attestation chain has a certificate since revoked — with
// reason, and returns how many it revoked. An EvidenceRechecker's
// refusal already stops an instance getting new attestations, but
// leaves those it has VALID until they expire: revoking it makes them
// INVALID too. It walks the whole store (InstanceStore.List), so match sees
// each instance once, as it was when read. It stops at the first error,
// having revoked those before it; run it again to finish.
func (p *Provider) RevokeWhere(ctx context.Context, match func(Instance) bool, reason string) (int, error) {
	if match == nil {
		return 0, errors.New("walletprovider: RevokeWhere needs a match function")
	}
	revoked := 0
	after := ""
	for {
		page, err := p.deps.Instances.List(ctx, after, listPageSize)
		if err != nil {
			return revoked, fmt.Errorf("walletprovider: listing instances: %w", err)
		}
		for _, in := range page {
			if in.State == StateRevoked || !match(in) {
				continue
			}
			if err := p.Revoke(ctx, in.ID, reason); err != nil {
				return revoked, err
			}
			revoked++
		}
		if len(page) < listPageSize {
			return revoked, nil
		}
		after = page[len(page)-1].ID
	}
}
