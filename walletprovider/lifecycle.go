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
// it nothing, and its status becomes SUSPENDED, until Resume. reason is
// recorded. It refuses a revoked instance with ErrInstanceRevoked.
func (p *Provider) Suspend(ctx context.Context, id, reason string) error {
	return p.transition(ctx, id, StateSuspended, reason)
}

// Resume makes a suspended instance active again, its status VALID. It
// refuses a revoked instance with ErrInstanceRevoked; resuming an
// active one only sets its status again.
func (p *Provider) Resume(ctx context.Context, id string) error {
	return p.transition(ctx, id, StateActive, "")
}

// Revoke revokes an instance for good: the provider issues it nothing,
// and its status becomes INVALID, so issuers refuse every attestation
// it was issued at their next status check. reason is recorded.
// Revoking a revoked instance only sets its status again.
func (p *Provider) Revoke(ctx context.Context, id, reason string) error {
	return p.transition(ctx, id, StateRevoked, reason)
}

// transition moves the instance to state, then sets its status to
// match. The state is stored first: should setting the status fail,
// the provider already refuses the instance, and repeating the call
// sets the status again.
func (p *Provider) transition(ctx context.Context, id string, state State, reason string) error {
	var ref statuslist.StatusListRef
	if err := p.update(ctx, id, func(in *Instance) error {
		if in.State == StateRevoked && state != StateRevoked {
			return ErrInstanceRevoked
		}
		if in.State == StateRevoked {
			// Keep the reason it was first revoked for.
			reason = in.Reason
		}
		in.State, in.Reason, ref = state, reason, in.Status
		return nil
	}); err != nil {
		return err
	}
	status := map[State]statuslist.StatusType{
		StateActive: statuslist.StatusValid, StateSuspended: statuslist.StatusSuspended, StateRevoked: statuslist.StatusInvalid,
	}[state]
	if err := p.allocator.SetStatus(ctx, ref, status); err != nil {
		return fmt.Errorf("walletprovider: setting the instance's status to %v: %w", status, err)
	}
	p.publisher.Invalidate()
	return nil
}

// listPageSize is how many instances RevokeWhere reads at a time.
const listPageSize = 100

// RevokeWhere revokes every instance not yet revoked that match
// selects — every instance of an app version, say, or every one whose
// device didn't boot verified — with reason, and returns how many it
// revoked. It walks the whole store (InstanceStore.List), so match sees
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
