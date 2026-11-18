package walletprovider

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

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
// instance with ErrInstanceRevoked. Suspending a suspended instance
// sets the statuses again, finishing a suspension whose status writes
// failed.
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
// recorded. Revoking a revoked instance only sets the statuses again,
// finishing a revocation whose status writes failed.
func (p *Provider) Revoke(ctx context.Context, id, reason string) error {
	return p.transition(ctx, id, StateRevoked, reason)
}

// transition moves the instance to state, then sets the status of each
// of its instance keys to match (settle): at its Status and
// PreviousStatus, on the lists still served (no live attestation names
// another). The state is stored first: should setting a status fail,
// the provider already refuses the instance, its KeyStatusesFor isn't
// its State, and repeating the call, RevokeWhere for a revocation, or
// the instance's next request sets the statuses again. A key recorded
// or moved while the statuses are set is one whose request saw the
// instance still active after its record changed (WalletAttestation,
// KeyAttestation), so it's listed here, or no attestation names its
// new index.
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
	return p.settle(ctx, id, state)
}

// errUnchanged makes update store nothing.
var errUnchanged = errors.New("walletprovider: unchanged")

// settle sets the status of each instance key of the instance id for
// state, then stores state as its KeyStatusesFor: only once every
// write succeeded, and only while state is still the instance's.
//
// A concurrent transition may store another state while the statuses
// are set: each then sets them for its own state, in whatever order
// their writes land. So once they're set, the instance is read again,
// and while its state isn't the one they were set for, they're set for
// the state it has — the last transition to store a state sets its
// statuses last, and a revoked instance's keys end INVALID. Should a
// write fail, the ones before it may have landed after the other
// transition stored its KeyStatusesFor, so that's cleared (unsettle),
// leaving its state pending.
func (p *Provider) settle(ctx context.Context, id string, state State) error {
	for range maxUpdateAttempts {
		if err := p.setKeyStatuses(ctx, id, keyStatus[state]); err != nil {
			p.unsettle(ctx, id, state)
			return err
		}
		stored := state
		err := p.update(ctx, id, func(in *Instance) error {
			stored = in.State
			if in.State != state || in.KeyStatusesFor == state {
				return errUnchanged
			}
			in.KeyStatusesFor = state
			return nil
		})
		if err != nil && !errors.Is(err, errUnchanged) {
			return fmt.Errorf("walletprovider: recording the instance's key statuses as set: %w", err)
		}
		if stored == state {
			return nil
		}
		state = stored
	}
	return fmt.Errorf("walletprovider: setting the instance's key statuses: %w after %d attempts", ErrConflict, maxUpdateAttempts)
}

// unsettle clears the KeyStatusesFor of the instance id when it's the
// instance's State and that isn't wrote, the state a failed settle was
// setting the statuses for, whose writes may have overwritten some of
// the statuses KeyStatusesFor says are set. It isn't cut short by
// ctx's cancellation; should it fail too, the store is failing, which
// settle reports.
func (p *Provider) unsettle(ctx context.Context, id string, wrote State) {
	_ = p.update(context.WithoutCancel(ctx), id, func(in *Instance) error {
		if in.State == wrote || in.KeyStatusesFor != in.State {
			return errUnchanged
		}
		in.KeyStatusesFor = ""
		return nil
	})
}

// completePending sets the key statuses of in, a suspended or revoked
// instance a request named, when they're pending (KeyStatusesFor isn't
// its State): a transition whose status writes failed part-way. It's
// called once for the request, which is then refused for the
// instance's state as before, and isn't cut short by the request's
// cancellation. A failure is logged at error level, with the
// instance's ID; the instance's next request tries again.
func (p *Provider) completePending(ctx context.Context, in Instance) {
	if in.State == StateActive || in.KeyStatusesFor == in.State {
		return
	}
	if err := p.settle(context.WithoutCancel(ctx), in.ID, in.State); err != nil {
		p.logger().LogAttrs(ctx, slog.LevelError, "walletprovider: setting the key statuses of a "+string(in.State)+" instance",
			slog.String("instance", in.ID), slog.Any("error", err))
	}
}

// keyStatus is the status of an instance's keys in each state.
var keyStatus = map[State]statuslist.StatusType{
	StateActive: statuslist.StatusValid, StateSuspended: statuslist.StatusSuspended, StateRevoked: statuslist.StatusInvalid,
}

// setKeyStatuses sets the status of each instance key of the instance
// id to status: at its Status and PreviousStatus, on the lists still
// served. It returns at the first write that fails.
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

// maxRevokeWhereFailures is how many instances RevokeWhere fails to
// revoke before it stops.
const maxRevokeWhereFailures = 100

// RevokeWhere revokes every instance that match selects — every
// instance of an app version, say, every one whose device didn't boot
// verified, or, from its EvidenceFacts, every one whose attestation
// chain has a certificate since revoked — with reason, and returns how
// many it revoked. An EvidenceRechecker's refusal already stops an
// instance getting new attestations, but — unless it found the
// evidence revoked or suspended by its issuer (ErrEvidenceRevoked,
// ErrEvidenceSuspended), which revokes or suspends the instance —
// leaves those it has VALID until they expire: revoking it makes them
// INVALID too. It walks the whole store (InstanceStore.List), so match
// sees each instance once, as it was when read.
//
// It passes by an instance already revoked whose keys' statuses are
// all set (KeyStatusesFor), and finishes the revocation of a revoked
// one whose aren't, keeping the reason it was revoked for, counting it
// too. So RevokeWhere(ctx, func(in Instance) bool { return in.State ==
// StateRevoked }, "") finishes every revocation pending.
//
// An instance it fails to revoke doesn't stop it: it goes on to the
// next, and returns a *RevokeWhereError naming each one that failed. It
// stops when ctx ends, when listing the instances fails, or after 100
// failures, as when the store fails for every one. What it didn't
// revoke is left for the next run: run it again to finish.
func (p *Provider) RevokeWhere(ctx context.Context, match func(Instance) bool, reason string) (int, error) {
	if match == nil {
		return 0, errors.New("walletprovider: RevokeWhere needs a match function")
	}
	revoked := 0
	var failed []InstanceError
	result := func(stop error) (int, error) {
		if len(failed) == 0 && stop == nil {
			return revoked, nil
		}
		return revoked, &RevokeWhereError{Failed: failed, Err: stop}
	}
	after := ""
	for {
		page, err := p.deps.Instances.List(ctx, after, listPageSize)
		if err != nil {
			return result(fmt.Errorf("walletprovider: listing instances: %w", err))
		}
		for _, in := range page {
			if in.State == StateRevoked && in.KeyStatusesFor == StateRevoked || !match(in) {
				continue
			}
			if err := p.Revoke(ctx, in.ID, reason); err != nil {
				failed = append(failed, InstanceError{ID: in.ID, Err: err})
				switch {
				case ctx.Err() != nil:
					return result(ctx.Err())
				case len(failed) >= maxRevokeWhereFailures:
					return result(fmt.Errorf("walletprovider: stopped after %d instances failed", len(failed)))
				}
				continue
			}
			revoked++
		}
		if len(page) < listPageSize {
			return result(nil)
		}
		after = page[len(page)-1].ID
	}
}

// InstanceError is the error acting on one instance failed with.
type InstanceError struct {
	// ID is the instance's.
	ID  string
	Err error
}

// RevokeWhereError is RevokeWhere's error when it failed to revoke an
// instance it selected, or stopped before it had walked every
// instance. errors.Is and errors.As see each of its errors.
type RevokeWhereError struct {
	// Failed are the instances it selected but failed to revoke, or to
	// finish revoking, in the order it reached them. Each may already
	// be revoked (State) with its keys' statuses not all set: run
	// RevokeWhere again, or Revoke it.
	Failed []InstanceError

	// Err, when not nil, is why it stopped before it had walked every
	// instance: ctx's error, listing them failing, or too many failures.
	Err error
}

func (e *RevokeWhereError) Error() string {
	var b strings.Builder
	b.WriteString("walletprovider: RevokeWhere")
	if len(e.Failed) > 0 {
		ids := make([]string, len(e.Failed))
		for i, f := range e.Failed {
			ids[i] = f.ID
		}
		fmt.Fprintf(&b, ": revoking %d instances failed (%s), the first with: %v", len(e.Failed), strings.Join(ids, ", "), e.Failed[0].Err)
	}
	if e.Err != nil {
		fmt.Fprintf(&b, ": stopped: %v", e.Err)
	}
	return b.String()
}

// Unwrap returns each failed instance's error, then Err.
func (e *RevokeWhereError) Unwrap() []error {
	errs := make([]error, 0, len(e.Failed)+1)
	for _, f := range e.Failed {
		errs = append(errs, f.Err)
	}
	if e.Err != nil {
		errs = append(errs, e.Err)
	}
	return errs
}
