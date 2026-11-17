package walletprovider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/internal/statefile"
	wp "github.com/idfoundry/oid4vcgo/walletprovider"
)

// instanceFileVersion is instanceFile's Version: 2 since instances
// have a registration key and per-issuance instance keys, each with
// its own status index. A file from before has instances whose key is
// a wallet's instance key, and is refused.
const instanceFileVersion = 2

// fileInstanceStore is a wp.InstanceStore kept in a JSON file,
// rewritten whole on every change, so the library instances the
// service registers, and their instance keys and those keys' status
// list indices (fileInstanceKeyStore, in the same file), outlive a
// restart. It also keeps the ID of the shared instance the service
// issues Key Attestations under. One process uses the file; a
// deployment uses a database.
type fileInstanceStore struct {
	mu    sync.Mutex
	path  string
	state instanceFile
	// swept is how many instance keys were left by the last sweep: the
	// next runs once there are twice as many, as
	// wp.MemoryInstanceKeyStore's does.
	swept int
}

// fileInstanceKeyStore is a wp.InstanceKeyStore kept in its
// fileInstanceStore's file.
type fileInstanceKeyStore struct {
	s *fileInstanceStore
}

// instanceFile is fileInstanceStore's file.
type instanceFile struct {
	Version        int                       `json:"version"`
	Instances      map[string]wp.Instance    `json:"instances"`
	InstanceKeys   map[string]wp.InstanceKey `json:"instance_keys"`
	HolderInstance string                    `json:"holder_instance,omitempty"`
}

var (
	_ wp.InstanceStore    = (*fileInstanceStore)(nil)
	_ wp.InstanceKeyStore = fileInstanceKeyStore{}
)

// openFileInstanceStore reads the store saved at path, empty when there
// is none, saving it back there on every change; with path "", it's
// kept in memory only.
func openFileInstanceStore(path string) (*fileInstanceStore, error) {
	s := &fileInstanceStore{path: path, state: instanceFile{
		Version: instanceFileVersion, Instances: map[string]wp.Instance{}, InstanceKeys: map[string]wp.InstanceKey{},
	}}
	if path == "" {
		return s, nil
	}
	data, err := os.ReadFile(path) // #nosec G304 -- operator-supplied state path
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return s, nil
	case err != nil:
		return nil, fmt.Errorf("walletprovider: read %s: %w", path, err)
	}
	s.state = instanceFile{}
	if err := json.Unmarshal(data, &s.state); err != nil {
		return nil, fmt.Errorf("walletprovider: %s: %w", path, err)
	}
	if s.state.Version != instanceFileVersion && (len(s.state.Instances) > 0 || len(s.state.InstanceKeys) > 0) {
		return nil, fmt.Errorf("walletprovider: %s is from before per-issuance instance keys: delete it and the status indices file beside it, and restart", path)
	}
	s.state.Version = instanceFileVersion
	if s.state.Instances == nil {
		s.state.Instances = map[string]wp.Instance{}
	}
	if s.state.InstanceKeys == nil {
		s.state.InstanceKeys = map[string]wp.InstanceKey{}
	}
	if err := s.state.checkLoaded(path); err != nil {
		return nil, err
	}
	return s, nil
}

// checkLoaded checks the instances and instance keys of a file read
// from path, refusing a damaged or duplicate one, and gives each
// instance key from before revisions its first.
func (f *instanceFile) checkLoaded(path string) error {
	keys := map[string]bool{}
	for id, in := range f.Instances {
		if in.ID != id || in.KeyThumbprint == "" || keys[in.KeyThumbprint] {
			return fmt.Errorf("walletprovider: %s: instance %q is damaged or a duplicate", path, id)
		}
		keys[in.KeyThumbprint] = true
	}
	for tp, k := range f.InstanceKeys {
		if k.Thumbprint != tp || keys[tp] {
			return fmt.Errorf("walletprovider: %s: instance key %q is damaged or a registration key", path, tp)
		}
		if _, ok := f.Instances[k.InstanceID]; !ok {
			return fmt.Errorf("walletprovider: %s: instance key %q is of an unknown instance", path, tp)
		}
		// A file from before instance keys could move has no Revision:
		// each was created, at 1.
		k.Revision = max(k.Revision, 1)
		f.InstanceKeys[tp] = k
	}
	return nil
}

// save writes the store to its file. Called with s.mu held.
func (s *fileInstanceStore) save() error {
	if s.path == "" {
		return nil
	}
	data, err := json.Marshal(s.state)
	if err != nil {
		return fmt.Errorf("walletprovider: encode instances: %w", err)
	}
	return statefile.WriteAtomic(s.path, data)
}

// Get implements wp.InstanceStore.
func (s *fileInstanceStore) Get(ctx context.Context, id string) (wp.Instance, error) {
	if err := ctx.Err(); err != nil {
		return wp.Instance{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	in, ok := s.state.Instances[id]
	if !ok {
		return wp.Instance{}, wp.ErrNotFound
	}
	return cloneInstance(in), nil
}

// Create implements wp.InstanceStore, saving the instance before it
// returns; should saving fail, it stores nothing.
func (s *fileInstanceStore) Create(ctx context.Context, in wp.Instance) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.state.Instances[in.ID]; ok {
		return wp.ErrExists
	}
	for _, stored := range s.state.Instances {
		// One registration key, and one App Attest key, is one instance.
		if stored.KeyThumbprint == in.KeyThumbprint || in.CredentialID != "" && stored.CredentialID == in.CredentialID {
			return wp.ErrExists
		}
	}
	in = cloneInstance(in)
	in.Revision = 1
	s.state.Instances[in.ID] = in
	if err := s.save(); err != nil {
		delete(s.state.Instances, in.ID)
		return err
	}
	return nil
}

// Update implements wp.InstanceStore, saving the change before it
// returns; should saving fail, it changes nothing.
func (s *fileInstanceStore) Update(ctx context.Context, in wp.Instance) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	stored, ok := s.state.Instances[in.ID]
	switch {
	case !ok:
		return wp.ErrNotFound
	case stored.Revision != in.Revision:
		return wp.ErrConflict
	}
	in = cloneInstance(in)
	in.Revision++
	s.state.Instances[in.ID] = in
	if err := s.save(); err != nil {
		s.state.Instances[in.ID] = stored
		return err
	}
	return nil
}

// List implements wp.InstanceStore.
func (s *fileInstanceStore) List(ctx context.Context, after string, limit int) ([]wp.Instance, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var ids []string
	for id := range s.state.Instances {
		if id > after {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	if len(ids) > limit {
		ids = ids[:max(limit, 0)]
	}
	out := make([]wp.Instance, len(ids))
	for i, id := range ids {
		out[i] = cloneInstance(s.state.Instances[id])
	}
	return out, nil
}

// keys is the store's wp.InstanceKeyStore.
func (s *fileInstanceStore) keys() fileInstanceKeyStore { return fileInstanceKeyStore{s} }

// Get implements wp.InstanceKeyStore.
func (k fileInstanceKeyStore) Get(ctx context.Context, thumbprint string) (wp.InstanceKey, error) {
	if err := ctx.Err(); err != nil {
		return wp.InstanceKey{}, err
	}
	k.s.mu.Lock()
	defer k.s.mu.Unlock()
	ik, ok := k.s.state.InstanceKeys[thumbprint]
	if !ok {
		return wp.InstanceKey{}, wp.ErrNotFound
	}
	return cloneInstanceKey(ik), nil
}

// Create implements wp.InstanceKeyStore, saving the key before it
// returns; should saving fail, it stores nothing. It drops the keys
// whose RetainUntil is before ik's CreatedAt, as
// wp.MemoryInstanceKeyStore does, saved with ik.
func (k fileInstanceKeyStore) Create(ctx context.Context, ik wp.InstanceKey) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	k.s.mu.Lock()
	defer k.s.mu.Unlock()
	if len(k.s.state.InstanceKeys) >= 2*k.s.swept+64 {
		for tp, stored := range k.s.state.InstanceKeys {
			if !stored.RetainUntil.IsZero() && stored.RetainUntil.Before(ik.CreatedAt) {
				delete(k.s.state.InstanceKeys, tp)
			}
		}
		k.s.swept = len(k.s.state.InstanceKeys)
	}
	if _, ok := k.s.state.InstanceKeys[ik.Thumbprint]; ok {
		return wp.ErrExists
	}
	ik = cloneInstanceKey(ik)
	ik.Revision = 1
	k.s.state.InstanceKeys[ik.Thumbprint] = ik
	if err := k.s.save(); err != nil {
		delete(k.s.state.InstanceKeys, ik.Thumbprint)
		return err
	}
	return nil
}

// Update implements wp.InstanceKeyStore, saving the change before it
// returns; should saving fail, it changes nothing.
func (k fileInstanceKeyStore) Update(ctx context.Context, ik wp.InstanceKey) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	k.s.mu.Lock()
	defer k.s.mu.Unlock()
	stored, ok := k.s.state.InstanceKeys[ik.Thumbprint]
	switch {
	case !ok:
		return wp.ErrNotFound
	case stored.InstanceID != ik.InstanceID:
		return errors.New("walletprovider: an update can't move an instance key to another instance")
	case stored.Revision != ik.Revision:
		return wp.ErrConflict
	}
	ik = cloneInstanceKey(ik)
	ik.Revision++
	k.s.state.InstanceKeys[ik.Thumbprint] = ik
	if err := k.s.save(); err != nil {
		k.s.state.InstanceKeys[ik.Thumbprint] = stored
		return err
	}
	return nil
}

// List implements wp.InstanceKeyStore.
func (k fileInstanceKeyStore) List(ctx context.Context, instanceID, after string, limit int) ([]wp.InstanceKey, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	k.s.mu.Lock()
	defer k.s.mu.Unlock()
	var thumbprints []string
	for tp, ik := range k.s.state.InstanceKeys {
		if ik.InstanceID == instanceID && tp > after {
			thumbprints = append(thumbprints, tp)
		}
	}
	sort.Strings(thumbprints)
	if len(thumbprints) > limit {
		thumbprints = thumbprints[:max(limit, 0)]
	}
	out := make([]wp.InstanceKey, len(thumbprints))
	for i, tp := range thumbprints {
		out[i] = cloneInstanceKey(k.s.state.InstanceKeys[tp])
	}
	return out, nil
}

// holderInstance is the shared Key Attestation instance's ID, "" if
// none is recorded.
func (s *fileInstanceStore) holderInstance() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state.HolderInstance
}

// setHolderInstance records the shared Key Attestation instance's ID.
func (s *fileInstanceStore) setHolderInstance(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	old := s.state.HolderInstance
	s.state.HolderInstance = id
	if err := s.save(); err != nil {
		s.state.HolderInstance = old
		return err
	}
	return nil
}

func cloneInstance(in wp.Instance) wp.Instance {
	in.Key = slices.Clone(in.Key)
	in.Credential = slices.Clone(in.Credential)
	in.EvidenceFacts = slices.Clone(in.EvidenceFacts)
	return in
}

func cloneInstanceKey(ik wp.InstanceKey) wp.InstanceKey {
	ik.Key = slices.Clone(ik.Key)
	ik.EvidenceFacts = slices.Clone(ik.EvidenceFacts)
	return ik
}

// pruneDemoInstances deletes, with their instance keys, the instances
// the older protocol registered (on DemoPlatform, other than the shared
// Key Attestation instance) that were last seen before idleBefore, and
// then the least recently seen of them past the newest keep, returning
// how many it deleted. The older protocol registers an instance for
// any new instance key, from any caller, so these are bounded and
// expire; a wallet whose instance went registers a new one with its
// next Wallet Attestation, as the protocol lets any caller do. The
// status list indices of their keys aren't reused.
func (s *fileInstanceStore) pruneDemoInstances(idleBefore time.Time, keep int) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	demo := s.demoInstancesOldestFirst()
	n := 0
	for n < len(demo) && (len(demo)-n > keep || lastSeen(demo[n]).Before(idleBefore)) {
		n++
	}
	if n == 0 {
		return 0, nil
	}
	instances, instanceKeys := maps.Clone(s.state.Instances), maps.Clone(s.state.InstanceKeys)
	dropped := map[string]bool{}
	for _, in := range demo[:n] {
		dropped[in.ID] = true
		delete(s.state.Instances, in.ID)
	}
	maps.DeleteFunc(s.state.InstanceKeys, func(_ string, ik wp.InstanceKey) bool { return dropped[ik.InstanceID] })
	if err := s.save(); err != nil {
		s.state.Instances, s.state.InstanceKeys = instances, instanceKeys
		return 0, err
	}
	return n, nil
}

// demoInstancesOldestFirst lists the instances pruneDemoInstances may
// delete, the least recently seen first. Called with s.mu held.
func (s *fileInstanceStore) demoInstancesOldestFirst() []wp.Instance {
	var out []wp.Instance
	for id, in := range s.state.Instances {
		if in.Evidence.Platform == DemoPlatform && id != s.state.HolderInstance {
			out = append(out, in)
		}
	}
	slices.SortFunc(out, func(a, b wp.Instance) int {
		if c := lastSeen(a).Compare(lastSeen(b)); c != 0 {
			return c
		}
		return strings.Compare(a.ID, b.ID)
	})
	return out
}

// lastSeen is when in was last seen, or registered.
func lastSeen(in wp.Instance) time.Time {
	if in.LastSeenAt.IsZero() {
		return in.CreatedAt
	}
	return in.LastSeenAt
}
