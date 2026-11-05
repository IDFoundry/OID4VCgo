package walletprovider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"sort"
	"sync"

	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/internal/statefile"
	wp "github.com/idfoundry/oid4vcgo/walletprovider"
)

// fileInstanceStore is a wp.InstanceStore kept in a JSON file,
// rewritten whole on every change, so the library instances the
// service registers — and their status list indices — outlive a
// restart. It also keeps the ID of the shared instance the service
// issues Key Attestations under. One process uses the file; a
// deployment uses a database.
type fileInstanceStore struct {
	mu    sync.Mutex
	path  string
	state instanceFile
}

// instanceFile is fileInstanceStore's file.
type instanceFile struct {
	Instances      map[string]wp.Instance `json:"instances"`
	HolderInstance string                 `json:"holder_instance,omitempty"`
}

var _ wp.InstanceStore = (*fileInstanceStore)(nil)

// openFileInstanceStore reads the store saved at path, empty when there
// is none, saving it back there on every change; with path "", it's
// kept in memory only.
func openFileInstanceStore(path string) (*fileInstanceStore, error) {
	s := &fileInstanceStore{path: path, state: instanceFile{Instances: map[string]wp.Instance{}}}
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
	if err := json.Unmarshal(data, &s.state); err != nil {
		return nil, fmt.Errorf("walletprovider: %s: %w", path, err)
	}
	if s.state.Instances == nil {
		s.state.Instances = map[string]wp.Instance{}
	}
	keys := map[string]bool{}
	for id, in := range s.state.Instances {
		if in.ID != id || in.KeyThumbprint == "" || keys[in.KeyThumbprint] {
			return nil, fmt.Errorf("walletprovider: %s: instance %q is damaged or a duplicate", path, id)
		}
		keys[in.KeyThumbprint] = true
	}
	return s, nil
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
		if stored.KeyThumbprint == in.KeyThumbprint {
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

// byThumbprint maps each stored instance's key thumbprint to its ID,
// but for the shared holder instance's, whose key no wallet holds.
func (s *fileInstanceStore) byThumbprint() map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := make(map[string]string, len(s.state.Instances))
	for id, in := range s.state.Instances {
		if id != s.state.HolderInstance {
			m[in.KeyThumbprint] = id
		}
	}
	return m
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
	return in
}
