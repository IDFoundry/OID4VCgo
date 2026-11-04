package issuerapp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sync"

	"github.com/idfoundry/oid4vcgo/statuslist"
)

// statusIndicesFile is where an issuer with Config.StateDir and no
// Config.Database keeps its status list's index reservations and
// statuses (fileIndexStore).
const statusIndicesFile = "status-indices.json"

// fileIndexStore is a statuslist.IndexStore kept in a JSON file,
// rewritten whole on every change: the durable store of an issuer with
// a state directory but no database. statuslist.MemoryIndexStore
// can't be saved and restored — it has no way to list its reservations
// — and a store that forgets them on a restart hands out the indices of
// credentials still in circulation again (draft-14 §13.3). One process
// uses the file; a deployment uses a database (sqlstore's
// StatusIndices, as Config.Database does), whose Reserve is atomic
// across processes.
type fileIndexStore struct {
	mu    sync.Mutex
	path  string
	lists map[string]map[uint64]statuslist.StatusType
}

var _ statuslist.IndexStore = (*fileIndexStore)(nil)

// openFileIndexStore reads the store saved at path, empty when there is
// none, saving it back there on every change.
func openFileIndexStore(path string) (*fileIndexStore, error) {
	s := &fileIndexStore{path: path, lists: map[string]map[uint64]statuslist.StatusType{}}
	data, err := os.ReadFile(path) // #nosec G304 -- operator-supplied state directory
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return s, nil
	case err != nil:
		return nil, fmt.Errorf("issuerapp: read %s: %w", path, err)
	}
	if err := json.Unmarshal(data, &s.lists); err != nil {
		return nil, fmt.Errorf("issuerapp: %s: %w", path, err)
	}
	for uri, list := range s.lists {
		if list == nil {
			s.lists[uri] = map[uint64]statuslist.StatusType{}
		}
	}
	return s, nil
}

// save writes the store to its file. Called with s.mu held.
func (s *fileIndexStore) save() error {
	data, err := json.Marshal(s.lists)
	if err != nil {
		return fmt.Errorf("issuerapp: encode status list indices: %w", err)
	}
	return writeFileAtomic(s.path, data)
}

// Reserve implements statuslist.IndexStore, saving the reservation
// before it returns; should saving fail, it reserves nothing.
func (s *fileIndexStore) Reserve(_ context.Context, uri string, idx uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	list := s.lists[uri]
	if _, ok := list[idx]; ok {
		return statuslist.ErrIndexTaken
	}
	if list == nil {
		list = map[uint64]statuslist.StatusType{}
		s.lists[uri] = list
	}
	list[idx] = statuslist.StatusValid
	if err := s.save(); err != nil {
		delete(list, idx)
		return err
	}
	return nil
}

// Reserved implements statuslist.IndexStore.
func (s *fileIndexStore) Reserved(_ context.Context, uri string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.lists[uri]), nil
}

// SetStatus implements statuslist.IndexStore, saving the status before
// it returns; should saving fail, it changes nothing.
func (s *fileIndexStore) SetStatus(_ context.Context, uri string, idx uint64, status statuslist.StatusType) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	old, ok := s.lists[uri][idx]
	if !ok {
		return statuslist.ErrIndexNotReserved
	}
	s.lists[uri][idx] = status
	if err := s.save(); err != nil {
		s.lists[uri][idx] = old
		return err
	}
	return nil
}

// Status implements statuslist.IndexStore.
func (s *fileIndexStore) Status(_ context.Context, uri string, idx uint64) (statuslist.StatusType, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	status, ok := s.lists[uri][idx]
	if !ok {
		return statuslist.StatusInvalid, statuslist.ErrIndexNotReserved
	}
	return status, nil
}

// Statuses implements statuslist.IndexStore.
func (s *fileIndexStore) Statuses(_ context.Context, uri string, size int) ([]uint8, error) {
	if size < 0 {
		return nil, fmt.Errorf("issuerapp: list size %d is negative", size)
	}
	statuses := make([]uint8, size)
	s.mu.Lock()
	defer s.mu.Unlock()
	for idx, status := range s.lists[uri] {
		if idx >= uint64(size) {
			return nil, fmt.Errorf("issuerapp: index %d of %s is reserved, outside its %d indices", idx, uri, size)
		}
		statuses[idx] = uint8(status)
	}
	return statuses, nil
}
