package statefile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math/bits"
	"os"
	"strconv"
	"sync"

	"github.com/idfoundry/oid4vcgo/statuslist"
)

// MaxIndex bounds the indices an IndexStore reserves: a list of up to
// 2^24 indices, the largest a Wallet Provider's may be.
const MaxIndex = 1<<24 - 1

// IndexStore is a statuslist.IndexStore kept in a JSON file,
// rewritten whole on every change: the durable store of a demo server
// with a state directory but no database. statuslist.MemoryIndexStore
// can't be saved and restored — it has no way to list its reservations
// — and a store that forgets them on a restart hands out the indices of
// statuses still in circulation again (draft-14 §13.3). One process
// uses the file; a deployment uses a database (sqlstore's
// StatusIndices), whose Reserve is atomic across processes.
//
// Each list is kept compactly, in memory and in the file: a bitmap of
// its reserved indices, one bit each, and the status of only those not
// VALID. A list's size so stays near an eighth of its indices in bytes
// however many are reserved, and a list deleted (as a Wallet Provider
// deletes its past periods' lists) takes its indices with it.
type IndexStore struct {
	mu    sync.Mutex
	path  string
	lists map[string]*indexList
}

var _ statuslist.IndexStore = (*IndexStore)(nil)

// indexList is one list's reservations.
type indexList struct {
	// reserved has bit idx%8 of byte idx/8 set for each reserved idx.
	reserved []byte
	count    int
	// statuses is the status of each reserved index not VALID.
	statuses map[uint64]statuslist.StatusType
}

func newIndexList() *indexList {
	return &indexList{statuses: map[uint64]statuslist.StatusType{}}
}

func (l *indexList) has(idx uint64) bool {
	return l != nil && idx/8 < uint64(len(l.reserved)) && l.reserved[idx/8]&(1<<(idx%8)) != 0
}

func (l *indexList) reserve(idx uint64) {
	if need, have := idx/8+1, uint64(len(l.reserved)); need > have {
		l.reserved = append(l.reserved, make([]byte, need-have)...)
	}
	l.reserved[idx/8] |= 1 << (idx % 8)
	l.count++
}

func (l *indexList) release(idx uint64) {
	l.reserved[idx/8] &^= 1 << (idx % 8)
	l.count--
}

func (l *indexList) status(idx uint64) statuslist.StatusType {
	if s, ok := l.statuses[idx]; ok {
		return s
	}
	return statuslist.StatusValid
}

func (l *indexList) setStatus(idx uint64, s statuslist.StatusType) {
	if s == statuslist.StatusValid {
		delete(l.statuses, idx)
	} else {
		l.statuses[idx] = s
	}
}

// fileFormat is the file's content: each list by URI.
type fileFormat struct {
	Version int                 `json:"version"`
	Lists   map[string]fileList `json:"lists"`
}

const fileVersion = 2

// fileList is a list in the file: its bitmap (base64), and the
// statuses not VALID by index.
type fileList struct {
	Reserved []byte                           `json:"reserved"`
	Statuses map[string]statuslist.StatusType `json:"statuses,omitempty"`
}

// OpenIndexStore reads the store saved at path, empty when there is
// none, saving it back there on every change. A file of the earlier
// format, every reserved index with its status, is read too, and
// rewritten in this one on the first change.
func OpenIndexStore(path string) (*IndexStore, error) {
	s := &IndexStore{path: path, lists: map[string]*indexList{}}
	data, err := os.ReadFile(path) // #nosec G304 -- operator-supplied state directory
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return s, nil
	case err != nil:
		return nil, fmt.Errorf("statefile: read %s: %w", path, err)
	}
	if err := s.load(data); err != nil {
		return nil, fmt.Errorf("statefile: %s: %w", path, err)
	}
	return s, nil
}

func (s *IndexStore) load(data []byte) error {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		return err
	}
	if _, ok := top["version"]; !ok {
		return s.loadEarlier(data)
	}
	var f fileFormat
	if err := json.Unmarshal(data, &f); err != nil {
		return err
	}
	if f.Version != fileVersion {
		return fmt.Errorf("status list indices of format %d, not %d", f.Version, fileVersion)
	}
	for uri, fl := range f.Lists {
		if len(fl.Reserved) > MaxIndex/8+1 {
			return fmt.Errorf("list %s reserves an index past %d", uri, MaxIndex)
		}
		l := newIndexList()
		l.reserved = fl.Reserved
		for _, b := range fl.Reserved {
			l.count += bits.OnesCount8(b)
		}
		for k, status := range fl.Statuses {
			idx, err := strconv.ParseUint(k, 10, 64)
			if err != nil || !l.has(idx) {
				return fmt.Errorf("list %s: status of unreserved index %q", uri, k)
			}
			l.setStatus(idx, status)
		}
		s.lists[uri] = l
	}
	return nil
}

// loadEarlier reads the earlier format: each list's reserved indices
// with their statuses.
func (s *IndexStore) loadEarlier(data []byte) error {
	var lists map[string]map[uint64]statuslist.StatusType
	if err := json.Unmarshal(data, &lists); err != nil {
		return err
	}
	for uri, reserved := range lists {
		l := newIndexList()
		for idx, status := range reserved {
			if idx > MaxIndex {
				return fmt.Errorf("list %s reserves index %d, past %d", uri, idx, MaxIndex)
			}
			l.reserve(idx)
			l.setStatus(idx, status)
		}
		s.lists[uri] = l
	}
	return nil
}

// save writes the store to its file. Called with s.mu held.
func (s *IndexStore) save() error {
	f := fileFormat{Version: fileVersion, Lists: make(map[string]fileList, len(s.lists))}
	for uri, l := range s.lists {
		fl := fileList{Reserved: l.reserved}
		if len(l.statuses) > 0 {
			fl.Statuses = make(map[string]statuslist.StatusType, len(l.statuses))
			for idx, status := range l.statuses {
				fl.Statuses[strconv.FormatUint(idx, 10)] = status
			}
		}
		f.Lists[uri] = fl
	}
	data, err := json.Marshal(f)
	if err != nil {
		return fmt.Errorf("statefile: encode status list indices: %w", err)
	}
	return WriteAtomic(s.path, data)
}

// Reserve implements statuslist.IndexStore, saving the reservation
// before it returns; should saving fail, it reserves nothing. It
// refuses an index past MaxIndex.
func (s *IndexStore) Reserve(_ context.Context, uri string, idx uint64) error {
	if idx > MaxIndex {
		return fmt.Errorf("statefile: index %d is past %d", idx, MaxIndex)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	list := s.lists[uri]
	if list.has(idx) {
		return statuslist.ErrIndexTaken
	}
	if list == nil {
		list = newIndexList()
		s.lists[uri] = list
	}
	list.reserve(idx)
	if err := s.save(); err != nil {
		list.release(idx)
		return err
	}
	return nil
}

// Reserved implements statuslist.IndexStore.
func (s *IndexStore) Reserved(_ context.Context, uri string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if l := s.lists[uri]; l != nil {
		return l.count, nil
	}
	return 0, nil
}

// SetStatus implements statuslist.IndexStore, saving the status before
// it returns; should saving fail, it changes nothing.
func (s *IndexStore) SetStatus(_ context.Context, uri string, idx uint64, status statuslist.StatusType) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	list := s.lists[uri]
	if !list.has(idx) {
		return statuslist.ErrIndexNotReserved
	}
	old := list.status(idx)
	list.setStatus(idx, status)
	if err := s.save(); err != nil {
		list.setStatus(idx, old)
		return err
	}
	return nil
}

// Status implements statuslist.IndexStore.
func (s *IndexStore) Status(_ context.Context, uri string, idx uint64) (statuslist.StatusType, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	list := s.lists[uri]
	if !list.has(idx) {
		return statuslist.StatusInvalid, statuslist.ErrIndexNotReserved
	}
	return list.status(idx), nil
}

// Statuses implements statuslist.IndexStore.
func (s *IndexStore) Statuses(_ context.Context, uri string, size int) ([]uint8, error) {
	if size < 0 {
		return nil, fmt.Errorf("statefile: list size %d is negative", size)
	}
	statuses := make([]uint8, size)
	s.mu.Lock()
	defer s.mu.Unlock()
	list := s.lists[uri]
	if list == nil {
		return statuses, nil
	}
	for idx := uint64(size); idx < uint64(len(list.reserved))*8; idx++ {
		if list.has(idx) {
			return nil, fmt.Errorf("statefile: index %d of %s is reserved, outside its %d indices", idx, uri, size)
		}
	}
	for idx, status := range list.statuses {
		statuses[idx] = uint8(status)
	}
	return statuses, nil
}

// Delete implements statuslist.IndexStore, saving the change before it
// returns; should saving fail, it deletes nothing.
func (s *IndexStore) Delete(_ context.Context, uri string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	list, ok := s.lists[uri]
	if !ok {
		return nil
	}
	delete(s.lists, uri)
	if err := s.save(); err != nil {
		s.lists[uri] = list
		return err
	}
	return nil
}
