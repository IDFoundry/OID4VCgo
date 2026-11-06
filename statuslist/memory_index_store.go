package statuslist

import (
	"context"
	"fmt"
	"sync"
)

// MemoryIndexStore is an IndexStore held in memory, safe for
// concurrent use; its zero value is ready to use. It is for tests and
// a single process whose lists live no longer than it does: it isn't
// durable, so a restart forgets every reservation and the indices of
// tokens still in circulation are handed out again — the double
// allocation draft-14 §13.3 has the Status Issuer prevent — and it
// isn't shared, so two processes allocating from the same lists each
// hand out the other's indices. Use a durable store in production.
type MemoryIndexStore struct {
	mu    sync.Mutex
	lists map[string]map[uint64]StatusType
}

var _ BatchIndexStore = (*MemoryIndexStore)(nil)

// Reserve implements IndexStore.
func (s *MemoryIndexStore) Reserve(_ context.Context, uri string, idx uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	list := s.list(uri)
	if _, ok := list[idx]; ok {
		return ErrIndexTaken
	}
	list[idx] = StatusValid
	return nil
}

// ReserveEach implements BatchIndexStore.
func (s *MemoryIndexStore) ReserveEach(_ context.Context, uri string, idxs []uint64) ([]uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	list := s.list(uri)
	reserved := make([]uint64, 0, len(idxs))
	for _, idx := range idxs {
		if _, ok := list[idx]; !ok {
			list[idx] = StatusValid
			reserved = append(reserved, idx)
		}
	}
	return reserved, nil
}

// list returns the reservations of the list at uri, made if need be.
// s.mu is held.
func (s *MemoryIndexStore) list(uri string) map[uint64]StatusType {
	list := s.lists[uri]
	if list == nil {
		if s.lists == nil {
			s.lists = make(map[string]map[uint64]StatusType)
		}
		list = make(map[uint64]StatusType)
		s.lists[uri] = list
	}
	return list
}

// Reserved implements IndexStore.
func (s *MemoryIndexStore) Reserved(_ context.Context, uri string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.lists[uri]), nil
}

// SetStatus implements IndexStore.
func (s *MemoryIndexStore) SetStatus(_ context.Context, uri string, idx uint64, status StatusType) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.lists[uri][idx]; !ok {
		return ErrIndexNotReserved
	}
	s.lists[uri][idx] = status
	return nil
}

// Status implements IndexStore.
func (s *MemoryIndexStore) Status(_ context.Context, uri string, idx uint64) (StatusType, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	status, ok := s.lists[uri][idx]
	if !ok {
		return StatusInvalid, ErrIndexNotReserved
	}
	return status, nil
}

// Statuses implements IndexStore.
func (s *MemoryIndexStore) Statuses(_ context.Context, uri string, size int) ([]uint8, error) {
	if size < 0 {
		return nil, fmt.Errorf("statuslist: list size %d is negative", size)
	}
	statuses := make([]uint8, size)
	s.mu.Lock()
	defer s.mu.Unlock()
	for idx, status := range s.lists[uri] {
		if idx >= uint64(size) {
			return nil, fmt.Errorf("statuslist: index %d of %s is reserved, outside its %d indices", idx, uri, size)
		}
		statuses[idx] = uint8(status)
	}
	return statuses, nil
}

// Delete implements IndexStore.
func (s *MemoryIndexStore) Delete(_ context.Context, uri string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.lists, uri)
	return nil
}
