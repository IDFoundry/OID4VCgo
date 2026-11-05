package certrevocation

import (
	"context"
	"time"
)

// SetScheduleForTest replaces the sleep and jitter Run uses, so a test
// can run its loop without waiting.
func (r *Refresher) SetScheduleForTest(wait func(context.Context, time.Duration) bool, jitter func(time.Duration) time.Duration) {
	r.wait, r.jitter = wait, jitter
}

// AcceptForTest parses body as a fetch of u would, and keeps the list
// if it's acceptable, without fetching: what a fetch answering body
// would do.
func (r *Refresher) AcceptForTest(u string, body []byte) error {
	list, err := parseCRL(body)
	if err != nil {
		return err
	}
	return r.keep(u, list, validators{}, nil)
}
