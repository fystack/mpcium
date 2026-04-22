package coordinator

import (
	"context"
	"errors"
	"sync"
)

type Runtime interface {
	Start(ctx context.Context) error
	Stop() error
}

type CompositeRuntime struct {
	mu       sync.Mutex
	runtimes []Runtime
	started  []Runtime
}

func NewCompositeRuntime(runtimes ...Runtime) *CompositeRuntime {
	filtered := make([]Runtime, 0, len(runtimes))
	for _, r := range runtimes {
		if r != nil {
			filtered = append(filtered, r)
		}
	}
	return &CompositeRuntime{runtimes: filtered}
}

func (r *CompositeRuntime) Start(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.started) > 0 {
		return errors.New("composite runtime already started")
	}

	r.started = make([]Runtime, 0, len(r.runtimes))

	for _, runtime := range r.runtimes {
		if err := runtime.Start(ctx); err != nil {
			r.stopLocked()
			return err
		}
		r.started = append(r.started, runtime)
	}

	return nil
}

func (r *CompositeRuntime) Stop() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.stopLocked()
}

func (r *CompositeRuntime) stopLocked() error {
	var errs []error
	for i := len(r.started) - 1; i >= 0; i-- {
		if err := r.started[i].Stop(); err != nil {
			errs = append(errs, err)
		}
	}
	r.started = nil
	return errors.Join(errs...)
}
