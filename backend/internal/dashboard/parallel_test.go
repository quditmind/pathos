package dashboard

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestRunParallel(t *testing.T) {
	var running, peak, done atomic.Int32
	var tasks []func(context.Context) error
	for range 12 {
		tasks = append(tasks, func(context.Context) error {
			n := running.Add(1)
			for {
				p := peak.Load()
				if n <= p || peak.CompareAndSwap(p, n) {
					break
				}
			}
			time.Sleep(5 * time.Millisecond)
			running.Add(-1)
			done.Add(1)
			return nil
		})
	}
	if err := runParallel(t.Context(), 3, tasks); err != nil {
		t.Fatal(err)
	}
	if done.Load() != 12 || peak.Load() > 3 || peak.Load() < 2 {
		t.Errorf("done %d, peak concurrency %d (limit 3)", done.Load(), peak.Load())
	}

	boom := errors.New("boom")
	err := runParallel(t.Context(), 2, []func(context.Context) error{
		func(context.Context) error { return boom },
		func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() },
	})
	if !errors.Is(err, boom) {
		t.Errorf("want the first error, got %v", err)
	}
	if err := runParallel(t.Context(), 4, nil); err != nil {
		t.Errorf("no tasks: %v", err)
	}
}
