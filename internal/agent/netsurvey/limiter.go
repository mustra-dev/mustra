package netsurvey

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// Limiter spaces every probe a run sends, across all protocols and all
// hosts in flight, at no more than its rate. It allows no burst: an IDS
// or a fragile PLC network stack sees an even trickle, never a spike when
// a batch of workers starts at once.
type Limiter struct {
	mu       sync.Mutex
	interval time.Duration
	next     time.Time
	sent     atomic.Int64
}

// NewLimiter returns a limiter for pps probes per second (at least 1).
func NewLimiter(pps int) *Limiter {
	if pps < 1 {
		pps = 1
	}
	return &Limiter{interval: time.Second / time.Duration(pps)}
}

// Wait blocks until the next probe may go, or ctx ends. Every call that
// returns nil is counted as one probe.
func (l *Limiter) Wait(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	l.mu.Lock()
	now := time.Now()
	if l.next.Before(now) {
		l.next = now
	}
	at := l.next
	l.next = l.next.Add(l.interval)
	l.mu.Unlock()
	if d := time.Until(at); d > 0 {
		t := time.NewTimer(d)
		defer t.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
	}
	l.sent.Add(1)
	return nil
}

// Sent is how many probes were let through.
func (l *Limiter) Sent() int { return int(l.sent.Load()) }
