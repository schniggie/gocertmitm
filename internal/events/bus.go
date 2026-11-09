// Package events provides a small in-process publish/subscribe bus used to
// feed live state (test results, intercepted requests, log lines) to the web
// UI without coupling the proxy to any particular transport.
//
// Publishing never blocks: every topic keeps a bounded ring of recent events
// for late joiners, and subscribers that cannot keep up are disconnected
// (their channel is closed) instead of slowing down the proxy hot path.
package events

import (
	"sync"
	"time"
)

// Well-known topics
const (
	TopicDomain    = "domain"    // a domain's test state changed
	TopicRequest   = "request"   // a decrypted / proxied request completed
	TopicHandshake = "handshake" // a TLS handshake with a client failed
	TopicLog       = "log"       // a log line was written
)

// Event is a single message on the bus
type Event struct {
	ID    uint64    `json:"id"`
	Time  time.Time `json:"time"`
	Topic string    `json:"topic"`
	Data  any       `json:"data"`
}

// Subscription receives events published after it was created
type Subscription struct {
	C      <-chan Event
	ch     chan Event
	bus    *Bus
	closed bool
}

// Close detaches the subscription from the bus. It is safe to call more
// than once and concurrently with Publish.
func (s *Subscription) Close() {
	s.bus.mu.Lock()
	defer s.bus.mu.Unlock()
	s.bus.removeLocked(s)
}

// Bus is a non-blocking fan-out event bus with per-topic history
type Bus struct {
	mu          sync.Mutex
	nextID      uint64
	rings       map[string]*ring
	defaultCap  int
	subscribers map[*Subscription]struct{}
	bufferSize  int
}

// Option configures a Bus
type Option func(*Bus)

// WithHistory sets how many recent events are retained for a topic
func WithHistory(topic string, n int) Option {
	return func(b *Bus) {
		if n > 0 {
			b.rings[topic] = newRing(n)
		}
	}
}

// WithDefaultHistory sets the retention for topics without an explicit size
func WithDefaultHistory(n int) Option {
	return func(b *Bus) {
		if n > 0 {
			b.defaultCap = n
		}
	}
}

// WithSubscriberBuffer sets the per-subscriber channel buffer
func WithSubscriberBuffer(n int) Option {
	return func(b *Bus) {
		if n > 0 {
			b.bufferSize = n
		}
	}
}

// NewBus creates a bus
func NewBus(opts ...Option) *Bus {
	b := &Bus{
		rings:       make(map[string]*ring),
		defaultCap:  500,
		subscribers: make(map[*Subscription]struct{}),
		bufferSize:  512,
	}
	for _, opt := range opts {
		opt(b)
	}
	return b
}

// Publish records an event and fans it out to subscribers. It never blocks;
// a subscriber whose buffer is full is dropped so it can reconnect and
// resynchronise from snapshots.
func (b *Bus) Publish(topic string, data any) {
	if b == nil {
		return
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	b.nextID++
	ev := Event{ID: b.nextID, Time: time.Now(), Topic: topic, Data: data}

	r, ok := b.rings[topic]
	if !ok {
		r = newRing(b.defaultCap)
		b.rings[topic] = r
	}
	r.push(ev)

	for sub := range b.subscribers {
		select {
		case sub.ch <- ev:
		default:
			b.removeLocked(sub)
		}
	}
}

// Subscribe returns a subscription receiving all future events
func (b *Bus) Subscribe() *Subscription {
	ch := make(chan Event, b.bufferSize)
	sub := &Subscription{C: ch, ch: ch, bus: b}

	b.mu.Lock()
	b.subscribers[sub] = struct{}{}
	b.mu.Unlock()

	return sub
}

// Recent returns up to limit of the most recent events for a topic, oldest
// first. A limit <= 0 returns everything retained.
func (b *Bus) Recent(topic string, limit int) []Event {
	b.mu.Lock()
	defer b.mu.Unlock()

	r, ok := b.rings[topic]
	if !ok {
		return []Event{}
	}
	return r.last(limit)
}

// SubscriberCount returns the number of attached subscribers
func (b *Bus) SubscriberCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.subscribers)
}

func (b *Bus) removeLocked(sub *Subscription) {
	if sub.closed {
		return
	}
	sub.closed = true
	delete(b.subscribers, sub)
	close(sub.ch)
}

// ring is a fixed-capacity circular buffer of events
type ring struct {
	buf   []Event
	start int
	n     int
}

func newRing(capacity int) *ring {
	return &ring{buf: make([]Event, capacity)}
}

func (r *ring) push(ev Event) {
	if r.n < len(r.buf) {
		r.buf[(r.start+r.n)%len(r.buf)] = ev
		r.n++
		return
	}
	r.buf[r.start] = ev
	r.start = (r.start + 1) % len(r.buf)
}

func (r *ring) last(limit int) []Event {
	n := r.n
	if limit > 0 && limit < n {
		n = limit
	}
	out := make([]Event, 0, n)
	for i := r.n - n; i < r.n; i++ {
		out = append(out, r.buf[(r.start+i)%len(r.buf)])
	}
	return out
}
