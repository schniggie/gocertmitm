package events

import (
	"sync"
	"testing"
)

func TestRecentKeepsNewestInOrder(t *testing.T) {
	b := NewBus(WithHistory("t", 3))
	for i := 1; i <= 5; i++ {
		b.Publish("t", i)
	}

	got := b.Recent("t", 0)
	if len(got) != 3 {
		t.Fatalf("expected 3 events, got %d", len(got))
	}
	for i, want := range []int{3, 4, 5} {
		if got[i].Data.(int) != want {
			t.Fatalf("event %d: got %v want %d", i, got[i].Data, want)
		}
	}

	limited := b.Recent("t", 2)
	if len(limited) != 2 || limited[0].Data.(int) != 4 || limited[1].Data.(int) != 5 {
		t.Fatalf("unexpected limited result: %+v", limited)
	}

	if len(b.Recent("missing", 10)) != 0 {
		t.Fatal("expected empty slice for unknown topic")
	}
}

func TestSubscribeReceivesEvents(t *testing.T) {
	b := NewBus()
	sub := b.Subscribe()
	defer sub.Close()

	b.Publish("a", "x")
	ev := <-sub.C
	if ev.Topic != "a" || ev.Data.(string) != "x" || ev.ID == 0 {
		t.Fatalf("unexpected event: %+v", ev)
	}
}

func TestSlowSubscriberIsDropped(t *testing.T) {
	b := NewBus(WithSubscriberBuffer(2))
	sub := b.Subscribe()

	for i := 0; i < 5; i++ {
		b.Publish("a", i) // must not block
	}

	if b.SubscriberCount() != 0 {
		t.Fatal("slow subscriber should have been removed")
	}

	// Buffered events drain, then the channel is closed
	n := 0
	for range sub.C {
		n++
	}
	if n != 2 {
		t.Fatalf("expected 2 buffered events, got %d", n)
	}

	sub.Close() // idempotent
}

func TestConcurrentPublishAndClose(t *testing.T) {
	b := NewBus()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s := b.Subscribe()
			for j := 0; j < 100; j++ {
				b.Publish("a", j)
			}
			s.Close()
		}()
	}
	wg.Wait()
	if b.SubscriberCount() != 0 {
		t.Fatal("expected all subscribers closed")
	}
}

func TestNilBusPublishIsNoop(t *testing.T) {
	var b *Bus
	b.Publish("a", 1)
}
