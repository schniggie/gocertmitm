package proxy

import (
	"errors"
	"net"
	"os"
	"testing"
	"time"
)

// Looking up SO_ORIGINAL_DST must leave the socket non-blocking so read
// deadlines keep working (net/http relies on them to abort reads on Hijack)
func TestGetOriginalDstKeepsDeadlinesWorking(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	client, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	server, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	// Without an iptables redirect this fails; it must still not disturb the socket
	_, _ = GetOriginalDst(server.(*net.TCPConn))

	_ = server.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	done := make(chan error, 1)
	go func() {
		_, err := server.Read(make([]byte, 1))
		done <- err
	}()

	select {
	case err := <-done:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("expected deadline error, got %v", err)
		}
	case <-time.After(3 * time.Second):
		// Unblock the stuck read so the test can fail instead of hanging
		_, _ = client.Write([]byte{0})
		<-done
		t.Fatal("read ignored its deadline: socket was switched to blocking mode")
	}
}
