package ingest

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakeClamd speaks the clamd zVERSION / zINSTREAM protocol.
type fakeClamd struct {
	ln       net.Listener
	maxBytes int
	received atomic.Int64
	silent   atomic.Bool // never reply to INSTREAM
}

func startClamd(t *testing.T, maxBytes int) *fakeClamd {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeClamd{ln: ln, maxBytes: maxBytes}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.handle(c)
		}
	}()
	return f
}

func (f *fakeClamd) handle(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	cmd, err := br.ReadString(0)
	if err != nil {
		return
	}
	switch cmd {
	case "zVERSION\x00":
		_, _ = c.Write([]byte("ClamAV 1.4.1/27470/Mon Nov 16 08:00:00 2026\x00"))
	case "zINSTREAM\x00":
		var data bytes.Buffer
		for {
			var l [4]byte
			if _, err := io.ReadFull(br, l[:]); err != nil {
				return
			}
			n := binary.BigEndian.Uint32(l[:])
			if n == 0 {
				break
			}
			if data.Len()+int(n) > f.maxBytes {
				_, _ = c.Write([]byte("INSTREAM size limit exceeded. ERROR\x00"))
				return
			}
			if _, err := io.CopyN(&data, br, int64(n)); err != nil {
				return
			}
		}
		f.received.Store(int64(data.Len()))
		if f.silent.Load() {
			time.Sleep(5 * time.Second)
			return
		}
		if bytes.Contains(data.Bytes(), []byte("EICAR-STANDARD-ANTIVIRUS-TEST-FILE")) {
			_, _ = c.Write([]byte("stream: Eicar-Test-Signature FOUND\x00"))
			return
		}
		_, _ = c.Write([]byte("stream: OK\x00"))
	default:
		_, _ = c.Write([]byte("UNKNOWN COMMAND\x00"))
	}
}

func TestClamAVScan(t *testing.T) {
	f := startClamd(t, 10<<20)
	c := ClamAV{Address: f.ln.Addr().String(), Timeout: 10 * time.Second}
	ctx := context.Background()

	clean := bytes.Repeat([]byte("benign "), 50000) // > several chunks
	v, err := c.Scan(ctx, bytes.NewReader(clean))
	if err != nil || !v.Clean || v.Signature != "" || !strings.HasPrefix(v.Engine, "ClamAV 1.4.1/") {
		t.Fatalf("clean: %+v %v", v, err)
	}
	if f.received.Load() != int64(len(clean)) {
		t.Fatalf("clamd received %d bytes, want %d", f.received.Load(), len(clean))
	}

	eicar := `X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`
	v, err = c.Scan(ctx, strings.NewReader(eicar))
	if err != nil || v.Clean || v.Signature != "Eicar-Test-Signature" {
		t.Fatalf("infected: %+v %v", v, err)
	}

	v, err = c.Scan(ctx, bytes.NewReader(nil))
	if err != nil || !v.Clean {
		t.Fatalf("empty: %+v %v", v, err)
	}
}

func TestClamAVSizeLimit(t *testing.T) {
	f := startClamd(t, 100<<10)
	c := ClamAV{Address: f.ln.Addr().String(), Timeout: 10 * time.Second}
	_, err := c.Scan(context.Background(), bytes.NewReader(make([]byte, 4<<20)))
	if !errors.Is(err, ErrClamAVSizeLimit) {
		t.Fatalf("expected ErrClamAVSizeLimit, got %v", err)
	}
}

func TestClamAVUnavailableAndTimeout(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	_ = ln.Close()
	if _, err := (ClamAV{Address: addr, Timeout: time.Second}).Scan(context.Background(), strings.NewReader("x")); err == nil {
		t.Fatal("expected a connection error")
	}
	if _, err := (ClamAV{}).Scan(context.Background(), strings.NewReader("x")); err == nil {
		t.Fatal("expected an error without an address")
	}

	f := startClamd(t, 1<<20)
	f.silent.Store(true)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := ClamAV{Address: f.ln.Addr().String(), Timeout: 10 * time.Second}.Scan(ctx, strings.NewReader("x"))
	if err == nil || time.Since(start) > 3*time.Second {
		t.Fatalf("expected a prompt timeout, got %v after %v", err, time.Since(start))
	}
}

func TestParseScanReply(t *testing.T) {
	if _, err := parseScanReply("stream: something weird", ""); !errors.Is(err, ErrClamAVProtocol) {
		t.Fatalf("got %v", err)
	}
	v, err := parseScanReply("stream: Win.Test.Foo-1 FOUND", "e")
	if err != nil || v.Signature != "Win.Test.Foo-1" || v.Clean {
		t.Fatalf("%+v %v", v, err)
	}
}
