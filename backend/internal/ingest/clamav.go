package ingest

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// ClamAV is a minimal clamd client (TCP, zINSTREAM).
type ClamAV struct {
	Address string        // host:port of clamd
	Timeout time.Duration // per connection; default 5 minutes
}

// Verdict is the result of one scan.
type Verdict struct {
	Clean     bool
	Signature string // set when infected
	Engine    string // zVERSION reply, e.g. "ClamAV 1.4.1/27470/Mon Nov 16 08:00:00 2026"
}

var (
	// ErrClamAVSizeLimit means the stream exceeded clamd's StreamMaxLength.
	ErrClamAVSizeLimit = errors.New("clamav: INSTREAM size limit exceeded")
	// ErrClamAVProtocol means clamd sent an unexpected reply.
	ErrClamAVProtocol = errors.New("clamav: unexpected reply")
)

const clamChunk = 64 << 10

func (c ClamAV) dial(ctx context.Context) (net.Conn, error) {
	if c.Address == "" {
		return nil, errors.New("clamav: no address configured")
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	d := net.Dialer{Timeout: min(timeout, 30*time.Second)}
	conn, err := d.DialContext(ctx, "tcp", c.Address)
	if err != nil {
		return nil, fmt.Errorf("clamav: %w", err)
	}
	deadline := time.Now().Add(timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)
	// Abort blocking I/O when ctx is cancelled.
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Unix(1, 0)) })
	return &stopConn{Conn: conn, stop: stop}, nil
}

type stopConn struct {
	net.Conn
	stop func() bool
}

func (s *stopConn) Close() error {
	s.stop()
	return s.Conn.Close()
}

// readReply reads one NUL-terminated reply (bounded).
func readReply(r io.Reader) (string, error) {
	br := bufio.NewReader(io.LimitReader(r, 4096))
	s, err := br.ReadString(0)
	if err != nil && !(err == io.EOF && s != "") {
		return "", fmt.Errorf("clamav: reading reply: %w", err)
	}
	return strings.TrimSpace(strings.TrimRight(s, "\x00")), nil
}

// Version returns the clamd engine and signature database version.
func (c ClamAV) Version(ctx context.Context) (string, error) {
	conn, err := c.dial(ctx)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("zVERSION\x00")); err != nil {
		return "", fmt.Errorf("clamav: %w", err)
	}
	v, err := readReply(conn)
	if err != nil {
		return "", err
	}
	if v == "" || strings.HasSuffix(v, "ERROR") {
		return "", fmt.Errorf("%w: %q", ErrClamAVProtocol, v)
	}
	return v, nil
}

// Scan streams r to clamd and returns its verdict. Engine is filled from
// zVERSION on a separate connection before the scan.
func (c ClamAV) Scan(ctx context.Context, r io.Reader) (Verdict, error) {
	engine, err := c.Version(ctx)
	if err != nil {
		return Verdict{}, err
	}
	v, err := c.ScanStream(ctx, r)
	v.Engine = engine
	return v, err
}

// ScanStream streams r to clamd and returns its verdict without asking for
// the engine version (callers scanning many files ask once). A failure to
// read r is reported as is (see IsClamAVSourceError).
func (c ClamAV) ScanStream(ctx context.Context, r io.Reader) (Verdict, error) {
	conn, err := c.dial(ctx)
	if err != nil {
		return Verdict{}, err
	}
	defer conn.Close()
	werr := sendStream(conn, r)
	var srcErr *sourceError
	if errors.As(werr, &srcErr) {
		return Verdict{}, srcErr
	}
	// clamd may answer (and close) early, for example when the size limit
	// is exceeded; its reply explains a failed write.
	reply, rerr := readReply(conn)
	if rerr != nil {
		if werr != nil {
			return Verdict{}, werr
		}
		if ctx.Err() != nil {
			return Verdict{}, ctx.Err()
		}
		return Verdict{}, rerr
	}
	return parseScanReply(reply, "")
}

func parseScanReply(reply, engine string) (Verdict, error) {
	switch {
	case strings.Contains(reply, "size limit exceeded"):
		return Verdict{}, ErrClamAVSizeLimit
	case strings.HasSuffix(reply, " OK"):
		return Verdict{Clean: true, Engine: engine}, nil
	case strings.HasSuffix(reply, " FOUND"):
		sig := strings.TrimSuffix(reply, " FOUND")
		if i := strings.LastIndex(sig, ": "); i >= 0 {
			sig = sig[i+2:]
		}
		return Verdict{Clean: false, Signature: sig, Engine: engine}, nil
	}
	return Verdict{}, fmt.Errorf("%w: %q", ErrClamAVProtocol, reply)
}

// sourceError wraps a failure to read the data being scanned (as opposed
// to a network error).
type sourceError struct{ err error }

func (e *sourceError) Error() string { return e.err.Error() }

func (e *sourceError) Unwrap() error { return e.err }

// IsClamAVSourceError reports whether err came from reading the scanned
// data rather than from clamd.
func IsClamAVSourceError(err error) bool {
	var se *sourceError
	return errors.As(err, &se)
}

func sendStream(w io.Writer, r io.Reader) error {
	if _, err := w.Write([]byte("zINSTREAM\x00")); err != nil {
		return fmt.Errorf("clamav: %w", err)
	}
	buf := make([]byte, 4+clamChunk)
	for {
		n, err := io.ReadFull(r, buf[4:])
		if n > 0 {
			binary.BigEndian.PutUint32(buf[:4], uint32(n)) // #nosec G115 -- n <= clamChunk
			if _, werr := w.Write(buf[:4+n]); werr != nil {
				return fmt.Errorf("clamav: %w", werr)
			}
		}
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		}
		if err != nil {
			return &sourceError{err: err}
		}
	}
	if _, err := w.Write([]byte{0, 0, 0, 0}); err != nil {
		return fmt.Errorf("clamav: %w", err)
	}
	return nil
}
