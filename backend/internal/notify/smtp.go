package notify

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/netip"
	"net/smtp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"

	"pathos/internal/scm"
)

// SMTPConfig is a resolved SMTP configuration (password revealed).
type SMTPConfig struct {
	Host        string
	Port        int
	TLSMode     string // starttls | tls | none
	Username    string
	Password    string
	FromAddress string
	FromName    string
}

// Message is one email.
type Message struct {
	To      string
	Subject string
	Body    string
	Event   string
}

// smtpNet allows private relays (common in enterprises) but never loopback,
// link-local or cloud metadata addresses.
var smtpNet = scm.NetPolicy{AllowPrivate: true}

// ValidateAddress checks a single bare email address.
func ValidateAddress(s string) error {
	a, err := mail.ParseAddress(s)
	if err != nil || a.Address != s || a.Name != "" || strings.ContainsAny(s, "\r\n") {
		return fmt.Errorf("invalid email address %q", s)
	}
	return nil
}

// ValidateHost rejects hosts that are syntactically invalid or literal
// addresses outside the policy.
func ValidateHost(h string) error {
	if h == "" || len(h) > 253 || strings.ContainsAny(h, " /\\@\r\n:") {
		return errors.New("invalid SMTP host")
	}
	if ip, err := netip.ParseAddr(h); err == nil && !smtpNet.Allowed(ip) {
		return scm.ErrBlockedAddress
	}
	return nil
}

func encodeHeader(s string) string { return mime.QEncoding.Encode("utf-8", SanitizeHeader(s, 300)) }

// Build renders RFC 5322 bytes. Header values are sanitized and encoded.
func Build(cfg SMTPConfig, m Message, now time.Time) ([]byte, error) {
	if err := ValidateAddress(cfg.FromAddress); err != nil {
		return nil, fmt.Errorf("from: %w", err)
	}
	if err := ValidateAddress(m.To); err != nil {
		return nil, fmt.Errorf("to: %w", err)
	}
	var b bytes.Buffer
	from := (&mail.Address{Name: SanitizeHeader(cfg.FromName, 100), Address: cfg.FromAddress}).String()
	domain := cfg.FromAddress[strings.LastIndexByte(cfg.FromAddress, '@')+1:]
	hdr := [][2]string{
		{"From", from},
		{"To", m.To},
		{"Subject", encodeHeader(m.Subject)},
		{"Date", now.UTC().Format(time.RFC1123Z)},
		{"Message-ID", "<" + uuid.NewString() + "@" + domain + ">"},
		{"MIME-Version", "1.0"},
		{"Content-Type", `text/plain; charset="utf-8"`},
		{"Content-Transfer-Encoding", "quoted-printable"},
		{"Auto-Submitted", "auto-generated"},
		{"X-Auto-Response-Suppress", "All"},
		{"X-PATHOS-Event", SanitizeHeader(m.Event, 60)},
	}
	for _, h := range hdr {
		b.WriteString(h[0] + ": " + h[1] + "\r\n")
	}
	b.WriteString("\r\n")
	qp := quotedprintable.NewWriter(&b)
	body := strings.ReplaceAll(strings.ReplaceAll(m.Body, "\r\n", "\n"), "\n", "\r\n")
	if _, err := qp.Write([]byte(body)); err != nil {
		return nil, err
	}
	if err := qp.Close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// Sender delivers messages.
type Sender interface {
	Send(ctx context.Context, cfg SMTPConfig, m Message) error
}

// SMTPSender talks to a relay with net/smtp.
type SMTPSender struct {
	// Dial overrides the dialer (tests).
	Dial func(ctx context.Context, addr string) (net.Conn, error)
}

func (s SMTPSender) dial(ctx context.Context, addr string) (net.Conn, error) {
	if s.Dial != nil {
		return s.Dial(ctx, addr)
	}
	d := &net.Dialer{
		Timeout: 15 * time.Second,
		Control: func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			ip, err := netip.ParseAddr(host)
			if err != nil || !smtpNet.Allowed(ip) {
				return fmt.Errorf("%w: %s", scm.ErrBlockedAddress, host)
			}
			return nil
		},
	}
	return d.DialContext(ctx, "tcp", addr)
}

// SMTPError is a failure at one stage of an SMTP session: connect,
// greeting, hello, starttls, auth, mail, rcpt or data.
type SMTPError struct {
	Stage string
	Err   error
}

func (e *SMTPError) Error() string { return e.Err.Error() }
func (e *SMTPError) Unwrap() error { return e.Err }

// ErrNoSTARTTLS: the server does not offer STARTTLS in starttls mode.
var ErrNoSTARTTLS = errors.New("server does not offer STARTTLS (refusing to send in clear text)")

// session opens an SMTP session up to and including AUTH. TLS modes are
// strict: "starttls" fails when the server does not offer STARTTLS (no
// silent downgrade).
func (s SMTPSender) session(ctx context.Context, cfg SMTPConfig) (*smtp.Client, error) {
	if err := ValidateHost(cfg.Host); err != nil {
		return nil, &SMTPError{"connect", err}
	}
	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
	conn, err := s.dial(ctx, addr)
	if err != nil {
		return nil, &SMTPError{"connect", fmt.Errorf("connect %s: %w", addr, err)}
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	tlsCfg := &tls.Config{ServerName: cfg.Host, MinVersion: tls.VersionTLS12}
	if cfg.TLSMode == "tls" {
		conn = tls.Client(conn, tlsCfg)
	}
	c, err := smtp.NewClient(conn, cfg.Host)
	if err != nil {
		_ = conn.Close()
		return nil, &SMTPError{"greeting", fmt.Errorf("smtp greeting: %w", err)}
	}
	if err := c.Hello("pathos.local"); err != nil {
		_ = c.Close()
		return nil, &SMTPError{"hello", fmt.Errorf("smtp hello: %w", err)}
	}
	if cfg.TLSMode == "starttls" {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			_ = c.Close()
			return nil, &SMTPError{"starttls", ErrNoSTARTTLS}
		}
		if err := c.StartTLS(tlsCfg); err != nil {
			_ = c.Close()
			return nil, &SMTPError{"starttls", fmt.Errorf("starttls: %w", err)}
		}
	}
	if cfg.Username != "" {
		if cfg.TLSMode == "none" {
			_ = c.Close()
			return nil, &SMTPError{"auth", errors.New("refusing to send SMTP credentials without TLS")}
		}
		if err := c.Auth(smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)); err != nil {
			_ = c.Close()
			return nil, &SMTPError{"auth", fmt.Errorf("smtp auth: %w", err)}
		}
	}
	return c, nil
}

// Probe checks the relay without sending a message: connect, EHLO,
// STARTTLS or implicit TLS, AUTH when credentials are set, then QUIT.
func (s SMTPSender) Probe(ctx context.Context, cfg SMTPConfig) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	c, err := s.session(ctx, cfg)
	if err != nil {
		return err
	}
	defer c.Close()
	_ = c.Quit()
	return nil
}

// Send delivers one message.
func (s SMTPSender) Send(ctx context.Context, cfg SMTPConfig, m Message) error {
	raw, err := Build(cfg, m, time.Now())
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	c, err := s.session(ctx, cfg)
	if err != nil {
		return err
	}
	defer c.Close()
	if err := c.Mail(cfg.FromAddress); err != nil {
		return &SMTPError{"mail", fmt.Errorf("smtp MAIL FROM: %w", err)}
	}
	if err := c.Rcpt(m.To); err != nil {
		return &SMTPError{"rcpt", fmt.Errorf("smtp RCPT TO: %w", err)}
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("smtp DATA: %w", err)
	}
	if _, err := w.Write(raw); err != nil {
		return fmt.Errorf("smtp write: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("smtp end of data: %w", err)
	}
	_ = c.Quit()
	return nil
}
