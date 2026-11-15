package logging

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestRedactsSensitiveKeys(t *testing.T) {
	var buf bytes.Buffer
	log := New(&buf, "info")
	log.Info("x", "password", "hunter2", "client_secret", "abc", "Authorization", "Basic Zm9v", "user", "alice")
	out := buf.String()
	for _, leaked := range []string{"hunter2", "abc\"", "Zm9v"} {
		if strings.Contains(out, leaked) {
			t.Errorf("leaked %q in %s", leaked, out)
		}
	}
	if !strings.Contains(out, "alice") {
		t.Errorf("non-sensitive value was removed: %s", out)
	}
}

func TestRedactsTokenShapedValues(t *testing.T) {
	cases := []string{
		"Bearer abcdefghijklmnop",
		"eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlLXZhbHVl",
		"ghp_abcdefghijklmnopqrstuvwxyz0123",
		"sk-ant-api03-abcdefghijklmnopqrstuvwxyz",
		"AKIAABCDEFGHIJKLMNOP",
		"postgres://pathos:supersecret@postgres:5432/pathos",
	}
	for _, c := range cases {
		var buf bytes.Buffer
		New(&buf, "info").Info("msg", "detail", "prefix "+c+" suffix")
		if strings.Contains(buf.String(), c) {
			t.Errorf("value not redacted: %s", buf.String())
		}
		if !strings.Contains(buf.String(), Redacted) {
			t.Errorf("missing redaction marker: %s", buf.String())
		}
	}
}

func TestRedactsErrors(t *testing.T) {
	var buf bytes.Buffer
	New(&buf, "info").Error("db failed", "err", errors.New("dial postgres://u:pw123@db/x failed"))
	if strings.Contains(buf.String(), "pw123") {
		t.Errorf("error value leaked credentials: %s", buf.String())
	}
}

func TestLevelFiltering(t *testing.T) {
	var buf bytes.Buffer
	New(&buf, "warn").Info("hidden")
	if buf.Len() != 0 {
		t.Errorf("info should be filtered at warn level")
	}
}
