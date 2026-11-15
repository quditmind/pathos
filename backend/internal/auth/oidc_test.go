package auth

import "testing"

func TestSafeReturnTo(t *testing.T) {
	cases := map[string]string{
		"":                       "/",
		"/admin/users":           "/admin/users",
		"/admin/users?q=a#x":     "/admin/users?q=a#x",
		"//evil.example/":        "/",
		`/\evil.example`:         "/",
		"https://evil.example/":  "/",
		"javascript:alert(1)":    "/",
		"/ok\r\nSet-Cookie: x=1": "/",
		"/api/auth/logout":       "/",
		"admin":                  "/",
	}
	for in, want := range cases {
		if got := SafeReturnTo(in); got != want {
			t.Errorf("SafeReturnTo(%q) = %q, want %q", in, got, want)
		}
	}
}
