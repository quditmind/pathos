//go:build integration

package integration

import "net/http"

func newMux(register func(*http.ServeMux)) *http.ServeMux {
	m := http.NewServeMux()
	register(m)
	return m
}
