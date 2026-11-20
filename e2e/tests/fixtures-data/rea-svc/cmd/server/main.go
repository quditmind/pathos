// Test data for the reverse-engineering e2e test (not a real service): the
// declared API is /api/orders, and a blank import of net/http/pprof also
// registers /debug/pprof/* handlers on the default mux.
package main

import (
	"log"
	"net/http"
	_ "net/http/pprof" // registers handlers on DefaultServeMux

	"example.com/payments/internal/orders"
)

func main() {
	http.HandleFunc("/api/orders", orders.Create)
	log.Fatal(http.ListenAndServe("127.0.0.1:8080", nil))
}
