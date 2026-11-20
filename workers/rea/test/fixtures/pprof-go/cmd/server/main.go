// Test fixture for pathos-rea (not shipped): a service whose declared API
// is /api/orders, built with a blank import of net/http/pprof that also
// registers /debug/pprof/* handlers on the default mux.
package main

import (
	"encoding/json"
	"log"
	"net/http"
	_ "net/http/pprof" // registers handlers on DefaultServeMux
)

// CreateOrder is the service's declared handler.
func CreateOrder(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "created"})
}

func main() {
	http.HandleFunc("/api/orders", CreateOrder)
	log.Fatal(http.ListenAndServe("127.0.0.1:8080", nil))
}
