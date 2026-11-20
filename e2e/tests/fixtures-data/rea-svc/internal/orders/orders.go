// Package orders is test data for the reverse-engineering e2e test.
package orders

import (
	"encoding/json"
	"net/http"
)

// Create is the declared handler of POST /api/orders.
func Create(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "created"})
}
