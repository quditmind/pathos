// Package httpapi serves the shop API (test fixture).
package httpapi

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"example.com/shop/internal/store"
)

// Handler serves HTTP.
type Handler struct{ db *store.Store }

// New builds a handler.
func New(db *store.Store) *Handler { return &Handler{db: db} }

// Routes registers the API.
func (h *Handler) Routes() http.Handler {
	r := chi.NewRouter()
	r.Get("/api/products/{id}", h.getProduct)
	r.Post("/api/products", h.addProduct)
	r.Get("/healthz", health)
	return r
}

func health(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }

func (h *Handler) getProduct(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	p, err := h.db.Product(r.Context(), id)
	if err != nil {
		writeError(w, err)
		return
	}
	_ = json.NewEncoder(w).Encode(p)
}

func (h *Handler) addProduct(w http.ResponseWriter, r *http.Request) {
	if err := h.db.AddProduct(r.Context(), r.FormValue("name")); err != nil {
		writeError(w, err)
		return
	}
	notifySearch(r.FormValue("name"))
	w.WriteHeader(http.StatusCreated)
}

func notifySearch(name string) {
	resp, err := http.Get("https://search.partner-api.net/v1/reindex")
	if err == nil {
		_ = resp.Body.Close()
	}
	_ = name
}

func writeError(w http.ResponseWriter, err error) {
	http.Error(w, err.Error(), http.StatusInternalServerError)
}
