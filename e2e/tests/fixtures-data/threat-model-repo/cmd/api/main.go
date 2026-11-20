// Example shop API (test fixture for pathos-graph; not built or run).
package main

import (
	"log"
	"net/http"
	"os"

	"example.com/shop/internal/httpapi"
	"example.com/shop/internal/store"
)

func main() {
	db, err := store.Open(os.Getenv("DATABASE_URL"))
	if err != nil {
		log.Fatal(err)
	}
	h := httpapi.New(db)
	log.Fatal(http.ListenAndServe(":8080", h.Routes()))
}
