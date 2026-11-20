// Test fixture for the PATHOS graph rules (example code, not executed).
package server

import (
	"context"
	"database/sql"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-chi/chi/v5"
	"github.com/redis/go-redis/v9"
	amqp "github.com/rabbitmq/amqp091-go"
)

func routes(db *sql.DB, rdb *redis.Client, ch *amqp.Channel) {
	mux := http.NewServeMux()
	// ruleid: pathos-graph-go-route-nethttp
	mux.HandleFunc("GET /health", health)
	// ruleid: pathos-graph-go-route-nethttp
	http.Handle("/metrics", nil)
	r := chi.NewRouter()
	// The gin/echo/fiber rule also matches chi's Get; the graph worker keeps
	// the match of the framework the file imports (requires_import).
	// ruleid: pathos-graph-go-route-chi, pathos-graph-go-route-gin-echo
	r.Get("/users/{id}", getUser)
	// ruleid: pathos-graph-go-route-chi, pathos-graph-go-route-gin-echo
	r.Post("/users", createUser)
	g := gin.Default()
	// ruleid: pathos-graph-go-route-gin-echo
	g.GET("/items/:id", auth, getItem)
	// ok: pathos-graph-go-route-gin-echo
	g.Use(auth)
	ctx := context.Background()
	// ruleid: pathos-graph-go-db-sql-read
	db.QueryContext(ctx, "SELECT id, name FROM users WHERE id = $1", 1)
	// ruleid: pathos-graph-go-db-sql-write
	db.Exec(`UPDATE users SET name = $1`, "x")
	// ok: pathos-graph-go-db-sql-read, pathos-graph-go-db-sql-write
	db.Exec(buildQuery())
	// ruleid: pathos-graph-go-db-redis
	rdb.Get(ctx, "session")
	// ruleid: pathos-graph-go-queue-amqp
	ch.PublishWithContext(ctx, "", "orders", false, false, amqp.Publishing{})
	// ruleid: pathos-graph-go-queue-amqp-consume
	ch.Consume("orders", "", true, false, false, false, nil)
	// ruleid: pathos-graph-go-http-call
	http.Get("https://api.payments.example.net/v1/charges")
	// ok: pathos-graph-go-http-call
	http.Get(baseURL + "/x")
}
