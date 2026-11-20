// Package store is the shop's PostgreSQL access (test fixture).
package store

import (
	"context"
	"database/sql"

	_ "github.com/lib/pq"
)

// Store wraps the database.
type Store struct{ db *sql.DB }

// Product is a catalogue entry.
type Product struct {
	ID   int64
	Name string
}

// Open connects to PostgreSQL.
func Open(dsn string) (*Store, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}
	return &Store{db: db}, nil
}

// Product loads one product.
func (s *Store) Product(ctx context.Context, id int64) (Product, error) {
	var p Product
	err := s.db.QueryRowContext(ctx, "SELECT id, name FROM products WHERE id = $1", id).Scan(&p.ID, &p.Name)
	return p, err
}

// AddProduct inserts a product.
func (s *Store) AddProduct(ctx context.Context, name string) error {
	_, err := s.db.ExecContext(ctx, "INSERT INTO products (name) VALUES ($1)", name)
	return s.audit(ctx, err)
}

func (s *Store) audit(ctx context.Context, err error) error {
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, "INSERT INTO audit_log (event) VALUES ('product_added')")
	return err
}
