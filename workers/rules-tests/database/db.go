// Test fixture for workers/rules/pathos-database.yml (Go). Not compiled.
package fixture

import (
	"database/sql"
	"fmt"
	"net/http"

	"go.mongodb.org/mongo-driver/bson"
	"gorm.io/gorm"
)

// ruleid: pathos.database.connection-string-hardcoded-password
const dsn = "postgres://app:fixture-pg-pass-not-real@db.internal:5432/app?sslmode=verify-full"

// ruleid: pathos.database.connection-string-tls-disabled
const dsnInsecure = "host=db.internal user=app dbname=app sslmode=disable"

func handler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		// ruleid: pathos.database.go.sql-string-concatenation
		rows, _ := db.Query("SELECT * FROM users WHERE name = '" + name + "'")
		// ruleid: pathos.database.go.sql-string-concatenation
		_, _ = db.ExecContext(r.Context(), "DELETE FROM users WHERE name = '"+r.FormValue("user")+"'")
		// ok: pathos.database.go.sql-string-concatenation
		rows2, _ := db.Query("SELECT * FROM users WHERE name = $1", name)
		where := "deleted_at IS NULL"
		// ok: pathos.database.go.sql-string-concatenation
		rows3, _ := db.Query("SELECT * FROM users WHERE " + where)
		_, _, _ = rows, rows2, rows3
	}
}

func gormQueries(db *gorm.DB, name, order string) {
	var users []string
	// ruleid: pathos.database.go.gorm-raw-sql
	db.Raw(fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name)).Scan(&users)
	// ruleid: pathos.database.go.gorm-raw-sql
	db.Where("name = '" + name + "'").Find(&users)
	// ruleid: pathos.database.go.gorm-raw-sql
	db.Order(fmt.Sprintf("%s DESC", order)).Find(&users)
	// ok: pathos.database.go.gorm-raw-sql
	db.Where("name = ?", name).Find(&users)
}

func mongoQueries(expr string) {
	// ruleid: pathos.database.go.nosql-injection
	f := bson.M{"$where": "this.owner == '" + expr + "'"}
	// ok: pathos.database.go.nosql-injection
	g := bson.M{"$where": "this.active == true"}
	_, _ = f, g
}
