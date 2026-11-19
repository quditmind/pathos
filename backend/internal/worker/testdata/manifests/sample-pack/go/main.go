// Deliberately vulnerable sample for the worker-sast fixture tests.
package main

import (
	"crypto/md5"
	"crypto/tls"
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"os/exec"
)

func handler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		rows, _ := db.Query("SELECT * FROM users WHERE name = '" + name + "'")
		defer rows.Close()
		out, _ := exec.Command("sh", "-c", "echo "+name).Output()
		fmt.Fprintf(w, "%s %x", out, md5.Sum([]byte(name)))
	}
}

func fetch(url string) {
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	resp, err := client.Get(url)
	if err != nil {
		return
	}
	fmt.Println(resp.StatusCode)
	os.Remove("/tmp/sample.lock")
}

func main() {
	fetch(os.Args[1])
	http.ListenAndServe(":8080", nil)
}
