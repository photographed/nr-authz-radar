// Go net/http + chi style fixture (source only). Not run.
package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"os/exec"
)

func routes(r chiRouter, db *sql.DB) {
	// IDOR: loads by id from the URL, no owner check
	r.Get("/api/orders/{id}", func(w http.ResponseWriter, req *http.Request) {
		id := req.PathValue("id")
		row := db.QueryRow("SELECT item FROM orders WHERE id = $1", id)
		_ = row
	})

	// SQL injection via fmt.Sprintf
	r.Get("/api/search", func(w http.ResponseWriter, req *http.Request) {
		q := req.URL.Query().Get("q")
		db.Query(fmt.Sprintf("SELECT id FROM orders WHERE item LIKE '%%%s%%'", q))
	})

	// command execution
	r.Post("/api/admin/orders/{id}/ship", func(w http.ResponseWriter, req *http.Request) {
		exec.Command("sh", "-c", "notify "+req.PathValue("id")).Run()
	})
}
