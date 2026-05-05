package main

import (
	"fmt"
	"log"
	"net/http"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "<html><body><h1>OK</h1><p>Path: %s</p></body></html>", r.URL.Path)
	})
	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"invalid credentials"}`)
		} else {
			fmt.Fprint(w, `<html><form method="post"><input name="user"/></form></html>`)
		}
	})
	http.HandleFunc("/upload", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"status":"uploaded"}`)
	})
	http.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><body><h1>Search</h1></body></html>`)
	})
	http.HandleFunc("/comment", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"status":"posted"}`)
	})
	http.HandleFunc("/contact", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"status":"received"}`)
	})

	fmt.Println("Mock backend listening on :18081")
	log.Fatal(http.ListenAndServe(":18081", nil))
}
