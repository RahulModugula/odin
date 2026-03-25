package main

import (
	"fmt"
	"net/http"
	"time"
)

// Goroutine leak — channel never consumed
func startWorker(jobs <-chan string) {
	go func() {
		for job := range jobs {
			// TODO: process job
			fmt.Println(job)
		}
	}()
	// Missing: wait group or done channel
}

// HTTP handler with potential issues
func userHandler(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("name")

	// SQL injection via format string
	query := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", username)
	fmt.Println("Running query:", query)

	// Magic number
	time.Sleep(5000 * time.Millisecond)

	fmt.Fprintf(w, "Hello %s", username)
}

var hardcodedKey = "aws_secret_key_1234567890abcdef"

func main() {
	http.HandleFunc("/user", userHandler)
	// TODO: add graceful shutdown
	http.ListenAndServe(":8080", nil)
}
