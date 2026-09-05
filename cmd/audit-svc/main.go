// Command audit-svc runs the audit engine (internal/audit) as a standalone
// HTTP microservice, called by the Python orchestrator's /jobs/audit route.
package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"speedtest/internal/svcaudit"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8081"
	}
	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           svcaudit.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      2 * time.Minute, // a full audit runs several sequential network probes
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	log.Printf("audit-svc listening on :%s", port)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
