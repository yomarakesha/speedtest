// Command scan-svc runs the port-scan/discovery engine (internal/portscan) as
// a standalone HTTP microservice, called by the Python orchestrator.
package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"speedtest/internal/svcscan"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8082"
	}
	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           svcscan.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      3 * time.Minute, // /discover sweeps a whole subnet
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	log.Printf("scan-svc listening on :%s", port)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
