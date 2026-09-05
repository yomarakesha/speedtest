// Command audit-svc runs the audit engine (internal/audit) as a standalone
// HTTP microservice, called by the Python orchestrator's /jobs/audit route.
package main

import (
	"log"
	"net/http"
	"os"

	"speedtest/internal/svcaudit"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8081"
	}
	log.Printf("audit-svc listening on :%s", port)
	if err := http.ListenAndServe(":"+port, svcaudit.Handler()); err != nil {
		log.Fatal(err)
	}
}
