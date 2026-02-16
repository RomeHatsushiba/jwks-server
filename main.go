package main

import (
	"log"
	"net/http"
	"time"

	"jwks-server/server"
)

func main() {
	now := time.Now().UTC()

	ks, err := server.NewKeyStore([]server.KeySpec{
		{Kid: "active-key-1", ExpiresAt: now.Add(24 * time.Hour)},
		{Kid: "expired-key-1", ExpiresAt: now.Add(-24 * time.Hour)},
	})
	if err != nil {
		log.Fatal(err)
	}

	s := server.NewServer(ks)

	log.Println("Server running on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", s.Router()))
}
