package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newTestServer(t *testing.T) *Server {
	t.Helper()
	now := time.Now().UTC()

	ks, err := NewKeyStore([]KeySpec{
		{Kid: "active-key-1", ExpiresAt: now.Add(1 * time.Hour)},
		{Kid: "expired-key-1", ExpiresAt: now.Add(-1 * time.Hour)},
	})
	if err != nil {
		t.Fatal(err)
	}
	return NewServer(ks)
}

func TestJWKSOnlyReturnsUnexpired(t *testing.T) {
	s := newTestServer(t)
	ts := httptest.NewServer(s.Router())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/.well-known/jwks.json")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var jwks JWKS
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		t.Fatal(err)
	}

	if len(jwks.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(jwks.Keys))
	}
	if jwks.Keys[0].Kid != "active-key-1" {
		t.Fatalf("expected active-key-1, got %s", jwks.Keys[0].Kid)
	}
}

func TestAuthReturnsJWT(t *testing.T) {
	s := newTestServer(t)
	ts := httptest.NewServer(s.Router())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/auth", "text/plain", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	b, _ := io.ReadAll(resp.Body)
	token := string(b)

	// Basic sanity: JWT has 3 dot-separated parts
	if len(token) < 20 || countDots(token) != 2 {
		t.Fatalf("expected JWT, got: %q", token)
	}
}

func TestAuthExpiredReturnsExpiredKidJWT(t *testing.T) {
	s := newTestServer(t)
	ts := httptest.NewServer(s.Router())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/auth?expired=true", "text/plain", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	b, _ := io.ReadAll(resp.Body)
	token := string(b)

	_, _, kid, err := ParseJWTParts(token)
	if err != nil {
		t.Fatal(err)
	}
	if kid != "expired-key-1" {
		t.Fatalf("expected expired-key-1, got %s", kid)
	}
}

func TestMethodGuards(t *testing.T) {
	s := newTestServer(t)
	ts := httptest.NewServer(s.Router())
	defer ts.Close()

	// JWKS should reject POST
	resp, _ := http.Post(ts.URL+"/.well-known/jwks.json", "text/plain", nil)
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", resp.StatusCode)
	}

	// Auth should reject GET
	resp2, _ := http.Get(ts.URL + "/auth")
	if resp2.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", resp2.StatusCode)
	}
}

func countDots(s string) int {
	n := 0
	for _, ch := range s {
		if ch == '.' {
			n++
		}
	}
	return n
}
