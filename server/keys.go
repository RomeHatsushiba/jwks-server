package server

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"sync"
	"time"
)

type KeySpec struct {
	Kid       string
	ExpiresAt time.Time
}

type KeyPair struct {
	Kid       string
	ExpiresAt time.Time
	Private   *rsa.PrivateKey
	Public    *rsa.PublicKey
}

type KeyStore struct {
	mu   sync.RWMutex
	keys map[string]KeyPair
}

// Creates RSA keys on server startup
func NewKeyStore(specs []KeySpec) (*KeyStore, error) {
	if len(specs) == 0 {
		return nil, errors.New("no key specs provided")
	}

	ks := &KeyStore{
		keys: make(map[string]KeyPair),
	}

	for _, s := range specs {
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}

		ks.keys[s.Kid] = KeyPair{
			Kid:       s.Kid,
			ExpiresAt: s.ExpiresAt.UTC(),
			Private:   priv,
			Public:    &priv.PublicKey,
		}
	}

	return ks, nil
}

// Returns only unexpired keys
func (ks *KeyStore) Unexpired(now time.Time) []KeyPair {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	out := []KeyPair{}
	for _, kp := range ks.keys {
		if kp.ExpiresAt.After(now.UTC()) {
			out = append(out, kp)
		}
	}
	return out
}

// Get any active key
func (ks *KeyStore) ActiveKey(now time.Time) (KeyPair, bool) {
	for _, kp := range ks.Unexpired(now) {
		return kp, true
	}
	return KeyPair{}, false
}

// Get expired key
func (ks *KeyStore) ExpiredKey(now time.Time) (KeyPair, bool) {
	for _, kp := range ks.keys {
		if !kp.ExpiresAt.After(now.UTC()) {
			return kp, true
		}
	}
	return KeyPair{}, false
}
