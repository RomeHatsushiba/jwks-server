package server

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

type jwtClaims struct {
	Sub string `json:"sub"`
	Iat int64  `json:"iat"`
	Exp int64  `json:"exp"`
}

func SignJWT_RS256(kid string, priv *rsa.PrivateKey, sub string, iat, exp time.Time) (string, error) {
	h := jwtHeader{Alg: "RS256", Typ: "JWT", Kid: kid}
	c := jwtClaims{Sub: sub, Iat: iat.UTC().Unix(), Exp: exp.UTC().Unix()}

	hb, _ := json.Marshal(h)
	cb, _ := json.Marshal(c)

	enc := base64.RawURLEncoding
	h64 := enc.EncodeToString(hb)
	c64 := enc.EncodeToString(cb)

	signingInput := h64 + "." + c64
	sum := sha256.Sum256([]byte(signingInput))

	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}

	return signingInput + "." + enc.EncodeToString(sig), nil
}

// ParseJWTParts pulls the header+claims JSON and the kid from a JWT without verifying it.
// Useful for tests and debugging.
func ParseJWTParts(token string) (headerJSON, claimsJSON []byte, kid string, err error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, nil, "", errors.New("invalid token format")
	}

	enc := base64.RawURLEncoding

	hb, err := enc.DecodeString(parts[0])
	if err != nil {
		return nil, nil, "", err
	}
	cb, err := enc.DecodeString(parts[1])
	if err != nil {
		return nil, nil, "", err
	}

	var h jwtHeader
	if err := json.Unmarshal(hb, &h); err != nil {
		return nil, nil, "", err
	}

	return hb, cb, h.Kid, nil
}
