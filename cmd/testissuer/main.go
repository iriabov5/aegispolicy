package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"log"
	"math/big"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	issuer   = "http://test-issuer:8090"
	audience = "aegispolicy"
	kid      = "development-key"
)

// main создаёт ephemeral RSA key и запускает локальные JWKS/token endpoints.
func main() {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
	server := &http.Server{Addr: ":8090", Handler: newHandler(key, time.Now), ReadHeaderTimeout: 2 * time.Second}
	log.Fatal(server.ListenAndServe())
}

// newHandler собирает development endpoints вокруг переданного ephemeral signing key.
func newHandler(key *rsa.PrivateKey, now func() time.Time) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		exponent := big.NewInt(int64(key.PublicKey.E)).Bytes()
		writeJSON(w, map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "use": "sig", "kid": kid, "alg": "RS256",
			"n": base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(exponent),
		}}})
	})
	mux.HandleFunc("GET /token", func(w http.ResponseWriter, r *http.Request) {
		subject := r.URL.Query().Get("sub")
		if subject == "" || len(subject) > 128 {
			http.Error(w, "sub is required", http.StatusBadRequest)
			return
		}
		tokenAudience := audience
		if requested := r.URL.Query().Get("aud"); requested != "" {
			tokenAudience = requested
		}
		expiresIn := 5 * time.Minute
		if r.URL.Query().Get("expired") == "true" {
			expiresIn = -time.Minute
		}
		tokenKid := kid
		if requested := r.URL.Query().Get("kid"); requested != "" {
			tokenKid = requested
		}
		issuedAt := now()
		claims := jwt.RegisteredClaims{Issuer: issuer, Subject: subject,
			Audience: jwt.ClaimStrings{tokenAudience}, IssuedAt: jwt.NewNumericDate(issuedAt),
			NotBefore: jwt.NewNumericDate(issuedAt.Add(-time.Second)), ExpiresAt: jwt.NewNumericDate(issuedAt.Add(expiresIn))}
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		token.Header["kid"] = tokenKid
		raw, err := token.SignedString(key)
		if err != nil {
			http.Error(w, "cannot sign token", http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]string{"access_token": raw, "token_type": "Bearer", "expires_in": "300"})
	})
	return mux
}

// writeJSON кодирует development response с явным content type.
func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}
