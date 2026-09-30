package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// TestDevelopmentIssuerEndpoints проверяет health, JWKS и варианты выпуска test token.
func TestDevelopmentIssuerEndpoints(t *testing.T) {
	t.Log("Сценарий: development issuer публикует RSA JWKS и управляемые test JWT без сохранения private key")
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.September, 30, 12, 0, 0, 0, time.UTC)
	handler := newHandler(key, func() time.Time { return now })

	t.Run("health сообщает готовность", func(t *testing.T) {
		response := performRequest(handler, "/health")
		if response.Code != http.StatusOK || response.Body.String() != "{\"status\":\"ok\"}\n" {
			t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
		}
	})
	t.Run("JWKS содержит публичную часть signing key", func(t *testing.T) {
		response := performRequest(handler, "/jwks.json")
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"kid":"development-key"`) ||
			!strings.Contains(response.Body.String(), `"alg":"RS256"`) {
			t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
		}
	})
	t.Run("валидный token подписан и содержит ожидаемые claims", func(t *testing.T) {
		claims, header := requestAndParseToken(t, handler, "/token?sub=ivan", &key.PublicKey)
		if claims.Subject != "ivan" || claims.Issuer != issuer || len(claims.Audience) != 1 || claims.Audience[0] != audience {
			t.Fatalf("claims=%+v", claims)
		}
		if header["kid"] != kid || !claims.ExpiresAt.Time.Equal(now.Add(5*time.Minute)) {
			t.Fatalf("header=%v expires=%v", header, claims.ExpiresAt)
		}
	})
	t.Run("параметры создают expired token с другой audience и kid", func(t *testing.T) {
		claims, header := requestAndParseToken(t, handler, "/token?sub=ivan&aud=other&kid=rotated&expired=true", &key.PublicKey)
		if header["kid"] != "rotated" || claims.Audience[0] != "other" || !claims.ExpiresAt.Time.Before(now) {
			t.Fatalf("header=%v claims=%+v", header, claims)
		}
	})
	for _, path := range []string{"/token", "/token?sub=" + strings.Repeat("x", 129)} {
		t.Run("некорректный subject отклоняется "+path, func(t *testing.T) {
			if response := performRequest(handler, path); response.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
}

// performRequest выполняет GET непосредственно через test handler.
func performRequest(handler http.Handler, target string) *httptest.ResponseRecorder {
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, target, nil))
	return response
}

// requestAndParseToken получает JWT, проверяет signature и возвращает claims с header.
func requestAndParseToken(t *testing.T, handler http.Handler, target string, key *rsa.PublicKey) (*jwt.RegisteredClaims, map[string]any) {
	t.Helper()
	response := performRequest(handler, target)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var body struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	claims := &jwt.RegisteredClaims{}
	token, err := jwt.ParseWithClaims(body.AccessToken, claims, func(*jwt.Token) (any, error) { return key, nil },
		jwt.WithoutClaimsValidation(), jwt.WithValidMethods([]string{"RS256"}))
	if err != nil || !token.Valid {
		t.Fatalf("token не прошёл signature validation: %v", err)
	}
	return claims, token.Header
}
