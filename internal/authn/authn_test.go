package authn

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// TestJWTVerifier проверяет доверенное извлечение subject и основные причины отказа.
func TestJWTVerifier(t *testing.T) {
	t.Log("Сценарий: только корректно подписанный RS256 JWT с ожидаемыми claims создаёт principal")
	privateKey := testRSAKey(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeTestJWKS(t, w, "key-1", &privateKey.PublicKey)
	}))
	defer server.Close()
	verifier := NewJWTVerifier("https://issuer.example", "aegispolicy", 0,
		NewJWKSCache(server.URL, server.Client(), time.Minute))
	now := time.Now()

	tests := []struct {
		name    string
		claims  jwt.RegisteredClaims
		method  jwt.SigningMethod
		wantErr error
	}{
		{name: "валидный token", claims: testClaims(now), method: jwt.SigningMethodRS256},
		{name: "неверный issuer", claims: claimsWith(now, "https://attacker.example", "aegispolicy", "ivan"), method: jwt.SigningMethodRS256, wantErr: ErrInvalidCredential},
		{name: "неверная audience", claims: claimsWith(now, "https://issuer.example", "other", "ivan"), method: jwt.SigningMethodRS256, wantErr: ErrInvalidCredential},
		{name: "пустой subject", claims: claimsWith(now, "https://issuer.example", "aegispolicy", ""), method: jwt.SigningMethodRS256, wantErr: ErrInvalidCredential},
		{name: "истёкший token", claims: claimsWithExpiry(now.Add(-time.Minute), "ivan"), method: jwt.SigningMethodRS256, wantErr: ErrInvalidCredential},
		{name: "запрещённый алгоритм", claims: testClaims(now), method: jwt.SigningMethodRS384, wantErr: ErrInvalidCredential},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := signTestToken(t, privateKey, tt.method, "key-1", tt.claims)
			principal, err := verifier.Verify(context.Background(), raw)
			if tt.wantErr != nil {
				if err != tt.wantErr {
					t.Fatalf("ошибка=%v, ожидалась %v", err, tt.wantErr)
				}
				return
			}
			if err != nil || principal.ID != "ivan" || principal.Type != "user" {
				t.Fatalf("principal=%+v error=%v", principal, err)
			}
		})
	}
}

// TestJWTVerifierRejectsSignatureAndHeaderFailures проверяет cryptographic и temporal edge cases.
func TestJWTVerifierRejectsSignatureAndHeaderFailures(t *testing.T) {
	t.Log("Сценарий: verifier отклоняет чужую подпись, missing kid и слишком ранний token, учитывая только разрешённый skew")
	trusted := testRSAKey(t)
	attacker := testRSAKey(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeTestJWKS(t, w, "key-1", &trusted.PublicKey)
	}))
	defer server.Close()
	cache := NewJWKSCache(server.URL, server.Client(), time.Minute)
	now := time.Now()

	t.Run("чужая signature", func(t *testing.T) {
		raw := signTestToken(t, attacker, jwt.SigningMethodRS256, "key-1", testClaims(now))
		if _, err := NewJWTVerifier("https://issuer.example", "aegispolicy", 0, cache).Verify(context.Background(), raw); err != ErrInvalidCredential {
			t.Fatalf("ошибка=%v", err)
		}
	})
	t.Run("отсутствует kid", func(t *testing.T) {
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, testClaims(now))
		raw, err := token.SignedString(trusted)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := NewJWTVerifier("https://issuer.example", "aegispolicy", 0, cache).Verify(context.Background(), raw); err != ErrInvalidCredential {
			t.Fatalf("ошибка=%v", err)
		}
	})
	t.Run("algorithm none запрещён allowlist", func(t *testing.T) {
		token := jwt.NewWithClaims(jwt.SigningMethodNone, testClaims(now))
		token.Header["kid"] = "key-1"
		raw, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := NewJWTVerifier("https://issuer.example", "aegispolicy", 0, cache).Verify(context.Background(), raw); err != ErrInvalidCredential {
			t.Fatalf("ошибка=%v", err)
		}
	})
	t.Run("roles и scopes не становятся permissions principal", func(t *testing.T) {
		claims := jwt.MapClaims{"iss": "https://issuer.example", "aud": "aegispolicy", "sub": "ivan",
			"exp": now.Add(time.Minute).Unix(), "nbf": now.Add(-time.Second).Unix(),
			"roles": []string{"ADMIN"}, "scope": "everything"}
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		token.Header["kid"] = "key-1"
		raw, err := token.SignedString(trusted)
		if err != nil {
			t.Fatal(err)
		}
		principal, err := NewJWTVerifier("https://issuer.example", "aegispolicy", 0, cache).Verify(context.Background(), raw)
		if err != nil || principal != (Principal{Type: "user", ID: "ivan"}) {
			t.Fatalf("principal=%+v error=%v", principal, err)
		}
	})
	t.Run("not-before за пределами skew", func(t *testing.T) {
		claims := testClaims(now)
		claims.NotBefore = jwt.NewNumericDate(now.Add(20 * time.Second))
		raw := signTestToken(t, trusted, jwt.SigningMethodRS256, "key-1", claims)
		if _, err := NewJWTVerifier("https://issuer.example", "aegispolicy", 5*time.Second, cache).Verify(context.Background(), raw); err != ErrInvalidCredential {
			t.Fatalf("ошибка=%v", err)
		}
		if principal, err := NewJWTVerifier("https://issuer.example", "aegispolicy", 30*time.Second, cache).Verify(context.Background(), raw); err != nil || principal.ID != "ivan" {
			t.Fatalf("principal=%+v error=%v", principal, err)
		}
	})
	t.Run("JWKS outage классифицируется как unavailable", func(t *testing.T) {
		unavailable := NewJWKSCache("http://127.0.0.1:1/jwks", &http.Client{Timeout: time.Millisecond}, time.Minute)
		raw := signTestToken(t, trusted, jwt.SigningMethodRS256, "key-1", testClaims(now))
		if _, err := NewJWTVerifier("https://issuer.example", "aegispolicy", 0, unavailable).Verify(context.Background(), raw); err != ErrUnavailable {
			t.Fatalf("ошибка=%v", err)
		}
	})
}

// TestJWKSCacheFailsClosedAfterExpiry проверяет запрет stale key при сбое обновления.
func TestJWKSCacheFailsClosedAfterExpiry(t *testing.T) {
	t.Log("Сценарий: после TTL недоступный JWKS приводит к fail-closed вместо использования старого key")
	privateKey := testRSAKey(t)
	var available atomic.Bool
	available.Store(true)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if !available.Load() {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		writeTestJWKS(t, w, "key-1", &privateKey.PublicKey)
	}))
	defer server.Close()
	cache := NewJWKSCache(server.URL, server.Client(), time.Millisecond)
	if _, err := cache.Key(context.Background(), "key-1"); err != nil {
		t.Fatalf("первичная загрузка: %v", err)
	}
	time.Sleep(2 * time.Millisecond)
	available.Store(false)
	if _, err := cache.Key(context.Background(), "key-1"); err != ErrUnavailable {
		t.Fatalf("ошибка=%v, ожидалась %v", err, ErrUnavailable)
	}
}

// TestJWKSCacheRefreshesUnknownKey проверяет ротацию key до завершения TTL.
func TestJWKSCacheRefreshesUnknownKey(t *testing.T) {
	t.Log("Сценарий: неизвестный kid инициирует одно обновление JWKS и принимает новый key")
	first := testRSAKey(t)
	second := testRSAKey(t)
	var rotated atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if rotated.Load() {
			writeTestJWKS(t, w, "key-2", &second.PublicKey)
			return
		}
		writeTestJWKS(t, w, "key-1", &first.PublicKey)
	}))
	defer server.Close()
	cache := NewJWKSCache(server.URL, server.Client(), time.Minute)
	if _, err := cache.Key(context.Background(), "key-1"); err != nil {
		t.Fatalf("первичная загрузка: %v", err)
	}
	rotated.Store(true)
	if _, err := cache.Key(context.Background(), "key-2"); err != nil {
		t.Fatalf("обновление после ротации: %v", err)
	}
}

// TestJWKSCacheRejectsMalformedDocuments проверяет bounded parser и ограничения допустимых keys.
func TestJWKSCacheRejectsMalformedDocuments(t *testing.T) {
	t.Log("Сценарий: пустой, неоднозначный или неподдерживаемый JWKS никогда не становится trusted key set")
	validKey := testRSAKey(t)
	n := base64.RawURLEncoding.EncodeToString(validKey.PublicKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(validKey.PublicKey.E)).Bytes())
	tests := []struct {
		name   string
		status int
		body   string
	}{
		{name: "HTTP error", status: http.StatusServiceUnavailable, body: `{}`},
		{name: "повреждённый JSON", status: http.StatusOK, body: `{`},
		{name: "пустой key set", status: http.StatusOK, body: `{"keys":[]}`},
		{name: "неизвестное поле", status: http.StatusOK, body: `{"keys":[],"extra":true}`},
		{name: "неподдерживаемый key type", status: http.StatusOK, body: `{"keys":[{"kty":"EC","use":"sig","kid":"a","alg":"RS256","n":"` + n + `","e":"` + e + `"}]}`},
		{name: "неверное key use", status: http.StatusOK, body: `{"keys":[{"kty":"RSA","use":"enc","kid":"a","alg":"RS256","n":"` + n + `","e":"` + e + `"}]}`},
		{name: "дублирующийся kid", status: http.StatusOK, body: `{"keys":[{"kty":"RSA","use":"sig","kid":"a","alg":"RS256","n":"` + n + `","e":"` + e + `"},{"kty":"RSA","use":"sig","kid":"a","alg":"RS256","n":"` + n + `","e":"` + e + `"}]}`},
		{name: "короткий modulus", status: http.StatusOK, body: `{"keys":[{"kty":"RSA","use":"sig","kid":"a","alg":"RS256","n":"AQ","e":"` + e + `"}]}`},
		{name: "чётный exponent", status: http.StatusOK, body: `{"keys":[{"kty":"RSA","use":"sig","kid":"a","alg":"RS256","n":"` + n + `","e":"BA"}]}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer server.Close()
			if _, err := NewJWKSCache(server.URL, server.Client(), time.Minute).Key(context.Background(), "a"); err != ErrUnavailable {
				t.Fatalf("ошибка=%v", err)
			}
		})
	}
	if _, err := NewJWKSCache(":bad-url", http.DefaultClient, time.Minute).Key(context.Background(), "a"); err != ErrUnavailable {
		t.Fatalf("неверный URL должен быть unavailable: %v", err)
	}
}

// TestJWKSCacheCoalescesConcurrentRefresh проверяет защиту источника ключей от amplification.
func TestJWKSCacheCoalescesConcurrentRefresh(t *testing.T) {
	t.Log("Сценарий: параллельные запросы нового kid объединяются в одну JWKS refresh")
	first := testRSAKey(t)
	second := testRSAKey(t)
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		call := calls.Add(1)
		if call == 1 {
			writeTestJWKS(t, w, "key-1", &first.PublicKey)
			return
		}
		time.Sleep(20 * time.Millisecond)
		writeTestJWKS(t, w, "key-2", &second.PublicKey)
	}))
	defer server.Close()
	cache := NewJWKSCache(server.URL, server.Client(), time.Minute)
	if _, err := cache.Key(context.Background(), "key-1"); err != nil {
		t.Fatal(err)
	}

	const workers = 12
	start := make(chan struct{})
	errors := make(chan error, workers)
	var group sync.WaitGroup
	for range workers {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			_, err := cache.Key(context.Background(), "key-2")
			errors <- err
		}()
	}
	close(start)
	group.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatalf("refresh error: %v", err)
		}
	}
	if calls.Load() != 2 {
		t.Fatalf("JWKS вызван %d раз вместо 2", calls.Load())
	}
}

// TestJWKSCacheWaitHonorsContext проверяет cancellation ожидающего concurrent caller.
func TestJWKSCacheWaitHonorsContext(t *testing.T) {
	t.Log("Сценарий: caller прекращает ожидание общей JWKS загрузки после отмены context")
	started := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(started)
		<-release
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	defer server.Close()
	cache := NewJWKSCache(server.URL, server.Client(), time.Minute)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = cache.Key(context.Background(), "key")
	}()
	<-started
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := cache.Key(ctx, "key"); err != ErrUnavailable {
		t.Fatalf("ошибка=%v", err)
	}
	close(release)
	<-done
}

// TestJWKSCacheHonorsHTTPTimeout проверяет ограничение времени обращения к key source.
func TestJWKSCacheHonorsHTTPTimeout(t *testing.T) {
	t.Log("Сценарий: медленный JWKS endpoint прерывается HTTP timeout и закрывает authentication")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(50 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	client := server.Client()
	client.Timeout = time.Millisecond
	if _, err := NewJWKSCache(server.URL, client, time.Minute).Key(context.Background(), "key"); err != ErrUnavailable {
		t.Fatalf("ошибка=%v", err)
	}
}

func testClaims(now time.Time) jwt.RegisteredClaims {
	return claimsWith(now, "https://issuer.example", "aegispolicy", "ivan")
}

func claimsWith(now time.Time, issuer, audience, subject string) jwt.RegisteredClaims {
	return jwt.RegisteredClaims{Issuer: issuer, Subject: subject, Audience: jwt.ClaimStrings{audience},
		ExpiresAt: jwt.NewNumericDate(now.Add(time.Minute)), NotBefore: jwt.NewNumericDate(now.Add(-time.Second))}
}

func claimsWithExpiry(expiry time.Time, subject string) jwt.RegisteredClaims {
	claims := claimsWith(time.Now(), "https://issuer.example", "aegispolicy", subject)
	claims.ExpiresAt = jwt.NewNumericDate(expiry)
	return claims
}

func signTestToken(t *testing.T, key *rsa.PrivateKey, method jwt.SigningMethod, kid string, claims jwt.RegisteredClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(method, claims)
	token.Header["kid"] = kid
	raw, err := token.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func testRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func writeTestJWKS(t *testing.T, w http.ResponseWriter, kid string, key *rsa.PublicKey) {
	t.Helper()
	e := big.NewInt(int64(key.E)).Bytes()
	set := jwkSet{Keys: []jwk{{Kty: "RSA", Use: "sig", Kid: kid, Alg: "RS256",
		N: base64.RawURLEncoding.EncodeToString(key.N.Bytes()), E: base64.RawURLEncoding.EncodeToString(e)}}}
	if err := json.NewEncoder(w).Encode(set); err != nil {
		t.Fatal(err)
	}
}
