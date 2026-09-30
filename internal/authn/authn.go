package authn

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const maxJWKSBytes = 1 << 20

var (
	// ErrInvalidCredential означает, что credential отсутствует или не прошёл проверку.
	ErrInvalidCredential = errors.New("invalid credential")
	// ErrUnavailable означает, что доверенный источник ключей временно недоступен.
	ErrUnavailable = errors.New("authentication unavailable")
)

// Principal содержит идентичность, подтверждённую подписью доверенного issuer.
type Principal struct {
	Type string
	ID   string
}

// Verifier проверяет access token и возвращает доверенный principal.
type Verifier interface {
	Verify(context.Context, string) (Principal, error)
}

// JWTVerifier проверяет JWT и получает RSA public key из JWKS cache.
type JWTVerifier struct {
	issuer   string
	audience string
	leeway   time.Duration
	keys     *JWKSCache
}

// NewJWTVerifier создаёт verifier со строгим алгоритмом RS256.
func NewJWTVerifier(issuer, audience string, leeway time.Duration, keys *JWKSCache) *JWTVerifier {
	return &JWTVerifier{issuer: issuer, audience: audience, leeway: leeway, keys: keys}
}

// Verify проверяет структуру, подпись и обязательные claims JWT.
func (v *JWTVerifier) Verify(ctx context.Context, raw string) (Principal, error) {
	claims := &jwt.RegisteredClaims{}
	token, err := jwt.ParseWithClaims(raw, claims, func(token *jwt.Token) (any, error) {
		if token.Method.Alg() != jwt.SigningMethodRS256.Alg() {
			return nil, ErrInvalidCredential
		}
		kid, ok := token.Header["kid"].(string)
		if !ok || kid == "" {
			return nil, ErrInvalidCredential
		}
		return v.keys.Key(ctx, kid)
	}, jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}), jwt.WithIssuer(v.issuer),
		jwt.WithAudience(v.audience), jwt.WithExpirationRequired(), jwt.WithLeeway(v.leeway))
	if err != nil || !token.Valid || claims.Subject == "" {
		if errors.Is(err, ErrUnavailable) {
			return Principal{}, ErrUnavailable
		}
		return Principal{}, ErrInvalidCredential
	}
	return Principal{Type: "user", ID: claims.Subject}, nil
}

// JWKSCache загружает и кеширует проверенные RSA keys; stale keys никогда не возвращаются.
type JWKSCache struct {
	url    string
	client *http.Client
	ttl    time.Duration
	now    func() time.Time

	mu      sync.Mutex
	keys    map[string]*rsa.PublicKey
	expires time.Time
	loading chan struct{}
}

// NewJWKSCache создаёт cache с ограниченными HTTP timeout и TTL.
func NewJWKSCache(url string, client *http.Client, ttl time.Duration) *JWKSCache {
	return &JWKSCache{url: url, client: client, ttl: ttl, now: time.Now}
}

// Key возвращает непросроченный key и один раз обновляет JWKS при неизвестном kid.
func (c *JWKSCache) Key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	keys, fresh, err := c.currentOrLoad(ctx, false)
	if err != nil {
		return nil, err
	}
	if key := keys[kid]; key != nil {
		return key, nil
	}
	if fresh {
		keys, _, err = c.currentOrLoad(ctx, true)
		if err != nil {
			return nil, err
		}
		if key := keys[kid]; key != nil {
			return key, nil
		}
	}
	return nil, ErrInvalidCredential
}

// currentOrLoad координирует единственную загрузку для параллельных callers.
func (c *JWKSCache) currentOrLoad(ctx context.Context, force bool) (map[string]*rsa.PublicKey, bool, error) {
	for {
		c.mu.Lock()
		if !force && c.keys != nil && c.now().Before(c.expires) {
			keys := c.keys
			c.mu.Unlock()
			return keys, true, nil
		}
		if pending := c.loading; pending != nil {
			c.mu.Unlock()
			select {
			case <-ctx.Done():
				return nil, false, ErrUnavailable
			case <-pending:
				force = false
				continue
			}
		}
		c.loading = make(chan struct{})
		pending := c.loading
		c.mu.Unlock()

		keys, err := c.fetch(ctx)
		c.mu.Lock()
		if err == nil {
			c.keys = keys
			c.expires = c.now().Add(c.ttl)
		}
		close(pending)
		c.loading = nil
		c.mu.Unlock()
		if err != nil {
			return nil, false, ErrUnavailable
		}
		return keys, false, nil
	}
}

// fetch скачивает и строго разбирает ограниченный JWKS document.
func (c *JWKSCache) fetch(ctx context.Context) (map[string]*rsa.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected JWKS status: %d", resp.StatusCode)
	}
	decoder := json.NewDecoder(io.LimitReader(resp.Body, maxJWKSBytes+1))
	decoder.DisallowUnknownFields()
	var set jwkSet
	if err := decoder.Decode(&set); err != nil || len(set.Keys) == 0 || len(set.Keys) > 100 {
		return nil, errors.New("invalid JWKS document")
	}
	keys := make(map[string]*rsa.PublicKey, len(set.Keys))
	for _, item := range set.Keys {
		if item.Kty != "RSA" || item.Alg != "RS256" || item.Kid == "" || (item.Use != "" && item.Use != "sig") {
			return nil, errors.New("unsupported JWK")
		}
		if _, exists := keys[item.Kid]; exists {
			return nil, errors.New("duplicate JWK kid")
		}
		key, err := parseRSAKey(item.N, item.E)
		if err != nil {
			return nil, err
		}
		keys[item.Kid] = key
	}
	return keys, nil
}

type jwkSet struct {
	Keys []jwk `json:"keys"`
}

type jwk struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// parseRSAKey преобразует base64url modulus и exponent в RSA public key.
func parseRSAKey(modulus, exponent string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(modulus)
	if err != nil || len(nBytes) < 256 {
		return nil, errors.New("invalid RSA modulus")
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(exponent)
	if err != nil || len(eBytes) == 0 || len(eBytes) > 4 {
		return nil, errors.New("invalid RSA exponent")
	}
	e := 0
	for _, value := range eBytes {
		e = e<<8 | int(value)
	}
	if e < 3 || e%2 == 0 {
		return nil, errors.New("invalid RSA exponent")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: e}, nil
}
