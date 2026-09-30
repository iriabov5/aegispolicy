package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config содержит проверенные параметры process lifecycle и внешних dependencies.
type Config struct {
	HTTPAddress       string
	DatabaseURL       string
	OPAURL            string
	OPATimeout        time.Duration
	ShutdownTimeout   time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	MaxDBConnections  int32
	JWTIssuer         string
	JWTAudience       string
	JWTAlgorithm      string
	JWKSURL           string
	JWTClockSkew      time.Duration
	JWKSTimeout       time.Duration
	JWKSCacheTTL      time.Duration
	AllowInsecureJWKS bool
}

// Load читает environment variables, применяет безопасные defaults и отклоняет неверные значения.
func Load() (Config, error) {
	cfg := Config{
		HTTPAddress:      env("HTTP_ADDRESS", "127.0.0.1:8080"),
		DatabaseURL:      os.Getenv("DATABASE_URL"),
		OPAURL:           env("OPA_URL", "http://127.0.0.1:8181"),
		OPATimeout:       750 * time.Millisecond,
		ShutdownTimeout:  10 * time.Second,
		ReadTimeout:      5 * time.Second,
		WriteTimeout:     5 * time.Second,
		IdleTimeout:      60 * time.Second,
		MaxDBConnections: 10,
		JWTIssuer:        os.Getenv("JWT_ISSUER"),
		JWTAudience:      os.Getenv("JWT_AUDIENCE"),
		JWTAlgorithm:     env("JWT_ALGORITHM", "RS256"),
		JWKSURL:          os.Getenv("JWKS_URL"),
		JWTClockSkew:     30 * time.Second,
		JWKSTimeout:      2 * time.Second,
		JWKSCacheTTL:     5 * time.Minute,
	}
	if cfg.DatabaseURL == "" {
		return Config{}, errors.New("DATABASE_URL is required")
	}
	if cfg.JWTIssuer == "" || cfg.JWTAudience == "" || cfg.JWKSURL == "" {
		return Config{}, errors.New("JWT_ISSUER, JWT_AUDIENCE and JWKS_URL are required")
	}
	if cfg.JWTAlgorithm != "RS256" {
		return Config{}, errors.New("JWT_ALGORITHM must be RS256")
	}
	var err error
	if cfg.JWTClockSkew, err = durationEnv("JWT_CLOCK_SKEW", cfg.JWTClockSkew); err != nil {
		return Config{}, err
	}
	if cfg.JWKSTimeout, err = positiveDurationEnv("JWKS_TIMEOUT", cfg.JWKSTimeout); err != nil {
		return Config{}, err
	}
	if cfg.JWKSCacheTTL, err = positiveDurationEnv("JWKS_CACHE_TTL", cfg.JWKSCacheTTL); err != nil {
		return Config{}, err
	}
	if cfg.AllowInsecureJWKS, err = boolEnv("DEVELOPMENT_ALLOW_INSECURE_JWKS"); err != nil {
		return Config{}, err
	}
	if err := validateJWKSURL(cfg.JWKSURL, cfg.AllowInsecureJWKS); err != nil {
		return Config{}, err
	}
	if value := os.Getenv("MAX_DB_CONNECTIONS"); value != "" {
		n, err := strconv.ParseInt(value, 10, 32)
		if err != nil || n < 1 || n > 100 {
			return Config{}, fmt.Errorf("MAX_DB_CONNECTIONS must be between 1 and 100")
		}
		cfg.MaxDBConnections = int32(n)
	}
	return cfg, nil
}

// durationEnv читает неотрицательную duration из environment variable.
func durationEnv(name string, fallback time.Duration) (time.Duration, error) {
	value := os.Getenv(name)
	if value == "" {
		return fallback, nil
	}
	duration, err := time.ParseDuration(value)
	if err != nil || duration < 0 {
		return 0, fmt.Errorf("%s must be a non-negative duration", name)
	}
	return duration, nil
}

// positiveDurationEnv читает строго положительную duration из environment variable.
func positiveDurationEnv(name string, fallback time.Duration) (time.Duration, error) {
	duration, err := durationEnv(name, fallback)
	if err != nil || duration <= 0 {
		return 0, fmt.Errorf("%s must be a positive duration", name)
	}
	return duration, nil
}

// boolEnv читает необязательное boolean-значение.
func boolEnv(name string) (bool, error) {
	value := os.Getenv(name)
	if value == "" {
		return false, nil
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return false, fmt.Errorf("%s must be boolean", name)
	}
	return parsed, nil
}

// validateJWKSURL разрешает HTTPS, а HTTP — только для loopback development endpoint.
func validateJWKSURL(raw string, allowInsecure bool) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("JWKS_URL must be an absolute URL without credentials, query or fragment")
	}
	if parsed.Scheme == "https" {
		return nil
	}
	if parsed.Scheme == "http" && allowInsecure && isDevelopmentHost(parsed.Hostname()) {
		return nil
	}
	return errors.New("JWKS_URL must use HTTPS; loopback HTTP requires DEVELOPMENT_ALLOW_INSECURE_JWKS=true")
}

// isDevelopmentHost ограничивает небезопасный HTTP локальной машиной или Compose service name.
func isDevelopmentHost(host string) bool {
	host = strings.ToLower(host)
	return host == "localhost" || host == "127.0.0.1" || host == "::1" || host == "test-issuer"
}

// env возвращает непустое значение environment variable либо заданное default value.
func env(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
