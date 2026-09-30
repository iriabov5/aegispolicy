package config

import "testing"

// TestLoadJWTConfiguration проверяет fail-fast validation authentication settings.
func TestLoadJWTConfiguration(t *testing.T) {
	t.Log("Сценарий: production JWKS требует HTTPS, а algorithm жёстко ограничен RS256")
	setRequiredEnvironment(t)
	cfg, err := Load()
	if err != nil || cfg.JWTAlgorithm != "RS256" {
		t.Fatalf("config=%+v error=%v", cfg, err)
	}

	t.Run("небезопасный algorithm отклоняется", func(t *testing.T) {
		setRequiredEnvironment(t)
		t.Setenv("JWT_ALGORITHM", "HS256")
		if _, err := Load(); err == nil {
			t.Fatal("ожидалась ошибка JWT_ALGORITHM")
		}
	})
	t.Run("HTTP JWKS без development flag отклоняется", func(t *testing.T) {
		setRequiredEnvironment(t)
		t.Setenv("JWKS_URL", "http://localhost:8090/jwks.json")
		if _, err := Load(); err == nil {
			t.Fatal("ожидалась ошибка небезопасного JWKS URL")
		}
	})
	t.Run("loopback HTTP разрешается только для development", func(t *testing.T) {
		setRequiredEnvironment(t)
		t.Setenv("JWKS_URL", "http://127.0.0.1:8090/jwks.json")
		t.Setenv("DEVELOPMENT_ALLOW_INSECURE_JWKS", "true")
		if _, err := Load(); err != nil {
			t.Fatalf("неожиданная ошибка: %v", err)
		}
	})
	t.Run("внешний HTTP запрещён даже с development flag", func(t *testing.T) {
		setRequiredEnvironment(t)
		t.Setenv("JWKS_URL", "http://issuer.example/jwks.json")
		t.Setenv("DEVELOPMENT_ALLOW_INSECURE_JWKS", "true")
		if _, err := Load(); err == nil {
			t.Fatal("ожидалась ошибка внешнего HTTP JWKS")
		}
	})
}

// TestLoadRejectsInvalidEnvironment проверяет все fail-fast ветки operator configuration.
func TestLoadRejectsInvalidEnvironment(t *testing.T) {
	t.Log("Сценарий: отсутствующие обязательные настройки и неверные limits/durations останавливают startup")
	tests := []struct {
		name  string
		key   string
		value string
	}{
		{name: "отсутствует database URL", key: "DATABASE_URL", value: ""},
		{name: "отсутствует issuer", key: "JWT_ISSUER", value: ""},
		{name: "отрицательный clock skew", key: "JWT_CLOCK_SKEW", value: "-1s"},
		{name: "неразбираемый JWKS timeout", key: "JWKS_TIMEOUT", value: "fast"},
		{name: "нулевой JWKS timeout", key: "JWKS_TIMEOUT", value: "0s"},
		{name: "нулевой cache TTL", key: "JWKS_CACHE_TTL", value: "0s"},
		{name: "неверный development flag", key: "DEVELOPMENT_ALLOW_INSECURE_JWKS", value: "sometimes"},
		{name: "нулевой database pool", key: "MAX_DB_CONNECTIONS", value: "0"},
		{name: "слишком большой database pool", key: "MAX_DB_CONNECTIONS", value: "101"},
		{name: "нечисловой database pool", key: "MAX_DB_CONNECTIONS", value: "many"},
		{name: "JWKS URL с credentials", key: "JWKS_URL", value: "https://user:pass@issuer.example/jwks.json"},
		{name: "JWKS URL с query", key: "JWKS_URL", value: "https://issuer.example/jwks.json?tenant=a"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setRequiredEnvironment(t)
			t.Setenv(tt.key, tt.value)
			if _, err := Load(); err == nil {
				t.Fatal("ожидалась ошибка configuration")
			}
		})
	}
}

// TestLoadAppliesCustomEnvironment проверяет успешный parsing всех настраиваемых limits.
func TestLoadAppliesCustomEnvironment(t *testing.T) {
	t.Log("Сценарий: корректные durations, pool limit и Compose JWKS host применяются без потери значений")
	setRequiredEnvironment(t)
	t.Setenv("HTTP_ADDRESS", ":9090")
	t.Setenv("OPA_URL", "http://opa:8181")
	t.Setenv("JWT_CLOCK_SKEW", "5s")
	t.Setenv("JWKS_TIMEOUT", "3s")
	t.Setenv("JWKS_CACHE_TTL", "10m")
	t.Setenv("MAX_DB_CONNECTIONS", "25")
	t.Setenv("JWKS_URL", "http://test-issuer:8090/jwks.json")
	t.Setenv("DEVELOPMENT_ALLOW_INSECURE_JWKS", "true")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.HTTPAddress != ":9090" || cfg.OPAURL != "http://opa:8181" || cfg.JWTClockSkew.String() != "5s" ||
		cfg.JWKSTimeout.String() != "3s" || cfg.JWKSCacheTTL.String() != "10m0s" || cfg.MaxDBConnections != 25 {
		t.Fatalf("не применены custom settings: %+v", cfg)
	}
}

// setRequiredEnvironment задаёт минимальную безопасную конфигурацию test process.
func setRequiredEnvironment(t *testing.T) {
	t.Helper()
	t.Setenv("DATABASE_URL", "postgres://example")
	t.Setenv("JWT_ISSUER", "https://issuer.example")
	t.Setenv("JWT_AUDIENCE", "aegispolicy")
	t.Setenv("JWKS_URL", "https://issuer.example/jwks.json")
	t.Setenv("JWT_ALGORITHM", "RS256")
	t.Setenv("DEVELOPMENT_ALLOW_INSECURE_JWKS", "false")
}
