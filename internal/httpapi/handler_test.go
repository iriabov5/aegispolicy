package httpapi

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/iriabov5/aegispolicy/internal/authn"
	"github.com/iriabov5/aegispolicy/internal/authorization"
)

// authorizerFunc превращает функцию в test double HTTP-потребителя authorization use case.
type authorizerFunc func(context.Context, authorization.Request) (authorization.Decision, error)

// verifierFunc превращает функцию в test double проверки access token.
type verifierFunc func(context.Context, string) (authn.Principal, error)

// Verify вызывает настроенное конкретным тестом поведение проверки token.
func (f verifierFunc) Verify(ctx context.Context, token string) (authn.Principal, error) {
	return f(ctx, token)
}

// Authorize вызывает настроенное конкретным тестом поведение use case.
func (f authorizerFunc) Authorize(ctx context.Context, req authorization.Request) (authorization.Decision, error) {
	return f(ctx, req)
}

// TestAuthorizeHandler проверяет успешное отображение JSON request в domain request и response.
func TestAuthorizeHandler(t *testing.T) {
	t.Log("Сценарий: корректный HTTP request передаётся use case и возвращает его ALLOW response")
	var received authorization.Request
	handler := New(authorizerFunc(func(_ context.Context, req authorization.Request) (authorization.Decision, error) {
		received = req
		return authorization.Decision{DecisionID: "id", Decision: authorization.Allow, Reasons: []string{"project_editor"}}, nil
	}), validVerifier(), ready, []byte("openapi: 3.1.0\n"), testLogger())

	req := httptest.NewRequest(http.MethodPost, "/v1/authorize", strings.NewReader(`{
		"action":"document:update",
      "resource":{"type":"document","id":"doc-1"},
      "context":{}
    }`))
	req.Header.Set("Authorization", "Bearer valid")
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK || received.SubjectID != "ivan" {
		t.Fatalf("status=%d body=%s request=%+v", resp.Code, resp.Body.String(), received)
	}
}

// TestAuthorizeHandlerRejectsInvalidInput проверяет transport validation до вызова use case.
func TestAuthorizeHandlerRejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "синтаксически некорректный JSON", body: `{`},
		{name: "попытка подменить subject неизвестным полем", body: `{"subject":{"type":"user","id":"attacker"},"action":"document:update","resource":{"type":"document","id":"doc-1"}}`},
		{name: "несколько JSON documents в одном body", body: `{"action":"document:update","resource":{"type":"document","id":"doc-1"}} {}`},
		{name: "неоднозначный дублирующийся ключ action", body: `{"action":"document:read","action":"document:update","resource":{"type":"document","id":"doc-1"}}`},
	}
	called := false
	handler := New(authorizerFunc(func(context.Context, authorization.Request) (authorization.Decision, error) {
		called = true
		return authorization.Decision{}, nil
	}), validVerifier(), ready, []byte("openapi: 3.1.0\n"), testLogger())
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			called = false
			resp := httptest.NewRecorder()
			handler.ServeHTTP(resp, authenticatedRequest(tt.body))
			if resp.Code != http.StatusBadRequest || called {
				t.Fatalf("status=%d called=%v body=%s", resp.Code, called, resp.Body.String())
			}
		})
	}
}

// TestAuthorizeHandlerLimitsBody проверяет защиту от чрезмерного request body.
func TestAuthorizeHandlerLimitsBody(t *testing.T) {
	t.Log("Сценарий: request больше 16 KiB отклоняется до вызова authorization use case")
	handler := New(authorizerFunc(func(context.Context, authorization.Request) (authorization.Decision, error) {
		t.Fatal("authorizer не должен вызываться")
		return authorization.Decision{}, nil
	}), validVerifier(), ready, []byte("openapi: 3.1.0\n"), testLogger())
	resp := httptest.NewRecorder()
	body := bytes.Repeat([]byte("x"), maxBodyBytes+1)
	req := httptest.NewRequest(http.MethodPost, "/v1/authorize", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer valid")
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("status=%d", resp.Code)
	}
}

// TestAuthorizeHandlerFailsClosedOnServiceError проверяет безопасный публичный 503 response.
func TestAuthorizeHandlerFailsClosedOnServiceError(t *testing.T) {
	t.Log("Сценарий: внутренняя ошибка use case не раскрывается клиенту и не превращается в ALLOW")
	handler := New(authorizerFunc(func(context.Context, authorization.Request) (authorization.Decision, error) {
		return authorization.Decision{}, errors.New("audit unavailable")
	}), validVerifier(), ready, []byte("openapi: 3.1.0\n"), testLogger())
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, authenticatedRequest(`{"action":"document:update","resource":{"type":"document","id":"doc-1"}}`))
	if resp.Code != http.StatusServiceUnavailable || strings.Contains(resp.Body.String(), "audit") {
		t.Fatalf("небезопасный response: status=%d body=%s", resp.Code, resp.Body.String())
	}
}

// TestAuthenticationMiddleware проверяет отказ без token и различие invalid/unavailable outcomes.
func TestAuthenticationMiddleware(t *testing.T) {
	tests := []struct {
		name      string
		header    string
		duplicate bool
		verify    verifierFunc
		expected  int
	}{
		{name: "заголовок отсутствует", expected: http.StatusUnauthorized, verify: validVerifier()},
		{name: "Bearer token пуст", header: "Bearer ", expected: http.StatusUnauthorized, verify: validVerifier()},
		{name: "неверная схема", header: "Basic abc", expected: http.StatusUnauthorized, verify: validVerifier()},
		{name: "несколько credentials", header: "Bearer valid", duplicate: true, expected: http.StatusUnauthorized, verify: validVerifier()},
		{name: "токен отклонён", header: "Bearer bad", expected: http.StatusUnauthorized, verify: verifierFunc(func(context.Context, string) (authn.Principal, error) {
			return authn.Principal{}, authn.ErrInvalidCredential
		})},
		{name: "JWKS недоступен", header: "Bearer valid", expected: http.StatusServiceUnavailable, verify: verifierFunc(func(context.Context, string) (authn.Principal, error) { return authn.Principal{}, authn.ErrUnavailable })},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := New(authorizerFunc(func(context.Context, authorization.Request) (authorization.Decision, error) {
				t.Fatal("authorizer не должен вызываться")
				return authorization.Decision{}, nil
			}), tt.verify, ready, []byte("openapi: 3.1.0\n"), testLogger())
			req := httptest.NewRequest(http.MethodPost, "/v1/authorize", strings.NewReader(`{}`))
			if tt.header != "" {
				req.Header.Set("Authorization", tt.header)
			}
			if tt.duplicate {
				req.Header.Add("Authorization", "Bearer second")
			}
			resp := httptest.NewRecorder()
			handler.ServeHTTP(resp, req)
			if resp.Code != tt.expected {
				t.Fatalf("status=%d body=%s", resp.Code, resp.Body.String())
			}
		})
	}
}

// TestOpenAPIDocument проверяет открытую выдачу встроенного contract без authentication и dependencies.
func TestOpenAPIDocument(t *testing.T) {
	t.Log("Сценарий: OpenAPI YAML доступен без Bearer token и не вызывает authorization dependencies")
	want := []byte("openapi: 3.1.0\ninfo:\n  title: AegisPolicy API\n")
	handler := New(authorizerFunc(func(context.Context, authorization.Request) (authorization.Decision, error) {
		t.Fatal("authorizer не должен вызываться")
		return authorization.Decision{}, nil
	}), verifierFunc(func(context.Context, string) (authn.Principal, error) {
		t.Fatal("verifier не должен вызываться")
		return authn.Principal{}, nil
	}), func(context.Context) error {
		t.Fatal("readiness не должна вызываться")
		return nil
	}, want, testLogger())

	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/openapi.yaml", nil))
	if resp.Code != http.StatusOK || resp.Body.String() != string(want) {
		t.Fatalf("status=%d body=%q", resp.Code, resp.Body.String())
	}
	if mediaType := resp.Header().Get("Content-Type"); !strings.HasPrefix(mediaType, "application/yaml") {
		t.Fatalf("неверный Content-Type: %s", mediaType)
	}
}

// validVerifier принимает test token и возвращает доверенный subject из JWT-слоя.
func validVerifier() verifierFunc {
	return func(_ context.Context, token string) (authn.Principal, error) {
		if token != "valid" {
			return authn.Principal{}, authn.ErrInvalidCredential
		}
		return authn.Principal{Type: "user", ID: "ivan"}, nil
	}
}

// authenticatedRequest создаёт запрос с корректным тестовым Bearer credential.
func authenticatedRequest(body string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/v1/authorize", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer valid")
	return req
}

// testLogger создаёт logger, который не засоряет вывод unit tests.
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// ready имитирует доступные dependencies для handler tests, не связанных с health endpoint.
func ready(context.Context) error { return nil }
