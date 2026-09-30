package policy

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/iriabov5/aegispolicy/internal/authorization"
)

// roundTripFunc позволяет тестировать HTTP adapter без локального TCP listener.
type roundTripFunc func(*http.Request) (*http.Response, error)

// RoundTrip реализует http.RoundTripper через функцию конкретного сценария.
func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

// TestOPAEvaluate проверяет разбор полных корректных ALLOW и DENY responses.
func TestOPAEvaluate(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected string
	}{
		{name: "корректный ALLOW сохраняет разрешающую причину", body: `{"result":{"decision":"ALLOW","reasons":["project_editor"],"policy_name":"document-access","policy_revision":"1.0.0"}}`, expected: authorization.Allow},
		{name: "корректный DENY сохраняет запрещающую причину", body: `{"result":{"decision":"DENY","reasons":["insufficient_permission"],"policy_name":"document-access","policy_revision":"1.0.0"}}`, expected: authorization.Deny},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := clientWithResponse(http.StatusOK, tt.body)
			decision, err := NewOPA("http://opa:8181", client).Evaluate(context.Background(), authorization.PolicyInput{})
			if err != nil || decision.Decision != tt.expected {
				t.Fatalf("неожиданный результат: %+v %v", decision, err)
			}
		})
	}
}

// TestOPARejectsInvalidResponses проверяет строгую validation всех ошибочных envelopes.
func TestOPARejectsInvalidResponses(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
	}{
		{name: "OPA возвращает HTTP не из диапазона 2xx", status: http.StatusInternalServerError, body: `{}`},
		{name: "OPA возвращает синтаксически некорректный JSON", status: http.StatusOK, body: `{`},
		{name: "в response отсутствует обязательный result", status: http.StatusOK, body: `{}`},
		{name: "policy возвращает неизвестный decision", status: http.StatusOK, body: `{"result":{"decision":"MAYBE","reasons":["x"],"policy_name":"p","policy_revision":"1"}}`},
		{name: "response содержит поле вне строгого контракта", status: http.StatusOK, body: `{"result":{"decision":"DENY","reasons":["x"],"policy_name":"p","policy_revision":"1","extra":true}}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewOPA("http://opa:8181", clientWithResponse(tt.status, tt.body)).Evaluate(context.Background(), authorization.PolicyInput{})
			if err == nil {
				t.Fatal("ожидалась ошибка")
			}
		})
	}
}

// TestOPAHonorsContextCancellation проверяет распространение deadline в HTTP request.
func TestOPAHonorsContextCancellation(t *testing.T) {
	t.Log("Сценарий: отмена context прерывает обращение к OPA и сохраняет DeadlineExceeded в error chain")
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		<-req.Context().Done()
		return nil, req.Context().Err()
	})}
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	_, err := NewOPA("http://opa:8181", client).Evaluate(ctx, authorization.PolicyInput{})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ожидался deadline exceeded: %v", err)
	}
}

// clientWithResponse создаёт in-memory HTTP client с заданным status и body.
func clientWithResponse(status int, body string) *http.Client {
	return &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path != "/v1/data/aegispolicy/authorization/decision" {
			return nil, errors.New("неожиданный path")
		}
		return &http.Response{
			StatusCode: status,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(body)),
			Request:    req,
		}, nil
	})}
}
