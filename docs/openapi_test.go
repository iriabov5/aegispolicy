package apidocs

import (
	"context"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

// TestOpenAPIContract проверяет синтаксис и критические security invariants внешнего API.
func TestOpenAPIContract(t *testing.T) {
	t.Log("Сценарий: OpenAPI 3.1 описывает реальные routes, Bearer JWT и запрещает subject в request body")
	loader := openapi3.NewLoader()
	document, err := loader.LoadFromData(OpenAPI)
	if err != nil {
		t.Fatalf("OpenAPI не разобран: %v", err)
	}
	if err := document.Validate(context.Background()); err != nil {
		t.Fatalf("OpenAPI не прошёл validation: %v", err)
	}

	authorize := requiredOperation(t, document, "/v1/authorize", "POST")
	if authorize.Security == nil || len(*authorize.Security) != 1 {
		t.Fatal("POST /v1/authorize должен требовать один Bearer security scheme")
	}
	if _, exists := (*authorize.Security)[0]["bearerAuth"]; !exists {
		t.Fatal("POST /v1/authorize не требует bearerAuth")
	}
	for _, status := range []string{"200", "400", "401", "503"} {
		if authorize.Responses.Value(status) == nil {
			t.Fatalf("POST /v1/authorize не описывает response %s", status)
		}
	}
	requestSchema := document.Components.Schemas["AuthorizationRequest"].Value
	if _, exists := requestSchema.Properties["subject"]; exists {
		t.Fatal("AuthorizationRequest не должен позволять caller-controlled subject")
	}
	if requestSchema.AdditionalProperties.Has == nil || *requestSchema.AdditionalProperties.Has {
		t.Fatal("AuthorizationRequest должен запрещать неизвестные поля")
	}

	for _, path := range []string{"/health/live", "/health/ready", "/openapi.yaml"} {
		operation := requiredOperation(t, document, path, "GET")
		if operation.Security == nil || len(*operation.Security) != 0 {
			t.Fatalf("%s должен явно отключать authentication", path)
		}
	}
}

// requiredOperation возвращает обязательную operation либо завершает test понятной ошибкой.
func requiredOperation(t *testing.T, document *openapi3.T, path, method string) *openapi3.Operation {
	t.Helper()
	item := document.Paths.Value(path)
	if item == nil {
		t.Fatalf("не описан path %s", path)
	}
	operation := item.GetOperation(method)
	if operation == nil {
		t.Fatalf("не описан method %s %s", method, path)
	}
	return operation
}
