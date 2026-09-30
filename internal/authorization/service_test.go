package authorization

import (
	"context"
	"errors"
	"testing"
	"time"
)

// factReaderFunc превращает функцию в управляемый test double интерфейса FactReader.
type factReaderFunc func(context.Context, string, string) (Facts, error)

// DocumentFacts вызывает настроенное тестом поведение получения trusted facts.
func (f factReaderFunc) DocumentFacts(ctx context.Context, subjectID, resourceID string) (Facts, error) {
	return f(ctx, subjectID, resourceID)
}

// policyEvaluatorFunc превращает функцию в управляемый test double PolicyEvaluator.
type policyEvaluatorFunc func(context.Context, PolicyInput) (PolicyDecision, error)

// Evaluate вызывает настроенное тестом поведение policy engine.
func (f policyEvaluatorFunc) Evaluate(ctx context.Context, input PolicyInput) (PolicyDecision, error) {
	return f(ctx, input)
}

// auditWriterFunc превращает функцию в управляемый test double AuditWriter.
type auditWriterFunc func(context.Context, AuditRecord) error

// WriteDecision вызывает настроенное тестом поведение audit storage.
func (f auditWriterFunc) WriteDecision(ctx context.Context, record AuditRecord) error {
	return f(ctx, record)
}

// TestServiceAllowIsAudited проверяет, что ALLOW возвращается только вместе с audit record.
func TestServiceAllowIsAudited(t *testing.T) {
	t.Log("Сценарий: разрешённая policy операция возвращает ALLOW и сохраняется с тем же decision_id")
	var audited AuditRecord
	service := testService(
		factReaderFunc(func(context.Context, string, string) (Facts, error) {
			return Facts{ResourceExists: true, ProjectID: "project-1", ProjectRole: "EDITOR"}, nil
		}),
		policyEvaluatorFunc(func(_ context.Context, input PolicyInput) (PolicyDecision, error) {
			if input.Facts.ProjectRole != "EDITOR" {
				t.Fatalf("не передана доверенная роль: %+v", input.Facts)
			}
			return PolicyDecision{Decision: Allow, Reasons: []string{"project_editor"}, PolicyName: "document-access", PolicyRevision: "1.0.0"}, nil
		}),
		auditWriterFunc(func(_ context.Context, record AuditRecord) error {
			audited = record
			return nil
		}),
	)

	decision, err := service.Authorize(context.Background(), validRequest())
	if err != nil {
		t.Fatal(err)
	}
	if decision.Decision != Allow || audited.DecisionID != decision.DecisionID {
		t.Fatalf("решение не сохранено: decision=%+v audit=%+v", decision, audited)
	}
}

// TestServicePolicyFailureDeniesWithoutFallback проверяет fail closed при ошибке OPA.
func TestServicePolicyFailureDeniesWithoutFallback(t *testing.T) {
	t.Log("Сценарий: ошибка policy engine даёт аудируемый DENY без резервной проверки роли")
	policyCalls := 0
	var audited AuditRecord
	service := testService(
		factReaderFunc(func(context.Context, string, string) (Facts, error) {
			return Facts{ResourceExists: true, ProjectRole: "EDITOR"}, nil
		}),
		policyEvaluatorFunc(func(context.Context, PolicyInput) (PolicyDecision, error) {
			policyCalls++
			return PolicyDecision{}, errors.New("OPA недоступен")
		}),
		auditWriterFunc(func(_ context.Context, record AuditRecord) error { audited = record; return nil }),
	)

	decision, err := service.Authorize(context.Background(), validRequest())
	if err != nil {
		t.Fatal(err)
	}
	if policyCalls != 1 || decision.Decision != Deny || decision.Reasons[0] != "policy_unavailable" {
		t.Fatalf("ожидался fail-closed DENY: %+v", decision)
	}
	if audited.Decision != Deny {
		t.Fatalf("DENY не записан в аудит: %+v", audited)
	}
}

// TestServiceFactFailureDenies проверяет запрет при недоступности trusted facts.
func TestServiceFactFailureDenies(t *testing.T) {
	t.Log("Сценарий: ошибка получения trusted facts даёт DENY и policy не вызывается")
	policyCalled := false
	service := testService(
		factReaderFunc(func(context.Context, string, string) (Facts, error) { return Facts{}, errors.New("db") }),
		policyEvaluatorFunc(func(context.Context, PolicyInput) (PolicyDecision, error) {
			policyCalled = true
			return PolicyDecision{}, nil
		}),
		auditWriterFunc(func(context.Context, AuditRecord) error { return nil }),
	)
	decision, err := service.Authorize(context.Background(), validRequest())
	if err != nil {
		t.Fatal(err)
	}
	if policyCalled || decision.Decision != Deny || decision.Reasons[0] != "facts_unavailable" {
		t.Fatalf("ожидался DENY без вызова policy: %+v", decision)
	}
}

// TestServiceUnknownActionDenies проверяет deny-by-default для неизвестного действия.
func TestServiceUnknownActionDenies(t *testing.T) {
	t.Log("Сценарий: неизвестное действие отклоняется до I/O и записывается в аудит")
	req := validRequest()
	req.Action = "document:delete"
	service := testService(nil, nil, auditWriterFunc(func(context.Context, AuditRecord) error { return nil }))
	decision, err := service.Authorize(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Decision != Deny || decision.Reasons[0] != "unknown_action" {
		t.Fatalf("ожидался DENY: %+v", decision)
	}
}

// TestServiceAuditFailureNeverReturnsAllow проверяет обязательность durable audit для ALLOW.
func TestServiceAuditFailureNeverReturnsAllow(t *testing.T) {
	t.Log("Сценарий: потенциальный ALLOW не покидает сервис при ошибке audit storage")
	service := testService(
		factReaderFunc(func(context.Context, string, string) (Facts, error) { return Facts{ResourceExists: true}, nil }),
		policyEvaluatorFunc(func(context.Context, PolicyInput) (PolicyDecision, error) {
			return PolicyDecision{Decision: Allow, Reasons: []string{"project_editor"}, PolicyName: "document-access", PolicyRevision: "1.0.0"}, nil
		}),
		auditWriterFunc(func(context.Context, AuditRecord) error { return errors.New("db") }),
	)
	decision, err := service.Authorize(context.Background(), validRequest())
	if !errors.Is(err, ErrAuditUnavailable) || decision.Decision == Allow {
		t.Fatalf("ALLOW не должен возвращаться: decision=%+v err=%v", decision, err)
	}
}

// testService создаёт детерминированный Service с постоянными временем и decision ID.
func testService(facts FactReader, policy PolicyEvaluator, audit AuditWriter) *Service {
	service := NewService(facts, policy, audit)
	service.newID = func() (string, error) { return "00000000-0000-4000-8000-000000000001", nil }
	service.now = func() time.Time { return time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC) }
	return service
}

// validRequest возвращает минимальный поддерживаемый authorization request.
func validRequest() Request {
	return Request{SubjectType: "user", SubjectID: "ivan", Action: "document:update", ResourceType: "document", ResourceID: "doc-1", Context: map[string]any{}}
}
