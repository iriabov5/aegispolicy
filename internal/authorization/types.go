package authorization

import (
	"context"
	"time"
)

// Request содержит нормализованное утверждение PEP об операции, которую нужно авторизовать.
type Request struct {
	SubjectType  string
	SubjectID    string
	Action       string
	ResourceType string
	ResourceID   string
	Context      map[string]any
}

// Facts содержит защищённые факты, полученные приложением из доверенного хранилища.
type Facts struct {
	ResourceExists bool   `json:"resource_exists"`
	ProjectID      string `json:"project_id,omitempty"`
	ProjectRole    string `json:"project_role,omitempty"`
}

// PolicyInput задаёт версионированный контракт данных, передаваемых в OPA.
type PolicyInput struct {
	InputVersion string         `json:"input_version"`
	Subject      PolicySubject  `json:"subject"`
	Action       string         `json:"action"`
	Resource     PolicyResource `json:"resource"`
	Facts        Facts          `json:"facts"`
	Context      map[string]any `json:"context"`
}

// PolicySubject идентифицирует субъект внутри policy input без добавления недоверенных ролей.
type PolicySubject struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// PolicyResource идентифицирует ресурс внутри policy input.
type PolicyResource struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// PolicyDecision представляет строго валидируемый семантический ответ policy engine.
type PolicyDecision struct {
	Decision       string   `json:"decision"`
	Reasons        []string `json:"reasons"`
	PolicyName     string   `json:"policy_name"`
	PolicyRevision string   `json:"policy_revision"`
}

// Decision представляет безопасный публичный результат authorization evaluation.
type Decision struct {
	DecisionID     string   `json:"decision_id"`
	Decision       string   `json:"decision"`
	Reasons        []string `json:"reasons"`
	PolicyName     string   `json:"policy_name,omitempty"`
	PolicyRevision string   `json:"policy_revision,omitempty"`
}

// AuditRecord содержит минимальный набор полей для воспроизводимого аудита решения.
type AuditRecord struct {
	DecisionID     string
	Decision       string
	Reasons        []string
	PolicyName     string
	PolicyRevision string
	SubjectType    string
	SubjectID      string
	Action         string
	ResourceType   string
	ResourceID     string
	DecidedAt      time.Time
}

// FactReader получает защищённые факты о субъекте и документе из доверенного источника.
type FactReader interface {
	DocumentFacts(ctx context.Context, subjectID, resourceID string) (Facts, error)
}

// PolicyEvaluator вычисляет решение по полному policy input.
type PolicyEvaluator interface {
	Evaluate(ctx context.Context, input PolicyInput) (PolicyDecision, error)
}

// AuditWriter синхронно сохраняет решение до его возврата вызывающей стороне.
type AuditWriter interface {
	WriteDecision(ctx context.Context, record AuditRecord) error
}
