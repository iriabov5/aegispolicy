package authorization

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

const (
	// Allow означает, что policy явно разрешила операцию.
	Allow = "ALLOW"
	// Deny означает отсутствие разрешения или fail-closed результат.
	Deny = "DENY"
)

// ErrAuditUnavailable сообщает, что обязательную audit record сохранить не удалось.
var ErrAuditUnavailable = errors.New("decision audit unavailable")

// Service координирует authorization flow и не содержит разрешающих business rules.
type Service struct {
	facts  FactReader
	policy PolicyEvaluator
	audit  AuditWriter
	now    func() time.Time
	newID  func() (string, error)
}

// NewService создаёт authorization service с явными I/O dependencies.
func NewService(facts FactReader, policy PolicyEvaluator, audit AuditWriter) *Service {
	return &Service{facts: facts, policy: policy, audit: audit, now: time.Now, newID: newDecisionID}
}

// Authorize вычисляет одно решение и возвращает его только после обязательного аудита.
// Ошибки facts или policy преобразуются в DENY; ошибка самого аудита возвращается как error.
func (s *Service) Authorize(ctx context.Context, req Request) (Decision, error) {
	id, err := s.newID()
	if err != nil {
		return Decision{}, fmt.Errorf("create decision id: %w", err)
	}

	decision := Decision{DecisionID: id, Decision: Deny}
	if reason := unsupportedReason(req); reason != "" {
		decision.Reasons = []string{reason}
		return s.persist(ctx, req, decision)
	}

	facts, err := s.facts.DocumentFacts(ctx, req.SubjectID, req.ResourceID)
	if err != nil {
		decision.Reasons = []string{"facts_unavailable"}
		return s.persist(ctx, req, decision)
	}

	policyDecision, err := s.policy.Evaluate(ctx, PolicyInput{
		InputVersion: "1",
		Subject:      PolicySubject{Type: req.SubjectType, ID: req.SubjectID},
		Action:       req.Action,
		Resource:     PolicyResource{Type: req.ResourceType, ID: req.ResourceID},
		Facts:        facts,
		Context:      req.Context,
	})
	if err != nil {
		decision.Reasons = []string{"policy_unavailable"}
		return s.persist(ctx, req, decision)
	}

	decision.Decision = policyDecision.Decision
	decision.Reasons = policyDecision.Reasons
	decision.PolicyName = policyDecision.PolicyName
	decision.PolicyRevision = policyDecision.PolicyRevision
	return s.persist(ctx, req, decision)
}

// persist сохраняет решение и обеспечивает запрет возврата неаудированного ALLOW.
func (s *Service) persist(ctx context.Context, req Request, decision Decision) (Decision, error) {
	err := s.audit.WriteDecision(ctx, AuditRecord{
		DecisionID: decision.DecisionID, Decision: decision.Decision, Reasons: decision.Reasons,
		PolicyName: decision.PolicyName, PolicyRevision: decision.PolicyRevision,
		SubjectType: req.SubjectType, SubjectID: req.SubjectID, Action: req.Action,
		ResourceType: req.ResourceType, ResourceID: req.ResourceID, DecidedAt: s.now().UTC(),
	})
	if err != nil {
		return Decision{}, fmt.Errorf("%w: %v", ErrAuditUnavailable, err)
	}
	return decision, nil
}

// unsupportedReason проверяет ограниченный vocabulary MVP до обращения к dependencies.
func unsupportedReason(req Request) string {
	if req.SubjectType != "user" {
		return "unknown_subject_type"
	}
	if req.ResourceType != "document" {
		return "unknown_resource_type"
	}
	if req.Action != "document:read" && req.Action != "document:update" {
		return "unknown_action"
	}
	if len(req.Context) != 0 {
		return "unsupported_context"
	}
	return ""
}

// newDecisionID генерирует UUIDv4 стандартной библиотекой без дополнительной зависимости.
func newDecisionID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	buf := make([]byte, 36)
	hex.Encode(buf[0:8], b[0:4])
	buf[8] = '-'
	hex.Encode(buf[9:13], b[4:6])
	buf[13] = '-'
	hex.Encode(buf[14:18], b[6:8])
	buf[18] = '-'
	hex.Encode(buf[19:23], b[8:10])
	buf[23] = '-'
	hex.Encode(buf[24:36], b[10:16])
	return string(buf), nil
}
