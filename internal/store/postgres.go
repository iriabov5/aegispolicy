package store

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/iriabov5/aegispolicy/internal/authorization"
	"github.com/iriabov5/aegispolicy/internal/store/dbgen"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Postgres объединяет sqlc queries для trusted facts и decision audit.
type Postgres struct {
	queries *dbgen.Queries
}

// NewPostgres создаёт adapter поверх общего pgx pool; adapter не владеет lifecycle pool.
func NewPostgres(pool *pgxpool.Pool) *Postgres {
	return &Postgres{queries: dbgen.New(pool)}
}

// DocumentFacts получает принадлежность документа и project role субъекта одним SQL query.
// Отсутствующий документ является корректным фактом, а не infrastructure error.
func (p *Postgres) DocumentFacts(ctx context.Context, subjectID, resourceID string) (authorization.Facts, error) {
	row, err := p.queries.GetDocumentFacts(ctx, dbgen.GetDocumentFactsParams{SubjectID: subjectID, ID: resourceID})
	if err != nil {
		if err == pgx.ErrNoRows {
			return authorization.Facts{ResourceExists: false}, nil
		}
		return authorization.Facts{}, fmt.Errorf("query document facts: %w", err)
	}
	return authorization.Facts{ResourceExists: true, ProjectID: row.ProjectID, ProjectRole: row.ProjectRole}, nil
}

// WriteDecision сохраняет одну audit record; успешный возврат означает завершённый INSERT.
func (p *Postgres) WriteDecision(ctx context.Context, record authorization.AuditRecord) error {
	reasons, err := json.Marshal(record.Reasons)
	if err != nil {
		return fmt.Errorf("encode audit reasons: %w", err)
	}
	var decisionID pgtype.UUID
	if err := decisionID.Scan(record.DecisionID); err != nil {
		return fmt.Errorf("parse decision id: %w", err)
	}
	err = p.queries.InsertAuthorizationDecision(ctx, dbgen.InsertAuthorizationDecisionParams{
		DecisionID: decisionID, Decision: record.Decision, Reasons: reasons,
		PolicyName: record.PolicyName, PolicyRevision: record.PolicyRevision,
		SubjectType: record.SubjectType, SubjectID: record.SubjectID, Action: record.Action,
		ResourceType: record.ResourceType, ResourceID: record.ResourceID,
		DecidedAt: pgtype.Timestamptz{Time: record.DecidedAt, Valid: true},
	})
	if err != nil {
		return fmt.Errorf("insert decision audit: %w", err)
	}
	return nil
}
