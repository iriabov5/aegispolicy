//go:build integration

package store

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/iriabov5/aegispolicy/internal/authorization"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
)

// TestPostgresFactsAndAudit проверяет schema, sqlc facts query и durable audit на реальной PostgreSQL.
func TestPostgresFactsAndAudit(t *testing.T) {
	t.Log("Сценарий: Testcontainers PostgreSQL применяет migration, возвращает trusted role и сохраняет audit record")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	container, err := postgres.Run(ctx, "postgres:18.6-alpine3.23",
		postgres.WithDatabase("aegispolicy"),
		postgres.WithUsername("aegispolicy"),
		postgres.WithPassword("test-only"),
		postgres.BasicWaitStrategies(),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = container.Terminate(context.Background()) })

	connectionString, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.New(ctx, connectionString)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	migration, err := os.ReadFile("../../db/migrations/000001_init.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, string(migration)); err != nil {
		t.Fatal(err)
	}

	adapter := NewPostgres(pool)
	facts, err := adapter.DocumentFacts(ctx, "ivan", "doc-1")
	if err != nil {
		t.Fatal(err)
	}
	if !facts.ResourceExists || facts.ProjectRole != "EDITOR" {
		t.Fatalf("неожиданные факты: %+v", facts)
	}

	record := authorization.AuditRecord{
		DecisionID: "00000000-0000-4000-8000-000000000001", Decision: authorization.Allow,
		Reasons: []string{"project_editor"}, PolicyName: "document-access", PolicyRevision: "1.0.0",
		SubjectType: "user", SubjectID: "ivan", Action: "document:update",
		ResourceType: "document", ResourceID: "doc-1", DecidedAt: time.Now().UTC(),
	}
	if err := adapter.WriteDecision(ctx, record); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM authorization_decisions WHERE decision_id = $1`, record.DecisionID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("ожидалась одна audit record, получено %d", count)
	}
}
