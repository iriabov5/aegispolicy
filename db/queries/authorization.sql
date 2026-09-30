-- name: GetDocumentFacts :one
-- Возвращает только trusted project facts для пары subject/document.
SELECT d.project_id, COALESCE(spr.role, '') AS project_role
FROM documents d
LEFT JOIN subject_project_roles spr
  ON spr.project_id = d.project_id AND spr.subject_id = $1
WHERE d.id = $2;

-- name: InsertAuthorizationDecision :exec
-- Синхронно сохраняет минимальный audit record до возврата ALLOW.
INSERT INTO authorization_decisions (
  decision_id, decision, reasons, policy_name, policy_revision,
  subject_type, subject_id, action, resource_type, resource_id, decided_at
) VALUES (
  sqlc.arg(decision_id), sqlc.arg(decision), sqlc.arg(reasons),
  NULLIF(sqlc.arg(policy_name)::text, ''), NULLIF(sqlc.arg(policy_revision)::text, ''),
  sqlc.arg(subject_type), sqlc.arg(subject_id), sqlc.arg(action),
  sqlc.arg(resource_type), sqlc.arg(resource_id), sqlc.arg(decided_at)
);
