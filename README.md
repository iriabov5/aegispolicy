# AegisPolicy

AegisPolicy — Zero-Trust-платформа авторизации людей, сервисов и AI-агентов с policy-based access control, ограниченным делегированием, объяснимыми решениями и контролем MCP-инструментов.

Сейчас реализован намеренно небольшой первый MVP: внутренний Policy Decision Point для документов demo domain. Он показывает разделение trusted facts и policy decisions, fail-closed поведение и обязательный аудит.

## Статус

### Реализовано

- `POST /v1/authorize` для subject type `user`, resource type `document` и действий `document:read`/`document:update`.
- Обязательная Bearer JWT-аутентификация: RS256, `kid`, signature, issuer, audience, `exp`, `nbf` и `sub`.
- `subject.id` берётся исключительно из проверенного JWT `sub`; тело запроса не может его подменить.
- Ограниченный JWKS-кеш с обновлением ключей и fail-closed без stale keys.
- ALLOW/DENY через отдельный OPA 1.21.0 и Rego-policy.
- Trusted project role и принадлежность документа из PostgreSQL 18.6.
- Уникальный `decision_id`, стабильные reason codes и policy revision.
- Синхронный audit: ALLOW не возвращается без сохранённой audit record.
- Fail closed при недоступности trusted facts, OPA, некорректном policy output и ошибке аудита.
- Structured JSON logs без tokens и raw policy input.
- Health endpoints, graceful shutdown, Docker Compose, Go/Rego unit tests и PostgreSQL Testcontainers test.
- OpenAPI 3.1 contract, runtime `GET /openapi.yaml` и локальный Swagger UI.

### Запланировано

- Аутентификация самого PEP как сервиса, OAuth2 login/refresh flow и интеграция с Keycloak.
- CHALLENGE, explicit DENY, hierarchy, ReBAC и расширенная explainability.
- Scoped delegation, отдельная agent identity и пересечение human/agent permissions.
- MCP Policy Gateway, policy simulation и list filtering через partial evaluation.

### Экспериментально

Текущий API предназначен только для local/internal development. Он проверяет identity пользователя по JWT, но ещё не аутентифицирует вызывающий PEP как отдельный workload. Development issuer из Compose не является заменой Keycloak или production IdP.

## Архитектура

```text
пользователь -> IdP -> JWT -> PEP -> Go API -> trusted facts -> OPA/Rego
                              |        \-> decision audit <- ALLOW/DENY
                              \-> subject.id = проверенный JWT sub
```

Go отвечает за transport, validation, trusted fact retrieval, policy input, audit и lifecycle. Rego принимает семантическое решение. При ошибке policy нет fallback на Go/JWT role.

Машиночитаемый контракт: [OpenAPI 3.1](docs/openapi.yaml).

## Быстрый запуск

Требования: Docker с Compose v2.

```bash
docker compose up --build -d
docker compose ps
```

После запуска доступны:

- API: `http://127.0.0.1:8080`;
- OpenAPI YAML: `http://127.0.0.1:8080/openapi.yaml`;
- Swagger UI: `http://127.0.0.1:8081`.

В Swagger UI нажмите **Authorize** и вставьте только token без префикса `Bearer`. Test token можно получить так:

```bash
curl -s 'http://127.0.0.1:8090/token?sub=ivan'
```

Development issuer и Swagger UI предназначены только для локальной разработки.

Проверка ALLOW для editor:

```bash
TOKEN=$(curl -s 'http://127.0.0.1:8090/token?sub=ivan' | \
  sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')
curl -s -X POST http://127.0.0.1:8080/v1/authorize \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer ${TOKEN}" \
  --data '{
    "action":"document:update",
    "resource":{"type":"document","id":"doc-1"},
    "context":{}
  }'
```

Пример ответа:

```json
{
  "decision_id": "4e85e054-ee0b-4e21-9aee-cfa5cc02056e",
  "decision": "ALLOW",
  "reasons": ["project_editor"],
  "policy_name": "document-access",
  "policy_revision": "1.0.0"
}
```

Seed data:

- `ivan` — `EDITOR` проекта `project-1`;
- `anna` — `VIEWER` проекта `project-1`;
- `doc-1`, `doc-2` принадлежат `project-1`.

Остановка:

```bash
docker compose down
```

Named volume с PostgreSQL сохраняется. Для его удаления требуется отдельная явная команда.

## Проверки

```bash
go test ./...
go vet ./...
docker run --rm -v "$PWD/policy:/policy:ro" \
  openpolicyagent/opa:1.21.0-static test /policy
go test -tags=integration ./internal/store -run TestPostgresFactsAndAudit -v
```

Локальный Go toolchain закреплён директивой `toolchain go1.27.1`. SQL-код генерируется закреплённым sqlc:

```bash
docker run --rm -v "$PWD:/src" -w /src sqlc/sqlc:1.31.1 generate
```

## Документация кода и тестов

Packages, types, interfaces и functions снабжаются русскими Go doc comments. Они объясняют назначение, contract и security semantics, а не пересказывают синтаксис. Исключение — `internal/store/dbgen`: это generated code sqlc, который нельзя редактировать вручную.

Каждый Go test содержит русское описание сценария, видимое с `go test -v`. Table-driven subtests используют русские имена. Rego rules и tests также имеют русские комментарии о проверяемом authorization behavior.

## Изменение HTTP-контракта

Канонический контракт редактируется в `docs/openapi.yaml`. Он встраивается в Go binary через `docs/embed.go`, поэтому `/openapi.yaml` всегда соответствует собранной версии. После изменения API одновременно обновляются handler, OpenAPI и contract tests в `docs/openapi_test.go`; `go test ./...` проверяет синтаксис OpenAPI, routes, security requirements и критические schemas.

Swagger UI не входит в production binary: Compose монтирует тот же YAML в отдельный официальный контейнер. Это сохраняет один источник истины и не требует CDN.

## HTTP flow и соединения

1. Middleware строго извлекает один Bearer token и проверяет JWT по JWKS.
2. Handler получает `subject.id` из JWT `sub`, ограничивает JSON body и проверяет структуру.
3. Authorization service через sqlc query получает trusted facts.
4. `pgxpool` выдаёт physical connection на время query и возвращает его в pool.
5. Сервис вызывает OPA с request context и timeout.
6. Output OPA строго валидируется; ошибка становится DENY.
7. Audit adapter выполняет `INSERT`; только после успешного audit клиент получает ALLOW.

В текущем flow нет многооперационной business transaction: чтение фактов и audit insert — отдельные операции. Решение имеет point-in-time semantics; атомарность с downstream mutation не заявляется.

При SIGINT/SIGTERM сервер прекращает принимать новые соединения, ждёт активные запросы в пределах shutdown deadline, после чего закрывает `pgxpool`.
