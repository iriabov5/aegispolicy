#!/usr/bin/env bash
set -euo pipefail

base_url=${AEGISPOLICY_URL:-http://127.0.0.1:8080}
issuer_url=${AEGISPOLICY_TEST_ISSUER_URL:-http://127.0.0.1:8090}
swagger_url=${AEGISPOLICY_SWAGGER_URL:-http://127.0.0.1:8081}

# Получает ephemeral access token у development-only issuer.
token_for() {
  local subject_id=$1
  local extra_query=${2:-}
  curl --fail-with-body --silent --show-error "${issuer_url}/token?sub=${subject_id}${extra_query}" |
    sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p'
}

# Отправляет один минимальный authorization request в уже запущенный Compose stack.
authorize() {
  local subject_id=$1
  local action=$2
  local token=${3:-$(token_for "${subject_id}")}
  curl --fail-with-body --silent --show-error \
    -X POST "${base_url}/v1/authorize" \
    -H 'Content-Type: application/json' \
    -H "Authorization: Bearer ${token}" \
    --data "{\"action\":\"${action}\",\"resource\":{\"type\":\"document\",\"id\":\"doc-1\"},\"context\":{}}"
}

# Сценарий: API сообщает readiness только при доступных PostgreSQL и OPA.
ready=$(curl --fail-with-body --silent --show-error "${base_url}/health/ready")
[[ ${ready} == *'"status":"ready"'* ]]

# Сценарий: runtime OpenAPI и development Swagger UI доступны без Bearer token.
openapi=$(curl --fail-with-body --silent --show-error "${base_url}/openapi.yaml")
[[ ${openapi} == openapi:* ]]
[[ ${openapi} == *'title: AegisPolicy API'* ]]
swagger=$(curl --fail-with-body --silent --show-error "${swagger_url}/")
[[ ${swagger} == *'Swagger UI'* ]]

# Сценарий: trusted EDITOR получает ALLOW с версией policy.
allow=$(authorize ivan document:update)
[[ ${allow} == *'"decision":"ALLOW"'* ]]
[[ ${allow} == *'"policy_revision":"1.0.0"'* ]]

# Сценарий: trusted VIEWER получает объяснимый DENY на изменение.
deny=$(authorize anna document:update)
[[ ${deny} == *'"decision":"DENY"'* ]]
[[ ${deny} == *'"insufficient_permission"'* ]]

# Сценарий: неизвестное действие закрывается по deny-by-default.
unknown=$(authorize ivan document:delete)
[[ ${unknown} == *'"decision":"DENY"'* ]]
[[ ${unknown} == *'"unknown_action"'* ]]

# Сценарий: caller не может подменить authenticated subject через request body.
spoof_status=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  -X POST "${base_url}/v1/authorize" -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $(token_for ivan)" \
  --data '{"subject":{"type":"user","id":"anna"},"action":"document:update","resource":{"type":"document","id":"doc-1"}}')
[[ ${spoof_status} == 400 ]]

# Сценарий: expired token, wrong audience и неизвестный kid дают общий 401.
for invalid_token in \
  "$(token_for ivan '&expired=true')" \
  "$(token_for ivan '&aud=other')" \
  "$(token_for ivan '&kid=unknown')"; do
  invalid_status=$(curl --silent --output /dev/null --write-out '%{http_code}' \
    -X POST "${base_url}/v1/authorize" -H 'Content-Type: application/json' \
    -H "Authorization: Bearer ${invalid_token}" \
    --data '{"action":"document:read","resource":{"type":"document","id":"doc-1"}}')
  [[ ${invalid_status} == 401 ]]
done

# Всегда восстанавливает OPA после outage test, включая аварийный выход script.
restore_opa() {
  docker compose start opa >/dev/null
}
trap restore_opa EXIT
docker compose stop opa >/dev/null

# Сценарий: недоступность OPA даёт DENY и не включает fallback по роли EDITOR.
unavailable=$(authorize ivan document:update)
[[ ${unavailable} == *'"decision":"DENY"'* ]]
[[ ${unavailable} == *'"policy_unavailable"'* ]]

restore_opa
trap - EXIT

# Сценарий: после истечения JWKS TTL outage issuer закрывает authentication через 503.
cached_token=$(token_for ivan)
# Всегда восстанавливает development issuer после outage test.
restore_issuer() {
  docker compose start test-issuer >/dev/null
}
trap restore_issuer EXIT
docker compose stop test-issuer >/dev/null
sleep 2
jwks_status=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  -X POST "${base_url}/v1/authorize" -H 'Content-Type: application/json' \
  -H "Authorization: Bearer ${cached_token}" \
  --data '{"action":"document:read","resource":{"type":"document","id":"doc-1"}}')
[[ ${jwks_status} == 503 ]]
restore_issuer
trap - EXIT

# Сценарий: все завершённые policy decisions оставляют audit records.
audit_count=$(docker compose exec -T postgres psql -U aegispolicy -d aegispolicy -Atc \
  "SELECT count(*) FROM authorization_decisions WHERE subject_id IN ('ivan', 'anna');")
(( audit_count >= 4 ))

echo "E2E: JWT binding, ALLOW/DENY, spoofing, outages и audit проверены"
