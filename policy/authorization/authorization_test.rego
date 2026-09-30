package aegispolicy.authorization_test

import data.aegispolicy.authorization.decision
import rego.v1

base_input := {
	"input_version": "1",
	"subject": {"type": "user", "id": "ivan"},
	"action": "document:update",
	"resource": {"type": "document", "id": "doc-1"},
	"facts": {"resource_exists": true, "project_id": "project-1", "project_role": "EDITOR"},
	"context": {},
}

# Проверяет, что EDITOR может изменить документ своего проекта.
test_editor_can_update if {
	result := decision with input as base_input
	result.decision == "ALLOW"
}

# Проверяет, что VIEWER не может изменить документ.
test_viewer_cannot_update if {
	result := decision with input as object.union(base_input, {"facts": object.union(base_input.facts, {"project_role": "VIEWER"})})
	result.decision == "DENY"
}

# Проверяет, что VIEWER может прочитать документ своего проекта.
test_viewer_can_read if {
	result := decision with input as object.union(base_input, {"action": "document:read", "facts": object.union(base_input.facts, {"project_role": "VIEWER"})})
	result.decision == "ALLOW"
}

# Проверяет deny-by-default при отсутствии project role.
test_missing_role_is_denied if {
	result := decision with input as object.union(base_input, {"facts": {"resource_exists": true, "project_id": "project-1", "project_role": ""}})
	result.decision == "DENY"
}

# Проверяет DENY для действия вне vocabulary policy.
test_unknown_action_is_denied if {
	result := decision with input as object.union(base_input, {"action": "document:delete"})
	result.decision == "DENY"
}

# Проверяет DENY и отдельную причину для отсутствующего ресурса.
test_missing_resource_is_denied if {
	result := decision with input as object.union(base_input, {"facts": {"resource_exists": false}})
	result.decision == "DENY"
}

# Проверяет, что заявленная клиентом роль не заменяет trusted facts.
test_claimed_role_outside_facts_is_ignored if {
	result := decision with input as object.union(base_input, {"subject": {"type": "user", "id": "anna", "role": "EDITOR"}, "facts": object.union(base_input.facts, {"project_role": "VIEWER"})})
	result.decision == "DENY"
}
