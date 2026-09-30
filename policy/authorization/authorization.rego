package aegispolicy.authorization

import rego.v1

# Идентификаторы policy входят в каждый decision и audit record.
policy_name := "document-access"
policy_revision := "1.0.0"

# Любая операция запрещена, пока одно из allow rules явно её не разрешит.
default allowed := false

# VIEWER и EDITOR могут читать существующий документ своего проекта.
allowed if {
	input.input_version == "1"
	input.subject.type == "user"
	input.resource.type == "document"
	input.facts.resource_exists == true
	input.action == "document:read"
	input.facts.project_role in {"VIEWER", "EDITOR"}
}

# Только EDITOR может изменять существующий документ своего проекта.
allowed if {
	input.input_version == "1"
	input.subject.type == "user"
	input.resource.type == "document"
	input.facts.resource_exists == true
	input.action == "document:update"
	input.facts.project_role == "EDITOR"
}

# Положительное решение содержит стабильную причину и точную версию policy.
decision := {
	"decision": "ALLOW",
	"reasons": [allow_reason],
	"policy_name": policy_name,
	"policy_revision": policy_revision,
} if {
	allowed
}

# Отсутствие разрешающего rule превращается в объяснимый DENY.
decision := {
	"decision": "DENY",
	"reasons": [deny_reason],
	"policy_name": policy_name,
	"policy_revision": policy_revision,
} if {
	not allowed
}

# Изменение документа разрешено благодаря роли EDITOR.
allow_reason := "project_editor" if {
	input.action == "document:update"
}

# Чтение разрешено участнику проекта с VIEWER или EDITOR.
allow_reason := "project_member" if {
	input.action == "document:read"
}

# Неизвестный ресурс маскируется стабильной причиной без раскрытия details.
deny_reason := "resource_not_found" if {
	input.facts.resource_exists == false
}

# Существующий ресурс запрещён из-за недостаточных trusted permissions.
deny_reason := "insufficient_permission" if {
	input.facts.resource_exists == true
}
