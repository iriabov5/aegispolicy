// Package apidocs предоставляет канонический OpenAPI contract как часть Go binary.
package apidocs

import _ "embed"

// OpenAPI содержит неизменённый docs/openapi.yaml, встроенный во время build.
//
//go:embed openapi.yaml
var OpenAPI []byte
