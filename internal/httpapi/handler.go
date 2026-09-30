package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/iriabov5/aegispolicy/internal/authn"
	"github.com/iriabov5/aegispolicy/internal/authorization"
)

// maxBodyBytes ограничивает память и CPU, доступные одному authorization request.
const maxBodyBytes = 16 << 10

// Authorizer описывает единственный use case, необходимый HTTP adapter.
type Authorizer interface {
	Authorize(ctx context.Context, req authorization.Request) (authorization.Decision, error)
}

// Handler хранит HTTP dependencies и отображает domain outcomes в безопасные responses.
type Handler struct {
	authorizer Authorizer
	readiness  func(context.Context) error
	log        *slog.Logger
	verifier   authn.Verifier
	openAPI    []byte
}

// New собирает router с authorization, liveness и readiness endpoints.
func New(authorizer Authorizer, verifier authn.Verifier, readiness func(context.Context) error, openAPI []byte, log *slog.Logger) http.Handler {
	h := &Handler{authorizer: authorizer, verifier: verifier, readiness: readiness, openAPI: openAPI, log: log}
	r := chi.NewRouter()
	r.Get("/health/live", h.live)
	r.Get("/health/ready", h.ready)
	r.Get("/openapi.yaml", h.openAPIDocument)
	r.With(h.authenticate).Post("/v1/authorize", h.authorize)
	return r
}

// openAPIDocument возвращает contract текущего build без обращения к внешним dependencies.
func (h *Handler) openAPIDocument(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(h.openAPI)
}

// authorizeRequest задаёт допустимый внешний JSON envelope без protected facts.
type authorizeRequest struct {
	Action   string         `json:"action"`
	Resource resource       `json:"resource"`
	Context  map[string]any `json:"context"`
}

// resource содержит только type и ID; защищённые атрибуты загружаются приложением.
type resource struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// authorize валидирует transport input, вызывает use case и не раскрывает внутренние ошибки.
func (h *Handler) authorize(w http.ResponseWriter, r *http.Request) {
	principal, ok := principalFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "authentication_failed")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	raw, err := io.ReadAll(r.Body)
	if err != nil || rejectDuplicateJSONKeys(raw) != nil {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var body authorizeRequest
	if err := decoder.Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if err := ensureSingleJSON(decoder); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if body.Context == nil {
		body.Context = map[string]any{}
	}
	if !validIdentifier(body.Resource.Type) || !validIdentifier(body.Resource.ID) || !validAction(body.Action) {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}

	decision, err := h.authorizer.Authorize(r.Context(), authorization.Request{
		SubjectType: principal.Type, SubjectID: principal.ID, Action: body.Action,
		ResourceType: body.Resource.Type, ResourceID: body.Resource.ID, Context: body.Context,
	})
	if err != nil {
		h.log.ErrorContext(r.Context(), "authorization failed closed", "error", err)
		writeError(w, http.StatusServiceUnavailable, "authorization_unavailable")
		return
	}

	h.log.InfoContext(r.Context(), "authorization decision",
		"decision_id", decision.DecisionID, "decision", decision.Decision,
		"subject_type", principal.Type, "action", body.Action, "resource_type", body.Resource.Type,
	)
	writeJSON(w, http.StatusOK, decision)
}

type principalContextKey struct{}

// authenticate проверяет единственный Bearer credential и помещает principal в request context.
func (h *Handler) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		values := r.Header.Values("Authorization")
		if len(values) != 1 {
			writeError(w, http.StatusUnauthorized, "authentication_failed")
			return
		}
		parts := strings.Split(values[0], " ")
		if len(parts) != 2 || parts[0] != "Bearer" || parts[1] == "" {
			writeError(w, http.StatusUnauthorized, "authentication_failed")
			return
		}
		principal, err := h.verifier.Verify(r.Context(), parts[1])
		if err != nil {
			if errors.Is(err, authn.ErrUnavailable) {
				h.log.ErrorContext(r.Context(), "authentication unavailable", "error", err)
				writeError(w, http.StatusServiceUnavailable, "authentication_unavailable")
				return
			}
			writeError(w, http.StatusUnauthorized, "authentication_failed")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalContextKey{}, principal)))
	})
}

// principalFromContext возвращает только principal, созданный authentication middleware.
func principalFromContext(ctx context.Context) (authn.Principal, bool) {
	principal, ok := ctx.Value(principalContextKey{}).(authn.Principal)
	return principal, ok && validIdentifier(principal.Type) && validIdentifier(principal.ID)
}

// rejectDuplicateJSONKeys запрещает неоднозначную JSON-семантику «последний ключ победил».
func rejectDuplicateJSONKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := scanJSONValue(decoder); err != nil {
		return err
	}
	return ensureSingleJSON(decoder)
}

// scanJSONValue рекурсивно проверяет уникальность ключей каждого JSON object.
func scanJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		return scanJSONObject(decoder)
	case '[':
		return scanJSONArray(decoder)
	default:
		return errors.New("unexpected JSON delimiter")
	}
}

// scanJSONObject проверяет уникальность ключей и рекурсивно валидирует их значения.
func scanJSONObject(decoder *json.Decoder) error {
	seen := make(map[string]struct{})
	for decoder.More() {
		key, err := nextJSONObjectKey(decoder)
		if err != nil {
			return err
		}
		if _, exists := seen[key]; exists {
			return errors.New("duplicate object key")
		}
		seen[key] = struct{}{}
		if err := scanJSONValue(decoder); err != nil {
			return err
		}
	}
	return consumeClosingDelimiter(decoder)
}

// nextJSONObjectKey читает очередной key и отклоняет нарушение JSON object contract.
func nextJSONObjectKey(decoder *json.Decoder) (string, error) {
	token, err := decoder.Token()
	if err != nil {
		return "", err
	}
	key, ok := token.(string)
	if !ok {
		return "", errors.New("object key is not a string")
	}
	return key, nil
}

// scanJSONArray рекурсивно проверяет каждый элемент JSON array.
func scanJSONArray(decoder *json.Decoder) error {
	for decoder.More() {
		if err := scanJSONValue(decoder); err != nil {
			return err
		}
	}
	return consumeClosingDelimiter(decoder)
}

// consumeClosingDelimiter завершает чтение ранее открытого JSON object или array.
func consumeClosingDelimiter(decoder *json.Decoder) error {
	_, err := decoder.Token()
	return err
}

// live сообщает только о работе HTTP process и не проверяет dependencies.
func (h *Handler) live(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ready сообщает о готовности обслуживать authorization requests с PostgreSQL и OPA.
func (h *Handler) ready(w http.ResponseWriter, r *http.Request) {
	if h.readiness == nil || h.readiness(r.Context()) != nil {
		writeError(w, http.StatusServiceUnavailable, "not_ready")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

// validIdentifier проверяет наличие и максимальную длину внешнего identifier.
func validIdentifier(value string) bool {
	value = strings.TrimSpace(value)
	return value != "" && len(value) <= 128
}

// validAction проверяет базовый формат namespaced action; vocabulary проверяет use case.
func validAction(value string) bool {
	value = strings.TrimSpace(value)
	return value != "" && len(value) <= 128 && strings.Contains(value, ":")
}

// ensureSingleJSON отклоняет несколько последовательных JSON documents в одном body.
func ensureSingleJSON(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

// writeError возвращает стабильный публичный code без текста внутренних errors.
func writeError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"error": code})
}

// writeJSON устанавливает JSON content type и кодирует один response object.
func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
