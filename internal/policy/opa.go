package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/iriabov5/aegispolicy/internal/authorization"
)

// ErrInvalidResponse означает, что OPA ответила данными вне согласованного decision contract.
var ErrInvalidResponse = errors.New("invalid OPA response")

// OPA реализует policy evaluation и readiness check через переиспользуемый HTTP client.
type OPA struct {
	baseURL string
	url     string
	client  *http.Client
}

// NewOPA создаёт адаптер для указанного OPA base URL и настроенного HTTP client.
func NewOPA(url string, client *http.Client) *OPA {
	baseURL := strings.TrimRight(url, "/")
	return &OPA{baseURL: baseURL, url: baseURL + "/v1/data/aegispolicy/authorization/decision", client: client}
}

// Ready проверяет health OPA и загрузку policy bundles в пределах переданного context.
func (o *OPA) Ready(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, o.baseURL+"/health?bundles=true", nil)
	if err != nil {
		return fmt.Errorf("create OPA health request: %w", err)
	}
	resp, err := o.client.Do(req)
	if err != nil {
		return fmt.Errorf("check OPA health: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("OPA health returned status %d", resp.StatusCode)
	}
	return nil
}

// Evaluate отправляет версионированный input и принимает только одно строго корректное решение.
func (o *OPA) Evaluate(ctx context.Context, input authorization.PolicyInput) (authorization.PolicyDecision, error) {
	body, err := json.Marshal(struct {
		Input authorization.PolicyInput `json:"input"`
	}{Input: input})
	if err != nil {
		return authorization.PolicyDecision{}, fmt.Errorf("encode OPA input: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.url, bytes.NewReader(body))
	if err != nil {
		return authorization.PolicyDecision{}, fmt.Errorf("create OPA request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := o.client.Do(req)
	if err != nil {
		return authorization.PolicyDecision{}, fmt.Errorf("call OPA: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return authorization.PolicyDecision{}, fmt.Errorf("OPA returned status %d", resp.StatusCode)
	}

	var envelope struct {
		Result *authorization.PolicyDecision `json:"result"`
	}
	decoder := json.NewDecoder(io.LimitReader(resp.Body, 64<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return authorization.PolicyDecision{}, fmt.Errorf("%w: decode: %v", ErrInvalidResponse, err)
	}
	if envelope.Result == nil || !validDecision(*envelope.Result) {
		return authorization.PolicyDecision{}, ErrInvalidResponse
	}
	if err := ensureEOF(decoder); err != nil {
		return authorization.PolicyDecision{}, fmt.Errorf("%w: %v", ErrInvalidResponse, err)
	}
	return *envelope.Result, nil
}

// validDecision запрещает неизвестный outcome и неполные explainability metadata.
func validDecision(d authorization.PolicyDecision) bool {
	return (d.Decision == authorization.Allow || d.Decision == authorization.Deny) &&
		len(d.Reasons) > 0 && d.PolicyName != "" && d.PolicyRevision != ""
}

// ensureEOF отклоняет дополнительные JSON values после ожидаемого response envelope.
func ensureEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}
