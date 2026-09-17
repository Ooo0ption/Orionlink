// Small Broker helpers for error responses and HTTP request/response plumbing.
package broker

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	comm "secure-sso/internal/common"
	"strings"

	"github.com/gofiber/fiber/v2"
)

// ErrorResponse is the JSON body returned for every broker error.
type ErrorResponse struct {
	Error string `json:"error"`
}

// handleError logs the failure and returns it to the caller as a JSON error.
func (s *BrokerServer) handleError(c *fiber.Ctx, status int, message string) error {
	log.Printf("[ERROR/Broker] Status %d: %s", status, message)

	return c.Status(status).JSON(ErrorResponse{
		Error: message,
	})
}

// getRequest decodes a JSON request body into request, rejecting empty or
// wrongly typed bodies with a 400.
func (s *BrokerServer) getRequest(c *fiber.Ctx, request any) error {
	if !strings.Contains(c.Get("Content-Type"), "application/json") {
		return s.handleError(c, comm.BadRequest, "IdP: expected application/json")
	}
	body := c.Body()
	if body == nil || len(body) == 0 {
		return s.handleError(c, comm.BadRequest, "IdP: empty body")
	}
	if err := json.Unmarshal(body, request); err != nil {
		return s.handleError(c, comm.BadRequest, "IdP: invalid json format or empty body")
	}
	return nil
}

// sendPostRequest POSTs requestBody as JSON to url and decodes the reply into
// responseBody, failing if the status differs from expectedStatus.
func (s *BrokerServer) sendPostRequest(c *fiber.Ctx, url string, requestBody any, expectedStatus int, responseBody any) error {
	body, err := json.Marshal(requestBody)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(c.Context(), http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("http request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != expectedStatus {
		raw, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("idp returned status %d, body: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}

	if err := json.NewDecoder(resp.Body).Decode(responseBody); err != nil {
		return fmt.Errorf("decode idp response: %w", err)
	}

	return nil
}
