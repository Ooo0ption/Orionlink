// Small RP helpers for error responses and outbound HTTP requests.
package rp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/gofiber/fiber/v2"
)

// ErrorResponse is the JSON body returned for every RP error.
type ErrorResponse struct {
	Error string `json:"error"`
}

// handleError logs a failure and returns it as a JSON error response.
func (s *RPServer) handleError(c *fiber.Ctx, status int, message string) error {
	log.Printf("[ERROR/RP] Status %d: %s", status, message)

	return c.Status(status).JSON(ErrorResponse{
		Error: message,
	})
}

// sendPostRequest posts a JSON body, checks the status code, and decodes the
// response. It takes a context so both request handlers and the startup
// auto-registration can use it.
func (s *RPServer) sendPostRequest(ctx context.Context, url string, requestBody any, expectedStatus int, responseBody any) error {
	body, err := json.Marshal(requestBody)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
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

// sendGetRequest issues a GET, checks the status code, and decodes the JSON
// response into responseBody.
func (s *RPServer) sendGetRequest(ctx context.Context, url string, responseBody any, expectedStatus int) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
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
