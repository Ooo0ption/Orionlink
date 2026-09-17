// Small IdP helpers for error responses and request decoding.
package idp

import (
	"encoding/json"
	"log"
	comm "secure-sso/internal/common"
	"strings"

	"github.com/gofiber/fiber/v2"
)

// ErrorResponse is the JSON body returned for every IdP error.
type ErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// handleError logs the failure and returns it to the caller as a JSON error.
func (s *IdPServer) handleError(c *fiber.Ctx, status int, message string) error {
	log.Printf("[ERROR/IdP] Status %d: %s", status, message)

	return c.Status(status).JSON(ErrorResponse{
		Error: message,
	})
}

// getRequest decodes a JSON request body into request, rejecting empty or
// wrongly typed bodies with a 400.
func (s *IdPServer) getRequest(c *fiber.Ctx, request any) error {
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
