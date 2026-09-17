// Remaining IdP SSO endpoints: OIDC discovery, JWKS, user info, authorization
// codes and revocation.
package idp

import (
	"bytes"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strings"
	"time"

	"secure-sso/internal/config"

	"github.com/gofiber/fiber/v2"
)

// handleOIDCDiscovery serves the IdP's OpenID discovery document.
func (s *IdPServer) handleOIDCDiscovery(c *fiber.Ctx) error {
	issuer := s.tokenHelper.Issuer
	if issuer == "" {
		issuer = config.Get().Issuer()
	}
	jwksUrl := strings.TrimRight(issuer, "/") + "/.well-known/jwks.json"
	cfg := map[string]interface{}{
		"issuer":                                issuer,
		"jwks_uri":                              jwksUrl,
		"response_types_supported":              []string{"code", "token", "id_token"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
	}
	return c.JSON(cfg)
}

// handleJWKS publishes the IdP's token-signing public key, which the broker uses
// to verify tokens before re-signing them.
func (s *IdPServer) handleJWKS(c *fiber.Ctx) error {
	if s.tokenHelper == nil || s.tokenHelper.verifyKey == nil {
		log.Printf("[ERROR/IdP] verifyKey is not initialized")
		return c.Status(http.StatusInternalServerError).SendString("verify key not available")
	}
	jwk, err := rsaPublicKeyToJWK(s.tokenHelper.verifyKey)
	if err != nil {
		log.Printf("[ERROR/IdP] failed to convert RSA key to JWK: %v", err)
		return c.Status(http.StatusInternalServerError).SendString("failed to build jwk")
	}
	resp := map[string]interface{}{
		"keys": []interface{}{jwk},
	}
	return c.JSON(resp)
}

// handleIndex renders the landing page shown to a logged-in user.
func (s *IdPServer) handleIndex(c *fiber.Ctx) error {
	sess, _ := s.store.sessions.Get(c)
	doc := fmt.Sprintf("<!DOCTYPE html><html><head><meta charset=\"utf-8\" /><title>IdP</title></head><body><h1>Hello, %s!</h1><a href=\"/ssso/userinfo\">See your details</a></body></html>", sess.Get("username").(string))
	return c.Type("html").Status(http.StatusOK).SendString(doc)
}

// handleUserInfo renders the user's profile together with every acid they have
// authorized, which is what the revocation page acts on.
func (s *IdPServer) handleUserInfo(c *fiber.Ctx) error {
	sess, err := s.store.sessions.Get(c)
	if err != nil {
		return c.Status(http.StatusInternalServerError).SendString("failed to get session")
	}
	username := sess.Get("username").(string)
	uid := sess.Get("uid").(string)
	user := s.store.users[username]

	type AuthorizedView struct {
		ACID  string
		Scope string
		DEnc  string
	}
	var authViews []AuthorizedView
	authorizedMsgs := s.store.authorized_msgs.GetAll(&uid)
	if len(authorizedMsgs) != 0 {
		for _, a := range authorizedMsgs {
			v := AuthorizedView{}
			v.ACID = a.acid
			v.Scope = a.scope
			v.DEnc = a.OprfEnc
			authViews = append(authViews, v)
		}
	}

	tmplData := map[string]any{
		"Username":   username,
		"Email":      user.Email,
		"UID":        uid,
		"Authorized": authViews,
	}

	tpl, err := template.ParseFiles(staticFile("userinfo.html"))
	if err != nil {
		log.Printf("[ERROR/IdP] Failed to parse template: %v", err)
		return c.Type("html").Status(http.StatusInternalServerError).SendString(s.fmtError(http.StatusInternalServerError, "template parse error"))
	}
	var buf bytes.Buffer
	if err := tpl.Execute(&buf, tmplData); err != nil {
		log.Printf("[ERROR/IdP] Failed to execute template: %v", err)
		return c.Type("html").Status(http.StatusInternalServerError).SendString(s.fmtError(http.StatusInternalServerError, "template execute error"))
	}
	return c.Type("html").Status(http.StatusOK).SendString(buf.String())
}

// handleRevokeAuthorized drops one authorization record, identified by the acid
// in the path, for the logged-in user.
func (s *IdPServer) handleRevokeAuthorized(c *fiber.Ctx) error {
	sess, err := s.store.sessions.Get(c)
	if err != nil {
		return c.Status(http.StatusInternalServerError).SendString("failed to get session")
	}
	uid := sess.Get("uid").(string)
	acid := c.Params("acid")
	if acid == "" {
		return c.Status(http.StatusBadRequest).SendString("missing acid")
	}
	s.store.authorized_msgs.Delete(&uid, &acid)
	return c.SendStatus(http.StatusNoContent)
}

// handleAuthorizeCode records the user's consent for (acid, scope) plus the
// TCA-supplied D_enc and returns a short-lived authorization code.
func (s *IdPServer) handleAuthorizeCode(c *fiber.Ctx) error {
	sess, err := s.store.sessions.Get(c)
	if err != nil {
		log.Printf("[ERROR/IdP] Failed to get session: %v", err)
		return c.Status(http.StatusInternalServerError).SendString("failed to get session")
	}
	acid := sess.Get("acid").(string)
	uid := sess.Get("uid").(string)
	username := sess.Get("username").(string)
	scope := c.Cookies("scope")
	d_enc := c.Query("D_enc")
	if d_enc == "" {
		log.Printf("[ERROR/IdP] Missing D_enc in code request: %s", c.OriginalURL())
		return c.Status(http.StatusBadRequest).SendString("missing D_enc.")
	}
	var email string
	if u, ok := s.store.users[username]; ok && u != nil {
		email = u.Email
	}
	code, err := s.store.codes.SaveCode(d_enc, acid, uid, username, email, scope, 5*time.Minute)
	if err != nil {
		log.Printf("[ERROR/IdP] Failed to save code: %v", err)
		return c.Status(http.StatusInternalServerError).SendString("failed to save code")
	}
	log.Printf("[INFO/IdP] Consent granted; issued authorization code (scope=%s, D_enc bound to acid)", scope)
	return c.Status(http.StatusOK).SendString(code.Code)
}

// fmtError renders an error as a standalone HTML page.
func (s *IdPServer) fmtError(status int, msg string) string {
	tmpl := "<!DOCTYPE html><html><head><meta charset=\"UTF-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\"><title>Error - IdP</title></head><body><h1>Error: %d</h1><p>Sorry, an error occurred while processing your request. Details: %s</p></body></html>"
	return fmt.Sprintf(tmpl, status, msg)
}
