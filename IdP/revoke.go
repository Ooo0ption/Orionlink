// IdP authorization-management page: renders a user's stored authorization record
// for review and revocation.
package idp

import (
	"bytes"
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"net/url"

	"github.com/gofiber/fiber/v2"
)

// jsonSafe marks an already-marshalled JSON string as safe to inline in a
// template's <script> block.
func jsonSafe(s string) template.JS { return template.JS(s) }

// handleRevokePage renders the authorization record of the logged-in user. The
// uid comes from the session, so no user is ever served another user's record.
// It picks the record matching the session's acid, falling back to the most
// recent authorization.
func (s *IdPServer) handleRevokePage(c *fiber.Ctx) error {
	sess, err := s.store.sessions.Get(c)
	if err != nil {
		return c.Status(http.StatusInternalServerError).SendString("failed to get session")
	}
	uid, ok := sess.Get("uid").(string)
	if !ok || uid == "" {
		return c.Redirect("/ssso/login?next=" + url.QueryEscape(c.OriginalURL()))
	}
	msgs := s.store.authorized_msgs.GetAll(&uid)
	if len(msgs) == 0 {
		return c.Status(http.StatusNotFound).SendString("no authorization record for this user")
	}
	rec := msgs[len(msgs)-1]
	if acid, ok := sess.Get("acid").(string); ok && acid != "" {
		for _, m := range msgs {
			if m.acid == acid {
				rec = m
				break
			}
		}
	}
	templateJSONData := map[string]string{
		"denc": rec.OprfEnc,
		"uid":  rec.uid,
		"acid": rec.acid,
	}
	jsonBytes, err := json.Marshal(templateJSONData)
	if err != nil {
		return c.Type("html").Status(http.StatusInternalServerError).
			SendString(s.fmtError(http.StatusInternalServerError, "template data marshal error"))
	}
	tmplData := map[string]any{
		"DEnc":     rec.OprfEnc,
		"UID":      rec.uid,
		"ACID":     rec.acid,
		"JSONData": string(jsonBytes),
	}
	tpl, err := template.New("revoke.html").Funcs(template.FuncMap{
		"jsonSafe": jsonSafe,
	}).ParseFiles(staticFile("revoke.html"))
	if err != nil {
		log.Printf("[ERROR/IdP] Failed to parse revoke template: %v", err)
		return c.Type("html").Status(http.StatusInternalServerError).
			SendString(s.fmtError(http.StatusInternalServerError, "template parse error"))
	}
	var buf bytes.Buffer
	if err := tpl.Execute(&buf, tmplData); err != nil {
		log.Printf("[ERROR/IdP] Failed to execute revoke template: %v", err)
		return c.Type("html").Status(http.StatusInternalServerError).
			SendString(s.fmtError(http.StatusInternalServerError, "template execute error"))
	}
	return c.Type("html").Status(http.StatusOK).SendString(buf.String())
}

var _ = fiber.New
