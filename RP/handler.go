// RP HTTP surface: server construction, route registration, and the login, home
// and refresh handlers.
package rp

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"path/filepath"
	comm "secure-sso/internal/common"
	orionconf "secure-sso/internal/config"
	"secure-sso/internal/protocol"
	"secure-sso/lib"
	"time"

	"github.com/cloudflare/circl/ecc/bls12381"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/session"
)

// RPServer holds the RP's identity and credentials (DomainCred, SecretCred, the
// IdP's public keys) together with its runtime state and browser sessions.
type RPServer struct {
	TID    string
	Domain []byte

	IdentitySk   *bls12381.Scalar
	ServerCredPk comm.ServerCredPk
	IdPAAKEPk    *bls12381.G1

	DomainCred *comm.DomainCredential
	SecretCred *comm.SecretCredential

	config     *SecureSSOConfig
	httpClient *http.Client

	store         *tempStorageService
	sessions      *session.Store
	refreshHelper *RefreshTokenHelper
}

// NewRPLocalServer builds an RP with a fresh in-memory identity, for the
// in-process local-overhead benchmark (no HTTP client, no persistence).
func NewRPLocalServer() *RPServer {
	identitySk := new(bls12381.Scalar)
	if err := identitySk.Random(rand.Reader); err != nil {
		panic(err)
	}
	domain := []byte(orionconf.Get().RP.Browser)
	domainCred := &comm.DomainCredential{
		Domain: domain,
		Sigma:  &lib.PSSignMsg{},
	}
	secretCred := &comm.SecretCredential{
		Domain:     domain,
		IdentitySk: identitySk,
		SigmaBar:   &lib.PSSignMsg{},
	}
	return &RPServer{
		IdentitySk:    identitySk,
		DomainCred:    domainCred,
		SecretCred:    secretCred,
		refreshHelper: NewRefreshTokenHelper(64),
	}
}

// NewRPClientServer builds the RP used by the live server role, restoring the
// identity secret and the IdP's AAKA public key from disk when available.
func NewRPClientServer(config *SecureSSOConfig) *RPServer {
	var pk *bls12381.G1
	var identitySk *bls12381.Scalar

	loadedPk, err := loadIdPAAKEPk()
	if err != nil {
		log.Printf("[INFO/RP] Failed to load IdP AAKE PK from file: %v, using default", err)
	} else {
		pk = loadedPk
		log.Printf("[INFO/RP] Loaded IdP AAKE PK from file")
	}

	loadedSk, err := loadIdentitySk()
	if err != nil {
		log.Printf("[INFO/RP] Failed to load IdentitySk from file: %v, generating new one", err)
		identitySk = new(bls12381.Scalar)
		if err := identitySk.Random(rand.Reader); err != nil {
			panic(fmt.Sprintf("failed to generate IdentitySk: %v", err))
		}
		if err := saveIdentitySk(identitySk); err != nil {
			log.Printf("[WARNING/RP] Failed to save IdentitySk: %v", err)
		} else {
			log.Printf("[INFO/RP] Generated and saved new IdentitySk")
		}
	} else {
		identitySk = loadedSk
		log.Printf("[INFO/RP] Loaded IdentitySk from file")
	}
	httpClient := &http.Client{
		Timeout: 100 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        1000,
			MaxIdleConnsPerHost: 1000,
		},
	}
	domain := []byte(config.RedirectURI)
	domainCred := &comm.DomainCredential{
		Domain: domain,
		Sigma:  &lib.PSSignMsg{},
	}
	secretCred := &comm.SecretCredential{
		Domain:     domain,
		IdentitySk: identitySk,
		SigmaBar:   &lib.PSSignMsg{},
	}
	return &RPServer{
		IdentitySk:    identitySk,
		IdPAAKEPk:     pk,
		DomainCred:    domainCred,
		SecretCred:    secretCred,
		config:        config,
		httpClient:    httpClient,
		store:         NewTempStorageService(),
		refreshHelper: NewRefreshTokenHelper(512),
		sessions: session.New(session.Config{
			CookieHTTPOnly: true,
			Expiration:     24 * time.Hour,
			KeyLookup:      "cookie:rp_session",
		}),
	}
}

// UseSecureSSO fetches the IdP's verification keys and registers every /ssso
// route the RP serves. Load-test endpoints are only mounted under the bench profile.
func (s *RPServer) UseSecureSSO(app *fiber.App) {
	vk1, vk2, err := s.getVks()
	if err != nil {
		log.Fatalf("[ERROR/RP] Get Vks failed from IdP (%s). %s\nPlease ensure IdP server is running on %s", s.config.IdPPubKeyURL, err.Error(), s.config.IdPPubKeyURL)
	}
	s.Init(vk1, vk2)
	secureSSO := app.Group("/ssso")

	secureSSO.Get("/", s.handleIndex)
	secureSSO.Get("/home", s.requireLogin, s.handleHome)
	secureSSO.Get("/register", s.handleRegisterPage)
	secureSSO.Get("/login", s.handleLoginPage)
	secureSSO.Get("/userinfo", s.requireLogin, s.handleCheckAuthorize)

	secureSSO.Post("/registerIdp", s.handleRegisterIdP)
	secureSSO.Post("/registerBroker", s.handleRegisterBroker)
	secureSSO.Get("/registration/status", s.handleRegistrationStatus)

	secureSSO.Get("/login/start", s.handleLogin)

	secureSSO.Post("/login/aake/pok", s.handleAAKEGenPoK)
	secureSSO.Post("/login/aake/unblind", s.handleUnblindAuid)
	secureSSO.Get("/callback", s.handleCallback)
	secureSSO.Get("/refresh", s.requireLogin, s.handleRefresh)

	if orionconf.Get().TestEndpointsEnabled() {
		secureSSO.Post("/test/aake/pok", s.handleAAKEGenPoKForTest)
		secureSSO.Post("/test/aake/fixture", s.handleAAKEGenPoKFixture)
	} else {
		log.Printf("[RP] profile=demo: load-test endpoints disabled (set ORION_PROFILE=bench to enable)")
	}
}

// Init records the RP's domain and the IdP's two PS verification keys.
func (s *RPServer) Init(publicKey1, publicKey2 *lib.PSPublicKey) {
	s.Domain = []byte(s.config.RedirectURI)
	s.ServerCredPk.Vk1 = publicKey1
	s.ServerCredPk.Vk2 = publicKey2
}

// fetchJWKS retrieves the JWKS document from the configured IdP endpoint.
func (s *RPServer) fetchJWKS() (map[string]interface{}, error) {
	resp, err := http.Get(s.config.BrokerJWKSURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks endpoint returned status %d", resp.StatusCode)
	}
	var jwks map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, err
	}
	return jwks, nil
}

// getVks fetches the IdP's PS verification keys, adopting and persisting its
// AAKA public key when the published one differs from the stored copy.
func (s *RPServer) getVks() (*lib.PSPublicKey, *lib.PSPublicKey, error) {
	resp, err := s.httpClient.Get(s.config.IdPPubKeyURL)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to connect to IdP server: %w", err)
	}

	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("idp returned status %d", resp.StatusCode)
	}
	var vkresp protocol.IdPCredKeyResponse
	if err := json.NewDecoder(resp.Body).Decode(&vkresp); err != nil {
		return nil, nil, fmt.Errorf("decode idp response: %w", err)
	}
	if len(vkresp.AAKEPk) > 0 {
		if pk, err := comm.BytesToG1(vkresp.AAKEPk); err != nil {
			log.Printf("[WARN/RP] IdP AAKE PK in /pubkeys is malformed: %v", err)
		} else if s.IdPAAKEPk == nil || !s.IdPAAKEPk.IsEqual(pk) {
			s.IdPAAKEPk = pk
			if err := saveIdPAAKEPk(pk); err != nil {
				log.Printf("[WARN/RP] failed to persist IdP AAKE PK: %v", err)
			}
			log.Printf("[INFO/RP] Adopted IdP AAKE PK from /ssso/pubkeys")
		}
	} else if s.IdPAAKEPk == nil {
		log.Printf("[WARN/RP] IdP published no AAKE PK and none is persisted — logins will fail at X3DH")
	}

	vk1, vk2, err := vkresp.FromJson()
	if err != nil {
		return nil, nil, fmt.Errorf("convert bytes to G1 points: %w", err)
	}
	return vk1, vk2, nil
}

// requireLogin admits a request only if its session carries a logged-in user,
// and otherwise redirects to the login page preserving the original URL.
func (s *RPServer) requireLogin(c *fiber.Ctx) error {
	sess, err := s.sessions.Get(c)
	if err != nil {
		return c.Redirect("/ssso/login?next=" + url.QueryEscape(c.OriginalURL()))
	}
	_, ok := sess.Get("rpuser").(rpUser)
	if !ok {
		return c.Redirect("/ssso/login?next=" + url.QueryEscape(c.OriginalURL()))
	}
	return c.Next()
}

// handleLogin starts a login by redirecting the user to the broker's authorize
// endpoint.
func (s *RPServer) handleLogin(c *fiber.Ctx) error {
	if _, err := s.loadRegistrationData(); err != nil {
		log.Printf("[WARNING/RP] Failed to load registration data: %v", err)
	}

	params := c.Queries()
	uri := s.config.BrokerAuthorizeURL + "?redirect_uri=" + url.QueryEscape(s.config.RedirectURI)
	for k, v := range params {
		uri += "&" + url.QueryEscape(k) + "=" + url.QueryEscape(v)
	}
	state := lib.NewRandomID()
	uri += "&tid=" + url.QueryEscape(s.TID)
	uri += "&state=" + url.QueryEscape(state)
	sess, err := s.sessions.Get(c)
	if err != nil {
		return s.handleError(c, comm.Forbidden, "RP: session error."+err.Error())
	}
	sess.Set("state", state)
	if err := sess.Save(); err != nil {
		return s.handleError(c, comm.Forbidden, "RP: session error."+err.Error())
	}

	log.Printf("[INFO/RP] Login started; sending login request to broker (tid=%s)", s.TID)
	return c.Redirect(uri)
}

// handleHome renders the post-login page from the user data held in the session.
func (s *RPServer) handleHome(c *fiber.Ctx) error {
	sess, err := s.sessions.Get(c)
	if err != nil {
		return c.Status(http.StatusInternalServerError).SendString("failed to get session")
	}
	user, ok := sess.Get("rpuser").(rpUser)
	if !ok {
		return c.Redirect("/ssso/login?next=" + url.QueryEscape(c.OriginalURL()))
	}

	tmplData := map[string]any{
		"Username":    user.Username,
		"Email":       user.Email,
		"Sub":         user.Sub,
		"UIDRP":       user.UID,
		"AccessToken": user.AccessToken,
	}
	tpl, err := template.ParseFiles(staticFile("home.html"))
	if err != nil {
		return c.Type("html").Status(http.StatusInternalServerError).SendString(s.fmtError(http.StatusInternalServerError, "template parse error"))
	}
	var buf bytes.Buffer
	if err := tpl.Execute(&buf, tmplData); err != nil {
		log.Printf("[ERROR/IdP] Failed to execute template: %v", err)
		return c.Type("html").Status(http.StatusInternalServerError).SendString(s.fmtError(http.StatusInternalServerError, "template execute error"))
	}
	return c.Type("html").Status(http.StatusOK).Send(buf.Bytes())
}

// handleIndex serves the RP's landing page.
func (s *RPServer) handleIndex(c *fiber.Ctx) error {
	return c.SendFile(staticFile("index.html"))
}

// handleCheckAuthorize sends the user to the IdP's userinfo page with the access
// token held in the session.
func (s *RPServer) handleCheckAuthorize(c *fiber.Ctx) error {
	sess, err := s.sessions.Get(c)
	if err != nil {
		return c.Status(http.StatusInternalServerError).SendString("failed to get session")
	}
	user, ok := sess.Get("rpuser").(rpUser)
	if !ok {
		return c.Redirect("/ssso/login?next=" + url.QueryEscape(c.OriginalURL()))
	}
	accessToken := user.AccessToken
	userinfoURL := s.config.IdPUserInfoURL + "?access_token=" + accessToken
	return c.Redirect(userinfoURL)
}

// handleRegisterPage serves the RP's registration page.
func (s *RPServer) handleRegisterPage(c *fiber.Ctx) error {
	return c.SendFile(staticFile("register.html"))
}

// handleLoginPage serves the RP's login page.
func (s *RPServer) handleLoginPage(c *fiber.Ctx) error {
	return c.SendFile(staticFile("login.html"))
}

// fmtError renders an error as a JSON string body.
func (s *RPServer) fmtError(status int, msg string) string {
	return fmt.Sprintf(`{"error": "%s", "status": %d}`, msg, status)
}

// handleRefresh runs a token refresh against the broker and replaces the access
// token held in the RP session.
func (s *RPServer) handleRefresh(c *fiber.Ctx) error {
	if s.refreshHelper == nil {
		return s.handleError(c, comm.ServerError, "refresh helper not initialized")
	}
	sess, err := s.sessions.Get(c)
	if err != nil {
		return s.handleError(c, comm.Forbidden, "RP: session error."+err.Error())
	}
	user, ok := sess.Get("rpuser").(rpUser)
	if !ok || user.UID == "" {
		return s.handleError(c, comm.Forbidden, "RP: user not logged in")
	}
	if s.TID == "" {
		return s.handleError(c, comm.BadRequest, "RP: missing tid")
	}

	brokerRefreshURL := s.config.BrokerRefreshURL
	req := &protocol.RefreshTokenFromRPRequest{
		TID:   s.TID,
		UIDRP: user.UID,
	}
	brokerResp := &protocol.RefreshTokenToRPResponse{}
	if err := s.sendPostRequest(c.Context(), brokerRefreshURL, req, http.StatusOK, brokerResp); err != nil {
		return s.handleError(c, comm.BadRequest, "RP: refresh request failed. "+err.Error())
	}

	newAccessToken, err := s.refreshHelper.DecryptResponse(brokerResp)
	if err != nil {
		return s.handleError(c, comm.Unauthorized, "RP: refresh decrypt failed. "+err.Error())
	}

	user.AccessToken = newAccessToken
	sess.Set("rpuser", user)
	if err := sess.Save(); err != nil {
		return s.handleError(c, comm.ServerError, "RP: failed to save session. "+err.Error())
	}

	return c.JSON(fiber.Map{
		"access_token": newAccessToken,
	})
}

// staticFile resolves a page in the RP's static directory for the active profile
// and asset directory.
func staticFile(name string) string {
	return filepath.Join(orionconf.Get().StaticDir("RP"), name)
}
