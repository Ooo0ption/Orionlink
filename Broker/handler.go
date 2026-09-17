// Broker HTTP surface: server construction, route registration, and the login,
// discovery, JWKS and refresh handlers.
package broker

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"path/filepath"
	comm "secure-sso/internal/common"
	orionconf "secure-sso/internal/config"
	"secure-sso/internal/protocol"
	"secure-sso/lib"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/session"
)

// BrokerServer holds the broker's runtime state: outbound HTTP client, token and
// refresh helpers, in-memory stores, deployment config and browser sessions.
type BrokerServer struct {
	httpClient    *http.Client
	tokenHelper   *TokenHelper
	refreshHelper *RefreshTokenHelper
	store         *tempStorageService
	config        *SecureSSOConfig

	sessions *session.Store
}

// NewBrokerLocalServer builds a broker with in-memory state only, for the
// in-process local-overhead benchmark (no HTTP client, no persistence).
func NewBrokerLocalServer() *BrokerServer {
	return &BrokerServer{
		refreshHelper: NewRefreshTokenHelper(),
		store:         NewTempStorageService(),
	}
}

// NewBrokerClientServer builds the broker used by the live server role and
// restores previously registered RP identities from disk.
func NewBrokerClientServer(tokenHelper *TokenHelper, config *SecureSSOConfig) *BrokerServer {
	httpClient := &http.Client{
		Timeout: 100 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        1000,
			MaxIdleConnsPerHost: 1000,
		},
	}
	server := &BrokerServer{
		httpClient:    httpClient,
		tokenHelper:   tokenHelper,
		refreshHelper: NewRefreshTokenHelper(),
		store:         NewTempStorageService(),
		config:        config,
		sessions: session.New(session.Config{
			CookieHTTPOnly: true,
			Expiration:     24 * 3600,
		}),
	}

	if regData, err := server.loadRegistrationData(); err == nil {
		if err := server.restoreRPIdentities(regData); err != nil {
			log.Printf("[WARNING/Broker] Failed to restore RP identities: %v", err)
		} else {
			log.Printf("[INFO/Broker] Loaded %d registered RPs from file", len(regData.RegisteredRPs))
		}
	} else {
		log.Printf("[INFO/Broker] No existing registration data found or error loading: %v", err)
	}

	return server
}

// UseSecureSSO registers every /ssso route the broker serves. Load-test
// endpoints are only mounted when the bench profile is active.
func (s *BrokerServer) UseSecureSSO(app *fiber.App) {
	secureSSO := app.Group("/ssso")

	secureSSO.Get("/pubconfig.js", handlePubConfig)

	secureSSO.Get("/.well-known/openid-configuration", s.handleOIDCDiscovery)
	secureSSO.Get("/.well-known/jwks.json", s.handleJWKS)

	secureSSO.Post("/rpregister", s.handleRegisterRP)

	secureSSO.Get("/authorize", s.handleRandomizeRPID)
	secureSSO.Get("/login", s.handleLogin)
	secureSSO.Post("/codetoken", s.handleTokenFromIdP)
	secureSSO.Post("/token", s.handleTokenFromBroker)
	secureSSO.Post("/refresh", s.handleRefreshTokenFromRP)

	if orionconf.Get().TestEndpointsEnabled() {
		secureSSO.Get("/randomizeRPIDForTest", s.handleRandomizeRPIDForTest)
	} else {
		log.Printf("[Broker] profile=demo: load-test endpoints disabled (set ORION_PROFILE=bench to enable)")
	}
}

// handleRandomizeRPID serves the page that starts a login: the broker randomizes
// the RP's DomainCred into a per-session acid and hands back a session_id.
func (s *BrokerServer) handleRandomizeRPID(c *fiber.Ctx) error {
	tid := c.Query("tid")
	state := c.Query("state")
	if tid == "" || s.store.rpIdentity[tid] == nil {
		return s.handleError(c, comm.BadRequest, "RP need to register first")
	}

	rpRedirectUrl := c.Query("redirect_uri")
	sData, err := generateSessionData(s, tid, state, rpRedirectUrl)
	if err != nil {
		return s.handleError(c, comm.InternalError, "session data generate failed"+err.Error())
	}

	sessionID, err := GenerateCode()
	if err != nil {
		return s.handleError(c, comm.InternalError, "failed to generate session_id: "+err.Error())
	}

	s.store.sessionData[sessionID] = sData

	c.ClearCookie("session_id")

	cookie := new(fiber.Cookie)
	cookie.Name = "session_id"
	cookie.Value = sessionID
	cookie.Expires = time.Now().Add(5 * time.Minute)
	cookie.SameSite = "Lax"
	cookie.HTTPOnly = false
	c.Cookie(cookie)

	c.ClearCookie("t")
	cookie.Name = "t"
	cookie.Value = comm.BytesToString(comm.ScalarToBytes(sData.t))
	cookie.Expires = time.Now().Add(5 * time.Minute)
	cookie.SameSite = "Lax"
	cookie.HTTPOnly = false
	c.Cookie(cookie)

	c.ClearCookie("rp_domain")
	cookie.Name = "rp_domain"
	cookie.Value = comm.BytesToString(s.store.rpIdentity[tid].DomainCred.Domain)
	cookie.Expires = time.Now().Add(5 * time.Minute)
	cookie.SameSite = "Lax"
	cookie.HTTPOnly = false
	c.Cookie(cookie)

	return c.SendFile(staticFile("auth.html"))
}

// handleLogin checks the session state and redirects the user to the IdP
// authorize endpoint, carrying the randomized credential.
func (s *BrokerServer) handleLogin(c *fiber.Ctx) error {
	sessionID := c.Query("session_id")
	if sessionID == "" {
		sessionID = c.Cookies("session_id")
	}

	if sessionID == "" {
		return s.handleError(c, comm.BadRequest, "session_id not found")
	}

	sData, ok := s.store.sessionData[sessionID]
	if !ok || sData == nil {
		log.Printf("[ERROR/Broker] Session data not found for session_id: %s", sessionID)
		return s.handleError(c, comm.BadRequest, "session data not found or invalid")
	}

	log.Printf("[INFO/Broker] Accepted login; randomized RP credential into a fresh session pseudonym acid")

	acidString := `{"Sigma1":"` + comm.G1ToString(sData.randSig.Sigma1)
	acidString += `","Sigma2":"` + comm.G1ToString(sData.randSig.Sigma2) + `"}`

	scopes := s.store.rpIdentity[sData.tid].Scopes
	scopeString := ""
	for _, scope := range scopes {
		scopeString += fmt.Sprintf("%s ", scope)
	}
	redirect_url := fmt.Sprintf(`%s?acid=%s&redirect_uri=%s&scope=%s`, s.config.IdPAuthorizeURL, url.QueryEscape(acidString), url.QueryEscape(s.tokenHelper.Issuer+"/ssso/callback"), url.QueryEscape(scopeString))
	log.Printf("[INFO/Broker] Forwarding login request to IdP with RP session pseudonym acid (RP identity hidden)")
	return c.Redirect(redirect_url)
}

// generateSessionData validates the RP's redirect_uri against its DomainCred and
// randomizes that credential into the per-session (t, k, acid) triple.
func generateSessionData(s *BrokerServer, tid string, state string, rpRedirectUrl string) (sData *brokerSessionData, err error) {
	domainCred := s.store.rpIdentity[tid].DomainCred
	domainStr := string(domainCred.Domain)
	if domainStr != rpRedirectUrl {
		return nil, errors.New("RP redirect_uri not match")
	}
	rsign, k, t, err := lib.RandomizeSig(domainCred.Sigma)
	if err != nil {
		return nil, errors.New("randomize sig failed")
	}
	sData = &brokerSessionData{
		t:       t,
		k:       k,
		randSig: rsign,
		tid:     tid,
		state:   state,
	}
	return sData, nil
}

// handleOIDCDiscovery serves the broker's OpenID discovery document, so RPs can
// locate the issuer and the JWKS used to verify broker-signed tokens.
func (s *BrokerServer) handleOIDCDiscovery(c *fiber.Ctx) error {
	issuer := s.tokenHelper.Issuer
	if issuer == "" {
		issuer = orionconf.Get().Broker.Browser
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

// handleJWKS publishes the broker's RSA token-signing public key as a JWK set.
func (s *BrokerServer) handleJWKS(c *fiber.Ctx) error {
	if s.tokenHelper == nil || s.tokenHelper.verifyKey == nil {
		log.Printf("[ERROR/Broker] verifyKey is not initialized")
		return c.Status(http.StatusInternalServerError).SendString("verify key not available")
	}
	jwk, err := rsaPublicKeyToJWK(s.tokenHelper.verifyKey)
	if err != nil {
		log.Printf("[ERROR/Broker] failed to convert RSA key to JWK: %v", err)
		return c.Status(http.StatusInternalServerError).SendString("failed to build jwk")
	}
	resp := map[string]interface{}{
		"keys": []interface{}{jwk},
	}
	return c.JSON(resp)
}

// handleRefreshTokenFromRP receives a refresh trigger from the RP and relays the
// encrypted refresh result back to it. The broker never decrypts the payload.
func (s *BrokerServer) handleRefreshTokenFromRP(c *fiber.Ctx) error {
	req := &protocol.RefreshTokenFromRPRequest{}
	if err := s.getRequest(c, req); err != nil {
		return s.handleError(c, comm.BadRequest, "invalid request body"+err.Error())
	}
	if req.TID == "" || req.UIDRP == "" {
		return s.handleError(c, comm.BadRequest, "missing tid or uid_rp")
	}
	if s.refreshHelper == nil {
		s.refreshHelper = NewRefreshTokenHelper()
	}

	rpInfo, ok := s.store.rpIdentity[req.TID]
	if !ok || rpInfo == nil || rpInfo.UserStore == nil {
		return s.handleError(c, comm.NotFound, "RP not found for tid")
	}
	user, ok := rpInfo.UserStore.GetUser(req.UIDRP)
	if !ok || user == nil || user.Token == nil || user.Token.RefreshToken == "" {
		return s.handleError(c, comm.NotFound, "refresh token not found for uid")
	}
	log.Printf("[INFO/Broker] Refresh: relaying ratcheted token request to IdP on the RP's behalf (broker cannot read the token)")

	resp, err := s.refreshHelper.RefreshWithIdP(
		s,
		c,
		req.TID,
		rpInfo.RPDHPks,
		user.Token.RefreshToken,
	)
	if err != nil {
		return s.handleError(c, comm.BadRequest, "refresh with idp failed: "+err.Error())
	}
	return c.Status(comm.StatusOK).JSON(resp)
}

// handlePubConfig serves the deployment's public routing information as a script
// that sets window.ORION, so static pages carry no compiled-in addresses.
func handlePubConfig(c *fiber.Ctx) error {
	c.Set("Content-Type", "application/javascript; charset=utf-8")
	c.Set("Cache-Control", "no-store")
	return c.SendString(orionconf.Get().PubConfigJS())
}

// staticFile resolves a page in the Broker's static directory for the active
// profile and asset directory.
func staticFile(name string) string {
	return filepath.Join(orionconf.Get().StaticDir("Broker"), name)
}
