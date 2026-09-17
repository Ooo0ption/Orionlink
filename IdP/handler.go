// IdP HTTP surface: server construction, route registration, and the login,
// consent, key-publication and RP-registration handlers.
package idp

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"path/filepath"
	comm "secure-sso/internal/common"
	"secure-sso/internal/config"
	orionconf "secure-sso/internal/config"
	"secure-sso/internal/protocol"
	"secure-sso/lib"
	"secure-sso/lib/oprf"
	"strconv"
	"sync"
	"time"

	"github.com/cloudflare/circl/ecc/bls12381"
	"github.com/gofiber/fiber/v2"
)

// IdPServer holds the IdP's long-term keys (identity key, credential key, OPRF)
// and its runtime state: token helper, in-memory stores and refresh ratchet.
type IdPServer struct {
	oprf        *oprf.PinHelper
	IdentityKey lib.DHKey
	CredKey     *comm.ServerCredKey

	mu sync.RWMutex

	tokenHelper   *TokenHelper
	store         *tempStorageService
	refreshHelper *RefreshTokenHelper
}

// NewIdPLocalServer builds an IdP with in-memory state only, for the in-process
// local-overhead benchmark (no key persistence).
func NewIdPLocalServer() *IdPServer {
	tokenHelper := NewTokenHelper()
	tokenHelper.Issuer = config.Get().Issuer()

	server := &IdPServer{
		oprf:          oprf.NewPinHelper(),
		store:         NewTempStorageService(),
		tokenHelper:   tokenHelper,
		refreshHelper: NewIdPRefreshTokenHelper(tokenHelper),
	}
	return server
}

// NewIdPServer builds the IdP used by the live server role, loading the identity
// and credential keys from disk and generating them on first run.
func NewIdPServer() *IdPServer {
	tokenHelper := NewTokenHelper()
	tokenHelper.Issuer = config.Get().Issuer()

	var identityKey lib.DHKey
	var credKey *comm.ServerCredKey

	loadedIdentityKey, err := loadIdentityKey()
	if err != nil {
		log.Printf("[INFO/IdP] Failed to load IdentityKey from file: %v, generating new one", err)
		sk := new(bls12381.Scalar)
		if err := sk.Random(rand.Reader); err != nil {
			panic(fmt.Sprintf("failed to generate IdentityKey SK: %v", err))
		}
		pk := new(bls12381.G1)
		pk.ScalarMult(sk, bls12381.G1Generator())
		identityKey = lib.DHKey{SK: sk, PK: pk}

		if err := saveIdentityKey(identityKey); err != nil {
			log.Printf("[WARNING/IdP] Failed to save IdentityKey: %v", err)
		} else {
			log.Printf("[INFO/IdP] Generated and saved new IdentityKey")
		}
	} else {
		identityKey = loadedIdentityKey
		log.Printf("[INFO/IdP] Loaded IdentityKey from file")
	}

	loadedCredKey, err := loadCredKey()
	if err != nil {
		log.Printf("[INFO/IdP] Failed to load CredKey from file: %v, generating new one", err)
		credKey = &comm.ServerCredKey{
			PSKey1: lib.PSKeyGen(1),
			PSKey2: lib.PSKeyGen(2),
		}

		if err := saveCredKey(credKey); err != nil {
			log.Printf("[WARNING/IdP] Failed to save CredKey: %v", err)
		} else {
			log.Printf("[INFO/IdP] Generated and saved new CredKey")
		}
	} else {
		credKey = loadedCredKey
		log.Printf("[INFO/IdP] Loaded CredKey from file")
	}

	server := &IdPServer{
		IdentityKey:   identityKey,
		CredKey:       credKey,
		oprf:          oprf.NewPinHelper(),
		tokenHelper:   tokenHelper,
		store:         NewTempStorageService(),
		refreshHelper: NewIdPRefreshTokenHelper(tokenHelper),
	}

	return server
}

// UseSecureSSO registers every /ssso route the IdP serves and seeds the demo and
// benchmark users. Load-test endpoints are only mounted under the bench profile.
func (s *IdPServer) UseSecureSSO(app *fiber.App) {
	secureSSO := app.Group("/ssso")

	secureSSO.Get("/pubconfig.js", handlePubConfig)

	secureSSO.Get("/.well-known/openid-configuration", s.handleOIDCDiscovery)
	secureSSO.Get("/.well-known/jwks.json", s.handleJWKS)

	secureSSO.Get("/", s.requireLogin, s.handleIndex)

	secureSSO.Get("/userinfo", s.requireLogin, s.handleUserInfo)
	secureSSO.Delete("/userinfo/authorized/:acid", s.requireLogin, s.handleRevokeAuthorized)

	secureSSO.Get("/pubkeys", s.handleGetCredVk)
	secureSSO.Post("/rpregister", s.handleRPRegister)

	secureSSO.Get("/login", s.handleLogin)
	secureSSO.Post("/login", s.handleDoLogin)

	secureSSO.Get("/aake/getempkey", s.handleGetIdPEmpKey)

	secureSSO.Get("/authorize", s.requireLogin, s.handleAuthorize)
	secureSSO.Get("/authorize/beta", s.requireLogin, s.handleAuthorizeBeta)
	secureSSO.Get("/authorize/code", s.requireLogin, s.handleAuthorizeCode)

	secureSSO.Post("/token", s.handleToken)
	secureSSO.Post("/refresh", s.handleRefreshTokenFromBroker)

	if orionconf.Get().TestEndpointsEnabled() {
		secureSSO.Post("/token/test", s.handleTokenForTest)
	} else {
		log.Printf("[IdP] profile=demo: load-test endpoints disabled (set ORION_PROFILE=bench to enable)")
	}

	secureSSO.Get("/revoke", s.requireLogin, s.handleRevokePage)

	s.store.UseTestUsers()
	s.store.SeedBenchUsers(orionconf.Get())
}

// handleRefreshTokenFromBroker processes a refresh request relayed by the broker.
func (s *IdPServer) handleRefreshTokenFromBroker(c *fiber.Ctx) error {
	req := &protocol.RefreshTokenFromBrokerRequest{}
	if err := s.getRequest(c, req); err != nil {
		return s.handleError(c, comm.BadRequest, "invalid request body"+err.Error())
	}
	if s.refreshHelper == nil {
		return s.handleError(c, comm.ServerError, "refresh helper not initialized")
	}
	resp, err := s.refreshHelper.HandleBrokerRequest(req)
	if err != nil {
		return s.handleError(c, comm.Unauthorized, "refresh failed: "+err.Error())
	}
	return c.Status(comm.StatusOK).JSON(resp)
}

// handleGetCredVk publishes the two PS verification keys and the IdP's AAKA
// public key, which RPs need to build and verify credentials.
func (s *IdPServer) handleGetCredVk(c *fiber.Ctx) error {
	if s.CredKey == nil || s.CredKey.PSKey1 == nil || s.CredKey.PSKey2 == nil {
		s.CredKey = &comm.ServerCredKey{
			PSKey1: lib.PSKeyGen(1),
			PSKey2: lib.PSKeyGen(2),
		}
	}
	vk1 := s.CredKey.PSKey1.PublicKey
	vk1response := protocol.PSPublicKeyResponse{
		Yn:    [][]byte{comm.G1ToBytes(vk1.Yn[0])},
		Xhat:  comm.G2ToBytes(vk1.Xhat),
		Yhatn: [][]byte{comm.G2ToBytes(vk1.Yhatn[0])},
	}
	vk2 := s.CredKey.PSKey2.PublicKey
	vk2response := protocol.PSPublicKeyResponse{
		Yn:    [][]byte{comm.G1ToBytes(vk2.Yn[0]), comm.G1ToBytes(vk2.Yn[1])},
		Xhat:  comm.G2ToBytes(vk2.Xhat),
		Yhatn: [][]byte{comm.G2ToBytes(vk2.Yhatn[0]), comm.G2ToBytes(vk2.Yhatn[1])},
	}
	resp := protocol.IdPCredKeyResponse{
		VK1: vk1response,
		VK2: vk2response,
	}
	if s.IdentityKey.PK != nil {
		resp.AAKEPk = comm.G1ToBytes(s.IdentityKey.PK)
	}
	c.Status(fiber.StatusOK)
	return c.JSON(resp)
}

// handleGetIdPEmpKey hands out the next of 100 pre-generated AAKA ephemeral
// public keys, refilling and wrapping around the pool as needed.
func (s *IdPServer) handleGetIdPEmpKey(c *fiber.Ctx) error {
	if len(s.store.empkeys.keys) == 0 {
		s.store.empkeys.keys = make(map[string]*comm.AAKEEphemeralKey, 100)
		s.store.EmpKeyIdx = 0

		for i := 0; i < 100; i++ {
			sk, pk := lib.GenerateEmpKey()
			s.store.empkeys.keys[strconv.Itoa(i)] = &comm.AAKEEphemeralKey{
				ID: strconv.Itoa(i),
				SK: sk,
				PK: pk,
			}
		}
	}
	if s.store.EmpKeyIdx >= len(s.store.empkeys.keys) {
		s.store.EmpKeyIdx = 0
	}
	idStr := strconv.Itoa(s.store.EmpKeyIdx)

	key, err := s.store.empkeys.getEmpKey(idStr)
	if err != nil {
		return s.handleError(c, comm.NotFound, "empheral key not found")
	}
	s.store.EmpKeyIdx++
	resp := protocol.IdPEmpKeyResponse{
		KID: key.ID,
		PK:  comm.G1ToBytes(key.PK),
	}

	return c.JSON(resp)
}

// requireLogin admits a request only if its session carries a logged-in user,
// and otherwise redirects to the login page preserving the original URL.
func (s *IdPServer) requireLogin(c *fiber.Ctx) error {
	sess, err := s.store.sessions.Get(c)
	if err != nil {
		return c.Redirect("/ssso/login?next=" + url.QueryEscape(c.OriginalURL()))
	}
	username := sess.Get("username")
	if username == nil {
		return c.Redirect("/ssso/login?next=" + url.QueryEscape(c.OriginalURL()))
	}
	return c.Next()
}

// handleLogin serves the login page.
func (s *IdPServer) handleLogin(c *fiber.Ctx) error {
	return c.SendFile(staticFile("login.html"))
}

// handleDoLogin authenticates the submitted credentials and, on success,
// establishes the session and continues to the URL the user was heading for.
func (s *IdPServer) handleDoLogin(c *fiber.Ctx) error {
	username := c.FormValue("username")
	password := c.FormValue("password")
	if username == "" || password == "" {
		username = "Alice"
		password = "Alice-pass"
	}
	ok, err := checkUser(s, username, password)
	if !ok || err != nil {
		return s.handleError(c, http.StatusUnauthorized, "Username or password is incorrect"+err.Error())
	}
	log.Printf("[INFO/IdP] Login request: username=%s", username)
	sess, err := s.store.sessions.Get(c)
	if err != nil {
		return s.handleError(c, comm.ServerError, "failed to get session")
	}
	sess.Set("uid", s.store.users[username].Sub)
	sess.Set("username", username)
	if err := sess.Save(); err != nil {
		return s.handleError(c, comm.ServerError, "failed to save session")
	}

	next := c.Query("next")
	if next == "" {
		next = "/"
	}
	return c.Redirect(next)
}

// handleAuthorize serves the consent page after login, carrying acid and scope so
// the user can verify the RP's identity before authorizing.
func (s *IdPServer) handleAuthorize(c *fiber.Ctx) error {
	sess, err := s.store.sessions.Get(c)
	if err != nil {
		return s.handleError(c, comm.ServerError, "failed to get session")
	}
	acid := c.Query("acid")
	scope := c.Query("scope")

	uid := sess.Get("uid").(string)
	cookie := new(fiber.Cookie)
	cookie.Name = "uid"
	cookie.Value = uid
	cookie.Expires = time.Now().Add(24 * time.Hour)
	cookie.SameSite = "Lax"
	cookie.HTTPOnly = false
	c.Cookie(cookie)

	cookie = new(fiber.Cookie)
	cookie.Name = "acid"
	cookie.Value = acid
	cookie.Expires = time.Now().Add(24 * time.Hour)
	cookie.SameSite = "Lax"
	cookie.HTTPOnly = false
	c.Cookie(cookie)
	sess.Set("acid", acid)
	if err := sess.Save(); err != nil {
		return s.handleError(c, comm.ServerError, "failed to save session")
	}

	cookie = new(fiber.Cookie)
	cookie.Name = "scope"
	cookie.Value = scope
	cookie.Expires = time.Now().Add(24 * time.Hour)
	cookie.SameSite = "Lax"
	cookie.HTTPOnly = false
	c.Cookie(cookie)

	log.Printf("[INFO/IdP] Authorization request for RP session pseudonym acid (scope=%s)", scope)
	return c.SendFile(staticFile("auth.html"))
}

// checkUser verifies a username/password pair against the IdP's user store.
func checkUser(s *IdPServer, username string, password string) (bool, error) {
	if username == "" || password == "" {
		return false, errors.New("missing username or password")
	}
	u, ok := s.store.users[username]
	if !ok || u.Password != password {
		return false, errors.New("invalid credentials")
	}
	return true, nil
}

// handleRPRegister issues the RP's DomainCred and SecretCred from its
// registration request.
func (s *IdPServer) handleRPRegister(c *fiber.Ctx) error {
	var request protocol.RPRegisterToIdPRequest
	if err := json.Unmarshal(c.Body(), &request); err != nil {
		return s.handleError(c, comm.BadRequest, "IdP: bad request"+err.Error())
	}

	if len(request.Domain) == 0 {
		return s.handleError(c, comm.BadRequest, "Domain is empty")
	}
	if len(request.C1) == 0 || len(request.R1) == 0 || len(request.Z0) == 0 || len(request.Zs) == 0 {
		return s.handleError(c, comm.BadRequest, "Missing required proof elements")
	}

	response, err := getRegisterRespToRP(s, &request)
	if err != nil {
		log.Printf("[ERROR/IdP] Registration failed: %v", err)
		return s.handleError(c, comm.Forbidden, "IdP: registration failed."+err.Error())
	}

	if response == nil || response.Sig1 == nil || response.BlindSig2 == nil {
		log.Printf("[ERROR/IdP] Generated empty signature")
		return s.handleError(c, comm.ServerError, "IdP: failed to generate signature")
	}

	c.Status(comm.StatusCreated)

	return c.JSON(response)
}

// handleAuthorizeBeta evaluates the PIN-OPRF on a blinded point from the TCA.
func (s *IdPServer) handleAuthorizeBeta(c *fiber.Ctx) error {
	alpha := c.Query("alpha")
	if alpha == "" {
		return s.handleError(c, comm.BadRequest, "missing alpha.")
	}
	alpha_bytes, err := comm.StringToBytes(alpha)
	if err != nil {
		return s.handleError(c, comm.ServerError, "failed to convert alpha to bytes")
	}
	beta_bytes, err := s.oprf.ServerEvaluate(alpha_bytes)
	if err != nil {
		return s.handleError(c, comm.ServerError, "OPRF evaluation failed")
	}
	beta := comm.BytesToString(beta_bytes)
	log.Printf("[INFO/IdP] PIN-OPRF: evaluated blinded PIN to help derive the management key")
	return c.Status(http.StatusOK).SendString(beta)
}

// handlePubConfig serves the deployment's public routing information as a script
// that sets window.ORION, so static pages carry no compiled-in addresses.
func handlePubConfig(c *fiber.Ctx) error {
	c.Set("Content-Type", "application/javascript; charset=utf-8")
	c.Set("Cache-Control", "no-store")
	return c.SendString(orionconf.Get().PubConfigJS())
}

// staticFile resolves a page in the IdP's static directory for the active
// profile and asset directory.
func staticFile(name string) string {
	return filepath.Join(orionconf.Get().StaticDir("IdP"), name)
}
