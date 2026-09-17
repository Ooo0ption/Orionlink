package idp

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
)

type OIDCIdPServer struct {
	tokenHelper *TokenHelper
	storage     map[string]*OIDCAuthorizationCode // code -> authorization data
	clients     map[string]*Client                // client_id -> client info
	issuer      string
	users       map[string]*User // username -> user info
	usersBySub  map[string]*User // sub -> user info
}

type OIDCAuthorizationCode struct {
	Code                string
	ClientID            string
	RedirectURI         string
	Scope               string
	UserID              string
	ExpiresAt           time.Time
	CodeChallenge       string
	CodeChallengeMethod string
}

type Client struct {
	ClientID     string
	ClientSecret string
	RedirectURIs []string
	Name         string
	ClientType   string // "broker" or "rp"
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

type ErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

func NewOIDCIdPServer() *OIDCIdPServer {
	tokenHelper := NewTokenHelper()
	tokenHelper.Issuer = "http://localhost:14930"

	server := &OIDCIdPServer{
		tokenHelper: tokenHelper,
		storage:     make(map[string]*OIDCAuthorizationCode),
		clients:     make(map[string]*Client),
		issuer:      "http://localhost:14930",
		users:       make(map[string]*User),
		usersBySub:  make(map[string]*User),
	}

	// 加载用户数据
	if err := server.loadUsers(); err != nil {
		log.Printf("[ERROR/IdP] Failed to load users: %v", err)
	}

	// 加载已注册的客户端（RP和Broker）
	if err := server.loadClients(); err != nil {
		log.Printf("[WARNING/IdP] Failed to load clients: %v", err)
	} else {
		log.Printf("[INFO/IdP] Loaded %d registered clients", len(server.clients))
	}

	return server
}

// 客户端注册请求结构体
type ClientRegistrationRequest struct {
	Name         string   `json:"client_name"`
	RedirectURIs []string `json:"redirect_uris"`
	ClientType   string   `json:"client_type"` // "broker" or "rp"
}

// 客户端注册响应结构体
type ClientRegistrationResponse struct {
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	Name         string   `json:"client_name"`
	RedirectURIs []string `json:"redirect_uris"`
	CreatedAt    string   `json:"created_at"`
}

// 生成随机的客户端ID和密钥
func (s *OIDCIdPServer) generateClientCredentials() (string, string) {
	// 生成客户端ID
	clientIDBytes := make([]byte, 16)
	rand.Read(clientIDBytes)
	clientID := base64.URLEncoding.EncodeToString(clientIDBytes)

	// 生成客户端密钥
	clientSecretBytes := make([]byte, 32)
	rand.Read(clientSecretBytes)
	clientSecret := base64.URLEncoding.EncodeToString(clientSecretBytes)

	return clientID, clientSecret
}

// BindOIDC 绑定OIDC相关的路由
func (s *OIDCIdPServer) UseOIDC(app *fiber.App) {
	oauth2 := app.Group("/oauth2")

	// OpenID Connect Discovery
	oauth2.Get("/.well-known/openid-configuration", s.handleDiscovery)
	oauth2.Get("/.well-known/jwks.json", s.handleJWKS)

	// Authorization endpoint
	oauth2.Get("/authorize", s.handleAuthorize)
	oauth2.Post("/authorize", s.handleAuthorizePost)

	// Token endpoint
	oauth2.Post("/token", s.handleToken)

	// UserInfo endpoint
	oauth2.Get("/userinfo", s.handleUserInfo)
	oauth2.Post("/userinfo", s.handleUserInfo)

	// 登录页面
	oauth2.Get("/login", s.handleLoginPage)
	oauth2.Post("/login", s.handleLogin)

	// 客户端注册API
	oauth2.Post("/register", s.handleClientRegistration)
}

func (s *OIDCIdPServer) handleDiscovery(c *fiber.Ctx) error {
	config := map[string]interface{}{
		"issuer":                 s.issuer,
		"authorization_endpoint": s.issuer + "/oauth2/authorize",
		"token_endpoint":         s.issuer + "/oauth2/token",
		"userinfo_endpoint":      s.issuer + "/oauth2/userinfo",
		"jwks_uri":               s.issuer + "/oauth2/.well-known/jwks.json",
		"response_types_supported": []string{
			"code",
			"token",
			"id_token",
			"code token",
			"code id_token",
			"token id_token",
			"code token id_token",
		},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported": []string{
			"openid",
			"profile",
			"email",
		},
		"token_endpoint_auth_methods_supported": []string{
			"client_secret_basic",
			"client_secret_post",
		},
		"claims_supported": []string{
			"sub",
			"iss",
			"aud",
			"exp",
			"iat",
			"name",
			"email",
		},
		"code_challenge_methods_supported": []string{"S256", "plain"},
	}
	return c.JSON(config)
}

func (s *OIDCIdPServer) handleJWKS(c *fiber.Ctx) error {
	if s.tokenHelper == nil || s.tokenHelper.verifyKey == nil {
		log.Printf("[ERROR/IdP] verifyKey is not initialized")
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error:            "server_error",
			ErrorDescription: "verify key not available",
		})
	}

	jwk, err := rsaPublicKeyToJWK(s.tokenHelper.verifyKey)
	if err != nil {
		log.Printf("[ERROR/IdP] failed to convert RSA key to JWK: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error:            "server_error",
			ErrorDescription: "failed to build jwk",
		})
	}

	resp := map[string]interface{}{
		"keys": []interface{}{jwk},
	}
	return c.JSON(resp)
}

func (s *OIDCIdPServer) handleAuthorize(c *fiber.Ctx) error {
	c.Set("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0")
	// 验证必需参数
	clientID := c.Query("client_id")
	redirectURI := c.Query("redirect_uri")
	responseType := c.Query("response_type")
	scope := c.Query("scope", "openid")
	state := c.Query("state")
	startTime := c.Query("startTime")
	prompt := c.Query("prompt")
	tBrokerLoad := c.Query("t_broker_load")
	tBrokerClick := c.Query("t_broker_click")
	tIdpLoad := c.Query("t_idp_load")
	tIdpSubmit := c.Query("t_idp_submit")

	if clientID == "" || redirectURI == "" || responseType == "" {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "missing required parameters",
		})
	}

	// 验证客户端
	client, exists := s.clients[clientID]
	if !exists {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error:            "invalid_client",
			ErrorDescription: "unknown client",
		})
	}

	// 验证重定向URI
	validRedirect := false
	for _, uri := range client.RedirectURIs {
		if uri == redirectURI {
			validRedirect = true
			break
		}
	}
	if !validRedirect {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "invalid redirect_uri",
		})
	}

	// 端到端延迟测试 / 无状态登录：不使用 session cookie 记录用户登录状态。
	// 始终重定向到登录页面（透传 startTime/prompt 及可选前端时间标记）。
	loginURL := fmt.Sprintf("/oauth2/login?client_id=%s&redirect_uri=%s&response_type=%s&scope=%s&state=%s&startTime=%s&prompt=%s&t_broker_load=%s&t_broker_click=%s&t_idp_load=%s&t_idp_submit=%s",
		url.QueryEscape(clientID),
		url.QueryEscape(redirectURI),
		url.QueryEscape(responseType),
		url.QueryEscape(scope),
		url.QueryEscape(state),
		url.QueryEscape(startTime),
		url.QueryEscape(prompt),
		url.QueryEscape(tBrokerLoad),
		url.QueryEscape(tBrokerClick),
		url.QueryEscape(tIdpLoad),
		url.QueryEscape(tIdpSubmit))
	return c.Redirect(loginURL)
}

func (s *OIDCIdPServer) handleAuthorizePost(c *fiber.Ctx) error {
	// 处理用户同意授权的POST请求
	return s.handleAuthorize(c)
}

func (s *OIDCIdPServer) handleToken(c *fiber.Ctx) error {
	grantType := c.FormValue("grant_type")

	switch grantType {
	case "authorization_code":
		return s.handleAuthorizationCodeGrant(c)
	case "refresh_token":
		return s.handleRefreshTokenGrant(c)
	default:
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error:            "unsupported_grant_type",
			ErrorDescription: "only authorization_code and refresh_token grant types are supported",
		})
	}
}

func (s *OIDCIdPServer) handleAuthorizationCodeGrant(c *fiber.Ctx) error {
	code := c.FormValue("code")
	redirectURI := c.FormValue("redirect_uri")
	clientID := c.FormValue("client_id")
	clientSecret := c.FormValue("client_secret")

	if code == "" || redirectURI == "" {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "missing required parameters",
		})
	}

	// 验证授权码
	log.Printf("[DEBUG/IdP] AuthorizationCodeGrant Receive code: %s", code)
	authCode, exists := s.storage[code]
	if !exists || authCode.ExpiresAt.Before(time.Now()) {
		if exists {
			delete(s.storage, code) // 清理过期的授权码
		}
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error:            "invalid_grant",
			ErrorDescription: "invalid or expired authorization code",
		})
	}

	// 验证客户端
	if clientID != "" && clientID != authCode.ClientID {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error:            "invalid_client",
			ErrorDescription: "client_id mismatch",
		})
	}

	client, exists := s.clients[authCode.ClientID]
	if !exists {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error:            "invalid_client",
			ErrorDescription: "unknown client",
		})
	}

	// 验证客户端密钥（如果提供）
	if clientSecret != "" && clientSecret != client.ClientSecret {
		return c.Status(fiber.StatusUnauthorized).JSON(ErrorResponse{
			Error:            "invalid_client",
			ErrorDescription: "invalid client credentials",
		})
	}

	// 验证重定向URI
	if redirectURI != authCode.RedirectURI {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error:            "invalid_grant",
			ErrorDescription: "redirect_uri mismatch",
		})
	}

	// 生成token
	accessToken, err := s.tokenHelper.GenerateAccessToken(authCode.UserID, authCode.Scope, authCode.ClientID)
	if err != nil {
		log.Printf("[ERROR/IdP] Failed to generate access token: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error:            "server_error",
			ErrorDescription: "failed to generate access token",
		})
	}

	var idToken string
	if strings.Contains(authCode.Scope, "openid") {
		// 模拟用户信息
		userInfo := s.getUserInfo(authCode.UserID)
		idToken, err = s.tokenHelper.GenerateIDToken(authCode.UserID, userInfo.Name, authCode.ClientID)
		if err != nil {
			log.Printf("[ERROR/IdP] Failed to generate ID token: %v", err)
			return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
				Error:            "server_error",
				ErrorDescription: "failed to generate ID token",
			})
		}
	}

	refreshToken, err := s.tokenHelper.GenerateRefreshToken(authCode.UserID, authCode.Scope, authCode.ClientID)
	if err != nil {
		log.Printf("[ERROR/IdP] Failed to generate refresh token: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error:            "server_error",
			ErrorDescription: "failed to generate refresh token",
		})
	}

	// 清理使用过的授权码
	delete(s.storage, code)

	response := TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		RefreshToken: refreshToken,
		Scope:        authCode.Scope,
	}

	if idToken != "" {
		response.IDToken = idToken
	}

	log.Printf("[INFO/IdP] Access token issued for client %s, user %s", authCode.ClientID, authCode.UserID)
	return c.JSON(response)
}

func (s *OIDCIdPServer) handleRefreshTokenGrant(c *fiber.Ctx) error {
	refreshToken := c.FormValue("refresh_token")
	clientID := c.FormValue("client_id")
	clientSecret := c.FormValue("client_secret")

	if refreshToken == "" {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "missing refresh_token",
		})
	}

	// 验证refresh token
	claims, err := s.tokenHelper.ValidateRefreshToken(refreshToken)
	if err != nil {
		log.Printf("[ERROR/IdP] Invalid refresh token: %v", err)
		return c.Status(fiber.StatusUnauthorized).JSON(ErrorResponse{
			Error:            "invalid_grant",
			ErrorDescription: "invalid or expired refresh token",
		})
	}

	// 验证客户端（如果提供）
	if clientID != "" {
		client, exists := s.clients[clientID]
		if !exists {
			return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
				Error:            "invalid_client",
				ErrorDescription: "unknown client",
			})
		}

		// 验证客户端密钥（如果提供）
		if clientSecret != "" && clientSecret != client.ClientSecret {
			return c.Status(fiber.StatusUnauthorized).JSON(ErrorResponse{
				Error:            "invalid_client",
				ErrorDescription: "invalid client credentials",
			})
		}
	}

	// 从refresh token claims中获取用户信息
	userID := claims.Subject
	scope := claims.Scope
	audienceClientID := ""
	if len(claims.Audience) > 0 {
		audienceClientID = claims.Audience[0]
	}

	// 验证用户是否存在
	user, exists := s.usersBySub[userID]
	if !exists {
		log.Printf("[ERROR/IdP] User not found for sub: %s", userID)
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error:            "invalid_grant",
			ErrorDescription: "user not found",
		})
	}

	// 生成新的access token
	accessToken, err := s.tokenHelper.GenerateAccessToken(userID, scope, audienceClientID)
	if err != nil {
		log.Printf("[ERROR/IdP] Failed to generate access token: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error:            "server_error",
			ErrorDescription: "failed to generate access token",
		})
	}

	// 生成新的ID token（如果请求了openid scope）
	var idToken string
	if strings.Contains(scope, "openid") {
		userInfo := s.getUserInfo(userID)
		idToken, err = s.tokenHelper.GenerateIDToken(userID, userInfo.Name, audienceClientID)
		if err != nil {
			log.Printf("[ERROR/IdP] Failed to generate ID token: %v", err)
			// ID token生成失败不影响access token的返回
		}
	}

	// 生成新的refresh token
	newRefreshToken, err := s.tokenHelper.GenerateRefreshToken(userID, scope, audienceClientID)
	if err != nil {
		log.Printf("[ERROR/IdP] Failed to generate refresh token: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(ErrorResponse{
			Error:            "server_error",
			ErrorDescription: "failed to generate refresh token",
		})
	}

	response := TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    1800, // 30 minutes
		RefreshToken: newRefreshToken,
		Scope:        scope,
	}

	if idToken != "" {
		response.IDToken = idToken
	}

	log.Printf("[INFO/IdP] Refresh token grant successful for user %s", user.Username)
	return c.JSON(response)
}

func (s *OIDCIdPServer) handleUserInfo(c *fiber.Ctx) error {
	// 从Authorization header获取access token
	authHeader := c.Get("Authorization")
	if authHeader == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(ErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "missing authorization header",
		})
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	if tokenString == authHeader {
		return c.Status(fiber.StatusUnauthorized).JSON(ErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "invalid authorization header format",
		})
	}

	// 验证access token
	claims, err := s.validateAccessToken(tokenString)
	if err != nil {
		log.Printf("[ERROR/IdP] Invalid access token: %v", err)
		return c.Status(fiber.StatusUnauthorized).JSON(ErrorResponse{
			Error:            "invalid_token",
			ErrorDescription: "invalid or expired access token",
		})
	}

	userID := claims["sub"].(string)
	userInfo := s.getUserInfo(userID)

	return c.JSON(userInfo)
}

func (s *OIDCIdPServer) handleLoginPage(c *fiber.Ctx) error {
	c.Set("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0")
	// 渲染登录页（但前端会自动提交表单，确保可测的页面渲染耗时 + 无需点击）
	tmpl, err := template.ParseFiles("./IdP/static/oidc_login.html")
	if err != nil {
		log.Printf("[ERROR/IdP] Failed to parse login template: %v", err)
		return c.Status(fiber.StatusInternalServerError).SendString("Template error")
	}

	data := struct {
		ClientID     string
		RedirectURI  string
		ResponseType string
		Scope        string
		State        string
		StartTime    string
		Prompt       string
	}{
		ClientID:     c.Query("client_id"),
		RedirectURI:  c.Query("redirect_uri"),
		ResponseType: c.Query("response_type"),
		Scope:        c.Query("scope"),
		State:        c.Query("state"),
		StartTime:    c.Query("startTime"),
		Prompt:       c.Query("prompt"),
	}

	c.Set("Content-Type", "text/html")
	return tmpl.Execute(c.Response().BodyWriter(), data)
}

func (s *OIDCIdPServer) handleLogin(c *fiber.Ctx) error {
	username := c.FormValue("username")
	password := c.FormValue("password")
	if username == "" || password == "" {
		username = "Alice"
		password = "Alice-pass"
	}
	// 简化的用户验证
	if !s.validateUser(username, password) {
		return c.Status(fiber.StatusUnauthorized).SendString("Invalid credentials")
	}

	// 无状态登录：登录成功后直接签发 authorization code 并重定向回 client redirect_uri
	clientID := c.FormValue("client_id")
	redirectURI := c.FormValue("redirect_uri")
	responseType := c.FormValue("response_type")
	scope := c.FormValue("scope")
	state := c.FormValue("state")
	startTime := c.FormValue("startTime")
	prompt := c.FormValue("prompt")
	tIdpRender := c.FormValue("t_idp_render")
	tIdpSubmit := c.FormValue("t_idp_submit")

	if startTime == "" {
		startTime = fmt.Sprintf("%d", time.Now().UnixMilli())
	}

	// 仅支持 code flow
	if responseType != "code" {
		return c.Status(fiber.StatusBadRequest).SendString("unsupported response_type")
	}

	// 验证客户端及 redirect_uri
	client, exists := s.clients[clientID]
	if !exists {
		return c.Status(fiber.StatusBadRequest).SendString("unknown client")
	}
	validRedirect := false
	for _, uri := range client.RedirectURIs {
		if uri == redirectURI {
			validRedirect = true
			break
		}
	}
	if !validRedirect {
		return c.Status(fiber.StatusBadRequest).SendString("invalid redirect_uri")
	}

	user := s.users[username]
	if user == nil {
		return c.Status(fiber.StatusUnauthorized).SendString("Invalid user")
	}

	code := s.generateAuthorizationCode()
	authCode := &OIDCAuthorizationCode{
		Code:        code,
		ClientID:    clientID,
		RedirectURI: redirectURI,
		Scope:       scope,
		UserID:      user.Sub,
		ExpiresAt:   time.Now().Add(10 * time.Minute),
	}
	s.storage[code] = authCode

	// 重定向回客户端（透传 startTime / t_idp_render / t_idp_submit）
	redirectURL := fmt.Sprintf("%s?code=%s&startTime=%s", redirectURI, code, url.QueryEscape(startTime))
	if state != "" {
		redirectURL += "&state=" + url.QueryEscape(state)
	}
	if prompt != "" {
		redirectURL += "&prompt=" + url.QueryEscape(prompt)
	}
	if tIdpRender != "" {
		redirectURL += "&t_idp_render=" + url.QueryEscape(tIdpRender)
	}
	if tIdpSubmit != "" {
		redirectURL += "&t_idp_submit=" + url.QueryEscape(tIdpSubmit)
	}

	log.Printf("[INFO/IdP] Authorization code granted for client %s, user %s", clientID, user.Sub)
	return c.Redirect(redirectURL)
}

// 辅助方法

func (s *OIDCIdPServer) generateAuthorizationCode() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return base64.URLEncoding.EncodeToString(bytes)
}

func (s *OIDCIdPServer) validateUser(username, password string) bool {
	user, exists := s.users[username]
	if !exists {
		return false
	}
	return user.Password == password
}

func (s *OIDCIdPServer) validateAccessToken(tokenString string) (jwt.MapClaims, error) {
	claims, err := s.tokenHelper.ValidateAccessToken(tokenString)
	if err != nil {
		return nil, err
	}

	// 转换为MapClaims以保持兼容性
	mapClaims := jwt.MapClaims{
		"sub":   claims.Subject,
		"iss":   claims.Issuer,
		"aud":   claims.Audience,
		"exp":   claims.ExpiresAt.Unix(),
		"iat":   claims.IssuedAt.Unix(),
		"scope": claims.Scope,
	}

	return mapClaims, nil
}

type UserInfo struct {
	Sub   string `json:"sub"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

func (s *OIDCIdPServer) getUserInfo(userID string) UserInfo {
	user, exists := s.usersBySub[userID]
	if !exists {
		// 返回默认用户信息
		return UserInfo{
			Sub:   userID,
			Name:  "Unknown User",
			Email: "unknown@example.com",
		}
	}

	return UserInfo{
		Sub:   user.Sub,
		Name:  user.Username,
		Email: user.Email,
	}
}

// 处理客户端注册请求
func (s *OIDCIdPServer) handleClientRegistration(c *fiber.Ctx) error {
	var req ClientRegistrationRequest
	if err := c.BodyParser(&req); err != nil {
		log.Printf("[ERROR/IdP] Failed to parse registration request: %v", err)
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "invalid request body",
		})
	}

	// 验证必要字段
	if req.Name == "" || len(req.RedirectURIs) == 0 {
		return c.Status(fiber.StatusBadRequest).JSON(ErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "client_name and redirect_uris are required",
		})
	}

	// 生成客户端凭据
	clientID, clientSecret := s.generateClientCredentials()

	// 创建客户端
	client := &Client{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURIs: req.RedirectURIs,
		Name:         req.Name,
		ClientType:   req.ClientType,
	}

	// 存储客户端
	s.clients[clientID] = client

	// 持久化保存客户端
	if err := s.saveClients(); err != nil {
		log.Printf("[WARNING/IdP] Failed to save clients: %v", err)
		// 继续执行，即使保存失败
	}

	// 返回注册响应
	response := ClientRegistrationResponse{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Name:         req.Name,
		RedirectURIs: req.RedirectURIs,
		CreatedAt:    time.Now().Format(time.RFC3339),
	}

	log.Printf("[INFO/IdP] Client registered: %s (%s)", req.Name, clientID)
	return c.Status(fiber.StatusCreated).JSON(response)
}

// loadUsers 从 users.json 文件加载用户数据
func (s *OIDCIdPServer) loadUsers() error {
	file, err := os.Open(idpUsersFile)
	if err != nil {
		return fmt.Errorf("failed to open users.json: %v", err)
	}
	defer file.Close()

	var users []User
	if err := json.NewDecoder(file).Decode(&users); err != nil {
		return fmt.Errorf("failed to decode users.json: %v", err)
	}

	// 构建用户映射
	for _, user := range users {
		userCopy := user // 安全复制
		s.users[user.Username] = &userCopy
		s.usersBySub[user.Sub] = &userCopy
	}

	log.Printf("[INFO/IdP] Loaded %d users from users.json", len(users))
	return nil
}

// getClientIDs 返回所有已注册的客户端ID（用于调试）
func (s *OIDCIdPServer) getClientIDs() []string {
	ids := make([]string, 0, len(s.clients))
	for id := range s.clients {
		ids = append(ids, id)
	}
	return ids
}

// loadClients 从文件加载已注册的客户端
func (s *OIDCIdPServer) loadClients() error {
	storage, err := loadClients()
	if err != nil {
		return fmt.Errorf("load clients: %w", err)
	}

	// 将存储的客户端数据转换为内存中的 Client 对象
	for _, clientData := range storage.Clients {
		client := &Client{
			ClientID:     clientData.ClientID,
			ClientSecret: clientData.ClientSecret,
			RedirectURIs: clientData.RedirectURIs,
			Name:         clientData.Name,
			ClientType:   clientData.ClientType,
		}
		s.clients[clientData.ClientID] = client
	}

	return nil
}

// saveClients 保存所有已注册的客户端到文件
func (s *OIDCIdPServer) saveClients() error {
	return saveClients(s.clients)
}
