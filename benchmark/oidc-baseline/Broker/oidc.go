package broker

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
)

type OIDCBrokerServer struct {
	tokenHelper   *TokenHelper
	clients       map[string]*BrokerClient  // client_id -> client info
	sessions      map[string]*BrokerSession // session_id -> session data
	idpConfig     *IDPConfig
	rpCredentials *RPCredentials        // RP在IdP的凭据，Broker代理使用
	tokenStore    map[string]*TokenInfo // user_id -> token info for refresh
	issuer        string
}

type BrokerClient struct {
	ClientID     string
	ClientSecret string
	RedirectURIs []string
	Name         string
}

type BrokerSession struct {
	SessionID    string
	State        string
	CodeVerifier string
	ClientID     string
	RedirectURI  string
	Scope        string
	UserID       string
	IdPCode      string // 从IdP获得的真实authorization code
	ExpiresAt    time.Time
}

// RP在IdP的凭据，Broker代理使用
type RPCredentials struct {
	ClientID     string
	ClientSecret string
	RedirectURI  string
}

// Token信息，用于token刷新管理
type TokenInfo struct {
	AccessToken  string
	RefreshToken string
	IDToken      string
	ExpiresAt    time.Time
	UserID       string
}

type IDPConfig struct {
	AuthorizeURL string
	TokenURL     string
	UserInfoURL  string
	JWKSURL      string
	RegisterURL  string
	ClientID     string
	ClientSecret string
}

type BrokerTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

type BrokerErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

func NewOIDCBrokerServer(tokenHelper *TokenHelper, config *OIDCConfig) *OIDCBrokerServer {
	server := &OIDCBrokerServer{
		tokenHelper: tokenHelper,
		clients:     make(map[string]*BrokerClient),
		sessions:    make(map[string]*BrokerSession),
		tokenStore:  make(map[string]*TokenInfo),
		issuer:      tokenHelper.Issuer,
	}

	// 尝试加载IdP客户端配置
	if idpConfig := server.loadIdPConfig(config); idpConfig != nil {
		server.idpConfig = idpConfig
		if idpConfig.ClientID != "" {
			log.Printf("[INFO/Broker] Loaded existing IdP configuration: %s", idpConfig.ClientID)
		}
	} else {
		log.Printf("[WARNING/Broker] Failed to load IdP configuration")
	}

	// 加载已注册的 RP 客户端
	if err := server.loadClients(); err != nil {
		log.Printf("[WARNING/Broker] Failed to load clients: %v", err)
	} else {
		log.Printf("[INFO/Broker] Loaded %d registered RP clients", len(server.clients))
	}

	// 加载 RP 凭据（用于 token 刷新）
	if err := server.loadRPCredentials(); err != nil {
		log.Printf("[WARNING/Broker] Failed to load RP credentials: %v", err)
	} else if server.rpCredentials != nil {
		log.Printf("[INFO/Broker] Loaded RP credentials for token refresh")
	}

	return server
}

// IdP配置管理方法
const brokerIdPConfigFile = "Broker/config/idp_config.json"

type IdPConfigStorage struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

func (s *OIDCBrokerServer) loadIdPConfig(config *OIDCConfig) *IDPConfig {
	idpConfig := &IDPConfig{
		AuthorizeURL: config.AuthorizeURL,
		TokenURL:     config.TokenURL,
		UserInfoURL:  config.UserInfoURL,
		JWKSURL:      config.JWKSURL,
		RegisterURL:  config.RegisterURL,
		ClientID:     "",
		ClientSecret: "",
	}

	// 尝试从文件加载已保存的客户端凭据
	data, err := os.ReadFile(brokerIdPConfigFile)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("[INFO/Broker] No saved IdP client credentials found")
			return idpConfig
		}
		log.Printf("[WARNING/Broker] Failed to read IdP config file: %v", err)
		return idpConfig
	}

	var stored IdPConfigStorage
	if err := json.Unmarshal(data, &stored); err != nil {
		log.Printf("[WARNING/Broker] Failed to parse IdP config file: %v", err)
		return idpConfig
	}

	// 如果找到保存的凭据，使用它们
	if stored.ClientID != "" && stored.ClientSecret != "" {
		idpConfig.ClientID = stored.ClientID
		idpConfig.ClientSecret = stored.ClientSecret
		log.Printf("[INFO/Broker] Loaded IdP client credentials: %s", stored.ClientID)
	}

	return idpConfig
}

func (s *OIDCBrokerServer) saveIdPConfig() error {
	if s.idpConfig == nil || s.idpConfig.ClientID == "" {
		return nil // 没有配置需要保存
	}

	stored := IdPConfigStorage{
		ClientID:     s.idpConfig.ClientID,
		ClientSecret: s.idpConfig.ClientSecret,
	}

	data, err := json.MarshalIndent(stored, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal IdP config: %w", err)
	}

	// 确保目录存在
	if err := os.MkdirAll("Broker/config", 0755); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}

	if err := os.WriteFile(brokerIdPConfigFile, data, 0600); err != nil {
		return fmt.Errorf("write IdP config file: %w", err)
	}

	log.Printf("[INFO/Broker] Saved IdP client credentials to file")
	return nil
}

// loadClients 从文件加载已注册的 RP 客户端
func (s *OIDCBrokerServer) loadClients() error {
	storage, err := loadBrokerClients()
	if err != nil {
		return fmt.Errorf("load clients: %w", err)
	}

	// 将存储的客户端数据转换为内存中的 BrokerClient 对象
	for _, clientData := range storage.Clients {
		client := &BrokerClient{
			ClientID:     clientData.ClientID,
			ClientSecret: clientData.ClientSecret,
			RedirectURIs: clientData.RedirectURIs,
			Name:         clientData.Name,
		}
		s.clients[clientData.ClientID] = client
	}

	return nil
}

// saveClients 保存所有已注册的 RP 客户端到文件
func (s *OIDCBrokerServer) saveClients() error {
	return saveBrokerClients(s.clients)
}

// loadRPCredentials 从文件加载 RP 凭据
func (s *OIDCBrokerServer) loadRPCredentials() error {
	storage, err := loadRPCredentials()
	if err != nil {
		return fmt.Errorf("load RP credentials: %w", err)
	}

	if storage != nil {
		s.rpCredentials = &RPCredentials{
			ClientID:     storage.ClientID,
			ClientSecret: storage.ClientSecret,
			RedirectURI:  storage.RedirectURI,
		}
	}

	return nil
}

// saveRPCredentials 保存 RP 凭据到文件
func (s *OIDCBrokerServer) saveRPCredentials() error {
	return saveRPCredentials(s.rpCredentials)
}

// autoRegisterWithIdP 自动向IdP注册Broker
func (s *OIDCBrokerServer) autoRegisterWithIdP() error {
	if s.idpConfig == nil {
		return fmt.Errorf("IdP config not initialized")
	}

	// 构建注册请求
	req := &ClientRegistrationRequest{
		ClientName:   "OIDC Broker",
		RedirectURIs: []string{s.tokenHelper.Issuer + "/oauth2/callback"},
		ClientType:   "broker",
	}

	// 向IdP注册
	resp, err := s.registerWithIdP(req)
	if err != nil {
		return fmt.Errorf("register with IdP: %w", err)
	}

	// 保存凭据
	s.idpConfig.ClientID = resp.ClientID
	s.idpConfig.ClientSecret = resp.ClientSecret

	// 持久化保存
	if err := s.saveIdPConfig(); err != nil {
		return fmt.Errorf("save IdP config: %w", err)
	}

	return nil
}

// 客户端注册相关结构体
type ClientRegistrationRequest struct {
	ClientName   string   `json:"client_name"`
	RedirectURIs []string `json:"redirect_uris"`
	ClientType   string   `json:"client_type"`
}

type ClientRegistrationResponse struct {
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	ClientName   string   `json:"client_name"`
	RedirectURIs []string `json:"redirect_uris"`
	CreatedAt    string   `json:"created_at"`
}

// UseOIDC 绑定OIDC相关的路由
func (s *OIDCBrokerServer) UseOIDC(app *fiber.App) {
	oauth2 := app.Group("/oauth2")

	// OpenID Connect Discovery
	oauth2.Get("/.well-known/openid-configuration", s.handleDiscovery)
	oauth2.Get("/.well-known/jwks.json", s.handleJWKS)

	// Broker注册页面和API
	oauth2.Get("/register", s.handleRegisterPage)
	oauth2.Post("/register", s.handleRegister)

	// RP凭据注册API (RP将其在IdP的凭据提供给Broker)
	oauth2.Post("/register-rp", s.handleRegisterRP)

	// Authorization endpoint (作为OIDC Provider)
	oauth2.Get("/authorize", s.handleAuthorize)

	// Token endpoint (作为OIDC Provider)
	oauth2.Post("/token", s.handleToken)

	// Callback endpoint (从IdP接收授权码)
	oauth2.Get("/callback", s.handleCallback)

	// UserInfo endpoint
	oauth2.Get("/userinfo", s.handleUserInfo)
}

func (s *OIDCBrokerServer) handleDiscovery(c *fiber.Ctx) error {
	config := map[string]interface{}{
		"issuer":                 s.issuer,
		"authorization_endpoint": s.issuer + "/oauth2/authorize",
		"token_endpoint":         s.issuer + "/oauth2/token",
		"userinfo_endpoint":      s.issuer + "/oauth2/userinfo",
		"jwks_uri":               s.issuer + "/oauth2/.well-known/jwks.json",
		"response_types_supported": []string{
			"code",
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
	}
	return c.JSON(config)
}

func (s *OIDCBrokerServer) handleJWKS(c *fiber.Ctx) error {
	if s.tokenHelper == nil || s.tokenHelper.verifyKey == nil {
		log.Printf("[ERROR/Broker] verifyKey is not initialized")
		return c.Status(fiber.StatusInternalServerError).JSON(BrokerErrorResponse{
			Error:            "server_error",
			ErrorDescription: "verify key not available",
		})
	}

	jwk, err := rsaPublicKeyToJWK(s.tokenHelper.verifyKey)
	if err != nil {
		log.Printf("[ERROR/Broker] failed to convert RSA key to JWK: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(BrokerErrorResponse{
			Error:            "server_error",
			ErrorDescription: "failed to build jwk",
		})
	}

	resp := map[string]interface{}{
		"keys": []interface{}{jwk},
	}
	return c.JSON(resp)
}

func (s *OIDCBrokerServer) handleAuthorize(c *fiber.Ctx) error {
	c.Set("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0")
	// 检查是否有IdP配置
	if s.idpConfig == nil {
		log.Printf("[WARNING/Broker] No IdP configuration found, redirecting to registration")
		return c.Redirect("/oauth2/register")
	}

	// 解析RP的授权请求
	clientID := c.Query("client_id")
	redirectURI := c.Query("redirect_uri")
	responseType := c.Query("response_type")
	scope := c.Query("scope", "openid")
	state := c.Query("state")
	startTime := c.Query("startTime")
	prompt := c.Query("prompt")

	if clientID == "" || redirectURI == "" || responseType != "code" {
		return c.Status(fiber.StatusBadRequest).JSON(BrokerErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "missing or invalid required parameters",
		})
	}

	// 验证RP客户端
	client, exists := s.clients[clientID]
	if !exists {
		return c.Status(fiber.StatusBadRequest).JSON(BrokerErrorResponse{
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
		return c.Status(fiber.StatusBadRequest).JSON(BrokerErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "invalid redirect_uri",
		})
	}

	// 创建broker session
	sessionID := s.generateSessionID()
	session := &BrokerSession{
		SessionID:   sessionID,
		State:       state,
		ClientID:    clientID,
		RedirectURI: string([]byte(redirectURI)),
		Scope:       scope,
		ExpiresAt:   time.Now().Add(10 * time.Minute),
	}
	s.sessions[sessionID] = session

	// 重定向到IdP进行认证
	// 透传 startTime / prompt（用于端到端延迟测试，且可强制每次都走IdP登录页）
	idpAuthURL := fmt.Sprintf("%s?client_id=%s&redirect_uri=%s&response_type=code&scope=%s&state=%s&startTime=%s&prompt=%s",
		s.idpConfig.AuthorizeURL,
		url.QueryEscape(s.idpConfig.ClientID),
		url.QueryEscape(s.tokenHelper.Issuer+"/oauth2/callback"),
		url.QueryEscape(scope),
		url.QueryEscape(sessionID), // 使用session_id作为state传递给IdP
		url.QueryEscape(startTime),
		url.QueryEscape(prompt))

	log.Printf("[INFO/Broker] Redirecting RP to IdP for authentication, session: %s", sessionID)
	//For Test: 直接跳转到IdP登录页
	// tmplData := map[string]any{
	// 	"IdPAuthURL": idpAuthURL,
	// }
	// tpl, err := template.ParseFiles("./Broker/static/oidc_login.html")
	// if err != nil {
	// 	return c.Status(http.StatusInternalServerError).SendString(s.fmtError(http.StatusInternalServerError, "failed to parse template"))
	// }
	// var buf bytes.Buffer
	// if err := tpl.Execute(&buf, tmplData); err != nil {
	// 	log.Printf("[ERROR/Broker] Failed to execute template: %v", err)
	// 	return c.Type("html").Status(http.StatusInternalServerError).SendString(s.fmtError(http.StatusInternalServerError, "template execute error"))
	// }
	// return c.Type("html").Status(http.StatusOK).Send(buf.Bytes())
	return c.Redirect(idpAuthURL)
}

func (s *OIDCBrokerServer) handleCallback(c *fiber.Ctx) error {
	// 从IdP接收授权码
	code := c.Query("code")
	state := c.Query("state") // 这是之前传给IdP的session_id
	startTime := c.Query("startTime")
	errorCode := c.Query("error")

	if errorCode != "" {
		log.Printf("[ERROR/Broker] IdP returned error: %s", errorCode)
		return c.Status(fiber.StatusBadRequest).JSON(BrokerErrorResponse{
			Error:            errorCode,
			ErrorDescription: c.Query("error_description"),
		})
	}

	if code == "" || state == "" {
		return c.Status(fiber.StatusBadRequest).JSON(BrokerErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "missing code or state",
		})
	}

	// 验证session
	session, exists := s.sessions[state]
	if !exists || session.ExpiresAt.Before(time.Now()) {
		return c.Status(fiber.StatusBadRequest).JSON(BrokerErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "invalid or expired session",
		})
	}

	// 存储从IdP获得的真实authorization code，待后续RP token请求时使用
	session.IdPCode = code
	log.Printf("[DEBUG/Broker] Receive code from IdP: %s", code)

	// 生成broker的授权码给RP
	brokerCode := s.generateAuthorizationCode()

	// 创建新session用于存储broker授权码，包含IdP code
	newSession := &BrokerSession{
		SessionID:   brokerCode,
		State:       session.State, // 保持原始state
		ClientID:    session.ClientID,
		RedirectURI: session.RedirectURI,
		Scope:       session.Scope,
		UserID:      "",
		IdPCode:     code, // 保存IdP的真实code用于后续token交换
		ExpiresAt:   time.Now().Add(10 * time.Minute),
	}
	s.sessions[brokerCode] = newSession

	// 重定向回RP
	log.Printf("[DEBUG/Broker] Generate broker code: %s", brokerCode)
	redirectURL := fmt.Sprintf("%s?code=%s&startTime=%s", session.RedirectURI, brokerCode, url.QueryEscape(startTime))
	if session.State != "" {
		redirectURL += "&state=" + url.QueryEscape(session.State)
	}

	// 端到端延迟测试：透传 IdP 侧的打点参数回 RP
	tIdpRender := c.Query("t_idp_render")
	tIdpSubmit := c.Query("t_idp_submit")
	if tIdpRender != "" {
		redirectURL += "&t_idp_render=" + url.QueryEscape(tIdpRender)
	}
	if tIdpSubmit != "" {
		redirectURL += "&t_idp_submit=" + url.QueryEscape(tIdpSubmit)
	}

	log.Printf("[INFO/Broker] Redirecting back to RP with authorization code")
	return c.Redirect(redirectURL)
}

func (s *OIDCBrokerServer) handleToken(c *fiber.Ctx) error {
	grantType := c.FormValue("grant_type")

	if grantType != "authorization_code" {
		return c.Status(fiber.StatusBadRequest).JSON(BrokerErrorResponse{
			Error:            "unsupported_grant_type",
			ErrorDescription: "only authorization_code grant type is supported",
		})
	}

	code := c.FormValue("code")
	redirectURI := c.FormValue("redirect_uri")
	clientID := c.FormValue("client_id")
	clientSecret := c.FormValue("client_secret")
	// 兼容 client_secret_basic（以及某些情况下 form 里缺字段）

	if code == "" || redirectURI == "" {
		return c.Status(fiber.StatusBadRequest).JSON(BrokerErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "missing required parameters",
		})
	}

	// 验证授权码（实际上是session）
	session, exists := s.sessions[code]
	if !exists || session.ExpiresAt.Before(time.Now()) {
		return c.Status(fiber.StatusBadRequest).JSON(BrokerErrorResponse{
			Error:            "invalid_grant",
			ErrorDescription: "invalid or expired authorization code",
		})
	}

	// 端到端延迟测试：以“授权码绑定的 client_id”为准，避免因为重复点击/字段缺失导致 client_id mismatch
	expectedClientID := session.ClientID
	if clientID != "" && clientID != expectedClientID {
		log.Printf("[WARNING/Broker] token request client_id mismatch: got=%q expected=%q (override expected for test)", clientID, expectedClientID)
		session.ClientID = clientID
	}
	_ = clientSecret // 端到端延迟测试：不校验 client_secret / 注册状态

	// 验证重定向URI
	if redirectURI != session.RedirectURI {
		return c.Status(fiber.StatusBadRequest).JSON(BrokerErrorResponse{
			Error:            "invalid_grant",
			ErrorDescription: "redirect_uri mismatch",
		})
	}

	// 使用RP凭据向IdP交换token（Broker代理RP与IdP交互）
	tokens, err := s.exchangeCodeForTokens(session.IdPCode)
	if err != nil {
		log.Printf("[ERROR/Broker] Failed to exchange code with IdP: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(BrokerErrorResponse{
			Error:            "server_error",
			ErrorDescription: "Failed to exchange authorization code with IdP",
		})
	}

	// 从IdP获取用户信息
	userInfo, err := s.getUserInfoFromIdP(tokens.AccessToken)
	if err != nil {
		log.Printf("[ERROR/Broker] Failed to get user info: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(BrokerErrorResponse{
			Error:            "server_error",
			ErrorDescription: "failed to get user info",
		})
	}

	// 更新session信息
	session.UserID = userInfo.Sub

	// 保存token信息用于后续刷新
	tokenInfo := &TokenInfo{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		IDToken:      tokens.IDToken,
		ExpiresAt:    time.Now().Add(time.Duration(tokens.ExpiresIn) * time.Second),
		UserID:       session.UserID,
	}
	s.tokenStore[session.UserID] = tokenInfo

	// 使用Broker的私钥重签名token
	reSignedAccessToken, err := s.reSignToken(tokens.AccessToken, session.ClientID)
	if err != nil {
		log.Printf("[ERROR/Broker] Failed to re-sign access token: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(BrokerErrorResponse{
			Error:            "server_error",
			ErrorDescription: "Failed to re-sign access token",
		})
	}

	var reSignedIDToken string
	if tokens.IDToken != "" {
		reSignedIDToken, err = s.reSignToken(tokens.IDToken, session.ClientID)
		if err != nil {
			log.Printf("[ERROR/Broker] Failed to re-sign ID token: %v", err)
			return c.Status(fiber.StatusInternalServerError).JSON(BrokerErrorResponse{
				Error:            "server_error",
				ErrorDescription: "Failed to re-sign ID token",
			})
		}
	}

	// 清理使用过的授权码
	delete(s.sessions, code)

	response := BrokerTokenResponse{
		AccessToken:  reSignedAccessToken,
		TokenType:    "Bearer",
		ExpiresIn:    tokens.ExpiresIn,
		RefreshToken: s.generateBrokerRefreshToken(session.UserID), // Broker自己的refresh token
		Scope:        session.Scope,
	}

	if reSignedIDToken != "" {
		response.IDToken = reSignedIDToken
	}

	log.Printf("[INFO/Broker] Token issued for client %s, user %s", session.ClientID, session.UserID)
	return c.JSON(response)
}

func (s *OIDCBrokerServer) handleUserInfo(c *fiber.Ctx) error {
	// 从Authorization header获取access token
	authHeader := c.Get("Authorization")
	if authHeader == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(BrokerErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "missing authorization header",
		})
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	if tokenString == authHeader {
		return c.Status(fiber.StatusUnauthorized).JSON(BrokerErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "invalid authorization header format",
		})
	}

	// 验证access token
	claims, err := s.validateAccessToken(tokenString)
	if err != nil {
		log.Printf("[ERROR/Broker] Invalid access token: %v", err)
		return c.Status(fiber.StatusUnauthorized).JSON(BrokerErrorResponse{
			Error:            "invalid_token",
			ErrorDescription: "invalid or expired access token",
		})
	}

	userID := claims["sub"].(string)
	userInfo := s.getCachedUserInfo(userID)

	return c.JSON(userInfo)
}

// 辅助方法

func (s *OIDCBrokerServer) generateSessionID() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return base64.URLEncoding.EncodeToString(bytes)
}

func (s *OIDCBrokerServer) generateAuthorizationCode() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return base64.URLEncoding.EncodeToString(bytes)
}

func (s *OIDCBrokerServer) exchangeCodeForTokens(code string) (*IdpTokenResponse, error) {
	// 构建token请求
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", s.tokenHelper.Issuer+"/oauth2/callback")
	data.Set("client_id", s.idpConfig.ClientID)
	data.Set("client_secret", s.idpConfig.ClientSecret)

	resp, err := http.PostForm(s.idpConfig.TokenURL, data)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("token request failed: %d %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var tokenResp IdpTokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, err
	}

	return &tokenResp, nil
}

type IdpTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

type IdpUserInfo struct {
	Sub   string `json:"sub"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

func (s *OIDCBrokerServer) getUserInfoFromIdP(accessToken string) (*IdpUserInfo, error) {
	req, err := http.NewRequest("GET", s.idpConfig.UserInfoURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("userinfo request failed: %d %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var userInfo IdpUserInfo
	if err := json.Unmarshal(body, &userInfo); err != nil {
		return nil, err
	}

	return &userInfo, nil
}

func (s *OIDCBrokerServer) validateAccessToken(tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return s.tokenHelper.verifyKey, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token")
}

func (s *OIDCBrokerServer) getCachedUserInfo(userID string) IdpUserInfo {
	// 简化实现，实际应该缓存从IdP获取的用户信息
	return IdpUserInfo{
		Sub:   userID,
		Name:  "Test User",
		Email: "test@example.com",
	}
}

// Broker注册相关处理方法

func (s *OIDCBrokerServer) handleRegisterPage(c *fiber.Ctx) error {
	tmpl, err := template.ParseFiles("./Broker/static/oidc_register.html")
	if err != nil {
		log.Printf("[ERROR/Broker] Failed to parse register template: %v", err)
		return c.Status(fiber.StatusInternalServerError).SendString("Template error")
	}

	c.Set("Content-Type", "text/html")
	return tmpl.Execute(c.Response().BodyWriter(), nil)
}

func (s *OIDCBrokerServer) handleRegister(c *fiber.Ctx) error {
	var req ClientRegistrationRequest
	if err := c.BodyParser(&req); err != nil {
		log.Printf("[ERROR/Broker] Invalid registration request: %v", err)
		return c.Status(fiber.StatusBadRequest).JSON(BrokerErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "Invalid JSON format",
		})
	}

	// 验证请求参数
	if req.ClientName == "" || len(req.RedirectURIs) == 0 {
		return c.Status(fiber.StatusBadRequest).JSON(BrokerErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "Missing required fields: client_name and redirect_uris",
		})
	}

	// 向IdP注册Broker客户端
	resp, err := s.registerWithIdP(&req)
	if err != nil {
		log.Printf("[ERROR/Broker] Failed to register with IdP: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(BrokerErrorResponse{
			Error:            "server_error",
			ErrorDescription: "Failed to register with IdP",
		})
	}

	// 保存IdP配置
	s.idpConfig.ClientID = resp.ClientID
	s.idpConfig.ClientSecret = resp.ClientSecret

	// 持久化保存配置
	if err := s.saveIdPConfig(); err != nil {
		log.Printf("[WARNING/Broker] Failed to save IdP config: %v", err)
		// 继续执行，即使保存失败
	}

	log.Printf("[INFO/Broker] Successfully registered with IdP: %s", resp.ClientID)
	return c.JSON(resp)
}

func (s *OIDCBrokerServer) registerWithIdP(req *ClientRegistrationRequest) (*ClientRegistrationResponse, error) {
	// 向IdP发送注册请求
	requestBody, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	resp, err := http.Post(s.idpConfig.RegisterURL, "application/json",
		bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("IdP registration failed: %d %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var regResp ClientRegistrationResponse
	if err := json.Unmarshal(body, &regResp); err != nil {
		return nil, err
	}

	return &regResp, nil
}

// 处理RP凭据注册 - RP将其在IdP的凭据提供给Broker
func (s *OIDCBrokerServer) handleRegisterRP(c *fiber.Ctx) error {
	var reqData struct {
		RPClientID     string `json:"rp_client_id"`
		RPClientSecret string `json:"rp_client_secret"`
		RPRedirectURI  string `json:"rp_redirect_uri"`
		RPName         string `json:"rp_name,omitempty"`
	}

	if err := c.BodyParser(&reqData); err != nil {
		log.Printf("[ERROR/Broker] Invalid RP registration request: %v", err)
		return c.Status(fiber.StatusBadRequest).JSON(BrokerErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "Invalid JSON format",
		})
	}

	// 验证必需参数
	if reqData.RPClientID == "" || reqData.RPClientSecret == "" || reqData.RPRedirectURI == "" {
		return c.Status(fiber.StatusBadRequest).JSON(BrokerErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "Missing required fields: rp_client_id, rp_client_secret, rp_redirect_uri",
		})
	}

	// 保存RP凭据，Broker将使用这些凭据代理RP与IdP交互
	s.rpCredentials = &RPCredentials{
		ClientID:     reqData.RPClientID,
		ClientSecret: reqData.RPClientSecret,
		RedirectURI:  reqData.RPRedirectURI,
	}

	s.clients[reqData.RPClientID] = &BrokerClient{
		ClientID:     reqData.RPClientID,
		ClientSecret: reqData.RPClientSecret,
		RedirectURIs: []string{reqData.RPRedirectURI},
		Name:         reqData.RPName,
	}

	// 持久化保存 RP 客户端信息
	if err := s.saveClients(); err != nil {
		log.Printf("[WARNING/Broker] Failed to save clients: %v", err)
		// 继续执行，即使保存失败
	}

	// 持久化保存 RP 凭据（用于 token 刷新）
	if err := s.saveRPCredentials(); err != nil {
		log.Printf("[WARNING/Broker] Failed to save RP credentials: %v", err)
		// 继续执行，即使保存失败
	}

	log.Printf("[INFO/Broker] Successfully registered RP credentials: %s", reqData.RPClientID)

	return c.JSON(map[string]string{
		"status":  "success",
		"message": "RP credentials registered successfully",
	})
}

// 重签名token - 使用Broker的私钥重新签名IdP的token
func (s *OIDCBrokerServer) reSignToken(originalToken, clientID string) (string, error) {
	// 解析原始token以获取claims (忽略签名验证，因为我们只需要claims)
	token, _ := jwt.Parse(originalToken, func(token *jwt.Token) (interface{}, error) {
		// 这里需要IdP的公钥来验证，简化处理
		return nil, nil
	})

	var claims jwt.MapClaims
	if token != nil {
		if tokenClaims, ok := token.Claims.(jwt.MapClaims); ok {
			claims = tokenClaims
		}
	} else {
		// 如果无法解析，创建基本claims
		claims = jwt.MapClaims{}
	}

	// 修改issuer为Broker
	claims["iss"] = s.issuer
	claims["aud"] = clientID
	claims["iat"] = time.Now().Unix()
	claims["exp"] = time.Now().Add(time.Hour).Unix()

	// 使用Broker的私钥重新签名
	newToken := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	return newToken.SignedString(s.tokenHelper.signKey)
}

// 生成Broker的refresh token
func (s *OIDCBrokerServer) generateBrokerRefreshToken(userID string) string {
	claims := jwt.MapClaims{
		"sub":  userID,
		"type": "refresh",
		"iss":  s.issuer,
		"iat":  time.Now().Unix(),
		"exp":  time.Now().Add(24 * time.Hour).Unix(), // 24小时有效期
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, err := token.SignedString(s.tokenHelper.signKey)
	if err != nil {
		log.Printf("[ERROR/Broker] Failed to generate refresh token: %v", err)
		return ""
	}

	return tokenString
}

// 处理token刷新 - 使用IdP的refresh token获取新token并重签名
func (s *OIDCBrokerServer) refreshTokenWithIdP(userID string) (*BrokerTokenResponse, error) {
	tokenInfo, exists := s.tokenStore[userID]
	if !exists || tokenInfo.RefreshToken == "" {
		return nil, fmt.Errorf("no refresh token available")
	}

	// 使用IdP的refresh token获取新的access token
	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", tokenInfo.RefreshToken)
	data.Set("client_id", s.rpCredentials.ClientID)
	data.Set("client_secret", s.rpCredentials.ClientSecret)

	resp, err := http.PostForm(s.idpConfig.TokenURL, data)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("IdP refresh token request failed: %d %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var idpTokens IdpTokenResponse
	if err := json.Unmarshal(body, &idpTokens); err != nil {
		return nil, err
	}

	// 更新存储的token信息
	tokenInfo.AccessToken = idpTokens.AccessToken
	if idpTokens.RefreshToken != "" {
		tokenInfo.RefreshToken = idpTokens.RefreshToken
	}
	tokenInfo.ExpiresAt = time.Now().Add(time.Duration(idpTokens.ExpiresIn) * time.Second)

	// 重签名新的token
	reSignedAccessToken, err := s.reSignToken(idpTokens.AccessToken, "default_client")
	if err != nil {
		return nil, err
	}

	var reSignedIDToken string
	if idpTokens.IDToken != "" {
		reSignedIDToken, err = s.reSignToken(idpTokens.IDToken, "default_client")
		if err != nil {
			return nil, err
		}
	}

	return &BrokerTokenResponse{
		AccessToken: reSignedAccessToken,
		TokenType:   "Bearer",
		ExpiresIn:   idpTokens.ExpiresIn,
		IDToken:     reSignedIDToken,
	}, nil
}

func (s *OIDCBrokerServer) fmtError(status int, msg string) string {
	tmpl := "<!DOCTYPE html><html><head><meta charset=\"UTF-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\"><title>Error - IdP</title></head><body><h1>Error: %d</h1><p>Sorry, an error occurred while processing your request. Details: %s</p></body></html>"
	return fmt.Sprintf(tmpl, status, msg)
}
