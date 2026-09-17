package rp

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
	"strconv"
	"sync/atomic"
	"time"

	"github.com/gofiber/fiber/v2"
)

var oidcTestCounter int64
var registerTestCounter int64

type OIDCRPServer struct {
	sessions     map[string]*RPSession // state -> session data
	idpConfig    *OIDCIdPConfig
	brokerConfig *BrokerConfig
	clientConfig *RPClientConfig
}

var debug = false

type RPSession struct {
	State        string
	CodeVerifier string
	RedirectURI  string
	Scope        string
	ExpiresAt    time.Time
	UserInfo     *RPUserInfo
	AccessToken  string
	IDToken      string
	RefreshToken string
}

type OIDCIdPConfig struct {
	RegisterURL string
}

type BrokerConfig struct {
	AuthorizeURL string
	TokenURL     string
	UserInfoURL  string
	JWKSURL      string
	RegisterURL  string
}

type RPClientConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURI  string
}

type RegisterToBrokerRequest struct {
	RPClientID     string `json:"rp_client_id"`
	RPClientSecret string `json:"rp_client_secret"`
	RPRedirectURI  string `json:"rp_redirect_uri"`
	RPName         string `json:"rp_name,omitempty"`
}

type RPUserInfo struct {
	Sub   string `json:"sub"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

type RPTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

type RPErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// Client registration structures
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

func NewOIDCRPServer(oidcConfig *OIDCConfig) *OIDCRPServer {
	server := &OIDCRPServer{
		sessions: make(map[string]*RPSession),
		idpConfig: &OIDCIdPConfig{
			RegisterURL: oidcConfig.IdPRegisterURL,
		},
		brokerConfig: &BrokerConfig{
			AuthorizeURL: oidcConfig.AuthorizeURL,
			TokenURL:     oidcConfig.TokenURL,
			UserInfoURL:  oidcConfig.UserInfoURL,
			JWKSURL:      oidcConfig.JWKSURL,
			RegisterURL:  oidcConfig.BrokerRegisterURL,
		},
	}

	// 尝试加载现有的客户端配置
	if config := server.loadClientConfig(oidcConfig); config != nil {
		server.clientConfig = config
		if config.ClientID != "" {
			log.Printf("[INFO/RP] Loaded existing client configuration: %s", config.ClientID)
		} else {
			log.Printf("[WARNING/RP] No saved client credentials found. Please register at /oauth2/register")
		}
	} else {
		log.Printf("[WARNING/RP] Failed to load client configuration")
	}

	return server
}

// UseOIDC 绑定OIDC相关的路由
func (s *OIDCRPServer) UseOIDC(app *fiber.App) {
	oauth2 := app.Group("/oauth2")

	// 主页，显示登录按钮
	oauth2.Get("/", s.handleHome)

	// 客户端注册页面
	oauth2.Get("/register", s.handleRegisterPage)

	// 客户端注册API
	oauth2.Post("/register", s.handleRegister)

	// 登录端点，重定向到broker
	oauth2.Get("/login", s.handleLogin)

	// 回调端点，接收来自broker的授权码
	oauth2.Get("/callback", s.handleCallback)

	// 用户信息端点
	oauth2.Get("/user", s.handleUser)

	// 登出端点
	oauth2.Post("/logout", s.handleLogout)

	// 端到端延迟测试：记录测试结果到 txt 文件
	oauth2.Post("/metrics", s.handleMetrics)
}

func (s *OIDCRPServer) handleMetrics(c *fiber.Ctx) error {
	var metrics struct {
		StartTime   int64 `json:"startTime"`
		IdpRenderAt int64 `json:"idpRenderAt"`
		IdpSubmitAt int64 `json:"idpSubmitAt"`
		UserViewAt  int64 `json:"userViewAt"`
	}
	if err := c.BodyParser(&metrics); err != nil {
		log.Printf("[ERROR/RP] Failed to parse metrics: %v", err)
		return c.Status(400).SendString("invalid metrics")
	}

	// 1. 点击 Login 到 IdP 显示界面的时间
	t1 := metrics.IdpRenderAt - metrics.StartTime
	// 2. 点击登录到查询到 userinfo 在前端显示的时间 (此处点击登录指 IdP 提交)
	t2 := metrics.UserViewAt - metrics.IdpSubmitAt
	// 3. 整个阶段 (点击 Login 到 得到 userinfo)
	t3 := metrics.UserViewAt - metrics.StartTime

	// Increment test counter (thread-safe)
	currentTestNum := atomic.AddInt64(&oidcTestCounter, 1)

	// Format result lines - each time on a separate line
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	var lines string
	lines += fmt.Sprintf("Test #%d At: %s\n", currentTestNum, timestamp)
	lines += fmt.Sprintf("  T1(Login->IdP渲染): %dms\n", t1)
	lines += fmt.Sprintf("  T2(Submit->UserView): %dms\n", t2)
	lines += fmt.Sprintf("  T3(Total): %dms\n", t3)
	lines += "\n" // Add blank line between tests

	f, err := os.OpenFile("RP/latency_results.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("[ERROR/RP] Failed to open latency file: %v", err)
		return c.Status(500).SendString("file error")
	}
	defer f.Close()
	if _, err := f.WriteString(lines); err != nil {
		log.Printf("[ERROR/RP] Failed to write to latency file: %v", err)
		return c.Status(500).SendString("write error")
	}

	log.Printf("[INFO/RP] Test #%d metrics recorded: T1=%dms, T2=%dms, T3=%dms", currentTestNum, t1, t2, t3)
	return c.SendString("ok")
}

func (s *OIDCRPServer) handleHome(c *fiber.Ctx) error {
	c.Set("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0")
	// 端到端延迟测试：不使用 session / cookie 记录登录状态，每次都展示登录入口
	tmpl, err := template.ParseFiles("./RP/static/oidc_home.html")
	if err != nil {
		log.Printf("[ERROR/RP] Failed to parse home template: %v", err)
		return c.Status(fiber.StatusInternalServerError).SendString("Template error")
	}

	c.Set("Content-Type", "text/html")
	return tmpl.Execute(c.Response().BodyWriter(), nil)
}

func (s *OIDCRPServer) handleLogin(c *fiber.Ctx) error {
	c.Set("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0")
	// 检查是否有客户端配置
	if s.clientConfig == nil {
		log.Printf("[WARNING/RP] No client configuration found, redirecting to registration")
		return c.Redirect("/oauth2/register")
	}

	// 生成state
	state := s.generateState()

	startTime := c.Query("startTime")
	if startTime == "" {
		// fallback: milliseconds since epoch
		startTime = fmt.Sprintf("%d", time.Now().UnixMilli())
	}
	scope := "openid profile email"

	// 构建授权URL
	// prompt=login: 强制IdP每次都展示登录页面（便于稳定的端到端延迟测试）
	authURL := fmt.Sprintf("%s?client_id=%s&redirect_uri=%s&response_type=code&scope=%s&state=%s&startTime=%s&prompt=login",
		s.brokerConfig.AuthorizeURL,
		url.QueryEscape(s.clientConfig.ClientID),
		url.QueryEscape(s.clientConfig.RedirectURI),
		url.QueryEscape(scope),
		url.QueryEscape(state),
		url.QueryEscape(startTime))

	log.Printf("[INFO/RP] Redirecting user to broker for authentication")
	return c.Redirect(authURL)
}

func (s *OIDCRPServer) handleCallback(c *fiber.Ctx) error {
	code := c.Query("code")
	state := c.Query("state")
	startTime := c.Query("startTime")
	errorCode := c.Query("error")

	if errorCode != "" {
		log.Printf("[ERROR/RP] Broker returned error: %s", errorCode)
		return s.renderErrorPage(c, errorCode, c.Query("error_description"))
	}

	if code == "" || state == "" {
		log.Printf("[ERROR/RP] Missing code or state in callback")
		return s.renderErrorPage(c, "invalid_request", "Missing code or state parameter")
	}

	// 端到端延迟测试：不依赖RP服务端 session 来校验 state，也不做 code 重复使用判断
	var startTimeMs int64
	if startTime != "" {
		if v, err := strconv.ParseInt(startTime, 10, 64); err == nil {
			startTimeMs = v
		}
	}
	if startTimeMs > 0 {
		duration := time.Since(time.UnixMilli(startTimeMs))
		// 不再输出详细的中间打点，仅保留核心逻辑
		_ = duration
	}

	// 使用授权码交换token
	tokens, err := s.exchangeCodeForTokens(code, s.clientConfig.RedirectURI)
	if err != nil {
		log.Printf("[ERROR/RP] Failed to exchange code for tokens: %v", err)
		return s.renderErrorPage(c, "server_error", "Failed to exchange authorization code")
	}

	// 获取用户信息
	userInfo, err := s.getUserInfo(tokens.AccessToken)
	if err != nil {
		log.Printf("[ERROR/RP] Failed to get user info: %v", err)
		return s.renderErrorPage(c, "server_error", "Failed to get user information")
	}

	log.Printf("[INFO/RP] User %s successfully authenticated", userInfo.Sub)

	// 端到端延迟测试：直接渲染结果页，不用 session/cookie 维持登录状态
	result := &RPSession{
		State:        state,
		RedirectURI:  s.clientConfig.RedirectURI,
		Scope:        "openid profile email",
		ExpiresAt:    time.Now().Add(5 * time.Minute),
		UserInfo:     userInfo,
		AccessToken:  tokens.AccessToken,
		IDToken:      tokens.IDToken,
		RefreshToken: tokens.RefreshToken,
	}
	return s.renderUserPage(c, result)
}

func (s *OIDCRPServer) handleUser(c *fiber.Ctx) error {
	// 不维护登录态：直接回到首页，让用户再次点击触发一轮新的OIDC流程
	return c.Redirect("/oauth2/")
}

func (s *OIDCRPServer) handleLogout(c *fiber.Ctx) error {
	log.Printf("[INFO/RP] Logout (stateless mode)")
	return c.Redirect("/oauth2/")
}

// 辅助方法

func (s *OIDCRPServer) generateState() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return base64.URLEncoding.EncodeToString(bytes)
}

func (s *OIDCRPServer) exchangeCodeForTokens(code string, redirectURI string) (*RPTokenResponse, error) {
	// 构建token请求
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", redirectURI)
	data.Set("client_id", s.clientConfig.ClientID)
	data.Set("client_secret", s.clientConfig.ClientSecret)

	resp, err := http.PostForm(s.brokerConfig.TokenURL, data)
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

	var tokenResp RPTokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, err
	}

	return &tokenResp, nil
}

func (s *OIDCRPServer) getUserInfo(accessToken string) (*RPUserInfo, error) {
	req, err := http.NewRequest("GET", s.brokerConfig.UserInfoURL, nil)
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

	var userInfo RPUserInfo
	if err := json.Unmarshal(body, &userInfo); err != nil {
		return nil, err
	}

	return &userInfo, nil
}

func (s *OIDCRPServer) renderUserPage(c *fiber.Ctx, session *RPSession) error {
	tmpl, err := template.ParseFiles("./RP/static/oidc_user.html")
	if err != nil {
		log.Printf("[ERROR/RP] Failed to parse user template: %v", err)
		return c.Status(fiber.StatusInternalServerError).SendString("Template error")
	}

	data := struct {
		UserInfo    *RPUserInfo
		AccessToken string
		IDToken     string
	}{
		UserInfo:    session.UserInfo,
		AccessToken: s.truncateToken(session.AccessToken),
		IDToken:     s.truncateToken(session.IDToken),
	}

	c.Set("Content-Type", "text/html")
	return tmpl.Execute(c.Response().BodyWriter(), data)
}

func (s *OIDCRPServer) renderErrorPage(c *fiber.Ctx, error, description string) error {
	tmpl, err := template.ParseFiles("./RP/static/oidc_error.html")
	if err != nil {
		log.Printf("[ERROR/RP] Failed to parse error template: %v", err)
		return c.Status(fiber.StatusInternalServerError).SendString("Template error")
	}

	data := struct {
		Error       string
		Description string
	}{
		Error:       error,
		Description: description,
	}

	c.Set("Content-Type", "text/html")
	return tmpl.Execute(c.Response().BodyWriter(), data)
}

func (s *OIDCRPServer) truncateToken(token string) string {
	if len(token) > 100 {
		return token[:50] + "..." + token[len(token)-50:]
	}
	return token
}

// 客户端配置管理方法

const rpClientConfigFile = "RP/config/client_config.json"

type ClientConfigStorage struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	RedirectURI  string `json:"redirect_uri"`
}

func (s *OIDCRPServer) loadClientConfig(config *OIDCConfig) *RPClientConfig {
	// 尝试从文件加载
	data, err := os.ReadFile(rpClientConfigFile)
	if err != nil {
		if os.IsNotExist(err) {
			// 文件不存在，返回默认配置（只有 RedirectURI）
			return &RPClientConfig{
				RedirectURI:  config.RedirectURI,
				ClientID:     "",
				ClientSecret: "",
			}
		}
		log.Printf("[WARNING/RP] Failed to read client config file: %v", err)
		return &RPClientConfig{
			RedirectURI:  config.RedirectURI,
			ClientID:     "",
			ClientSecret: "",
		}
	}

	var stored ClientConfigStorage
	if err := json.Unmarshal(data, &stored); err != nil {
		log.Printf("[WARNING/RP] Failed to parse client config file: %v", err)
		return &RPClientConfig{
			RedirectURI:  config.RedirectURI,
			ClientID:     "",
			ClientSecret: "",
		}
	}

	// 如果存储的 RedirectURI 与配置不一致，使用配置中的
	redirectURI := stored.RedirectURI
	if redirectURI == "" {
		redirectURI = config.RedirectURI
	}

	return &RPClientConfig{
		ClientID:     stored.ClientID,
		ClientSecret: stored.ClientSecret,
		RedirectURI:  redirectURI,
	}
}

func (s *OIDCRPServer) saveClientConfig(config *RPClientConfig) error {
	// 保存到文件
	stored := ClientConfigStorage{
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		RedirectURI:  config.RedirectURI,
	}

	data, err := json.MarshalIndent(stored, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal client config: %w", err)
	}

	// 确保目录存在
	if err := os.MkdirAll("RP/config", 0755); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}

	if err := os.WriteFile(rpClientConfigFile, data, 0600); err != nil {
		return fmt.Errorf("write client config file: %w", err)
	}

	// 同时更新内存中的配置
	s.clientConfig = config
	log.Printf("[INFO/RP] Client config saved: ID=%s", config.ClientID)
	return nil
}

// autoRegister 自动向IdP和Broker注册RP
func (s *OIDCRPServer) autoRegister(oidcConfig *OIDCConfig) error {
	// 使用配置中的 RedirectURI
	redirectURI := oidcConfig.RedirectURI
	if redirectURI == "" {
		redirectURI = "http://localhost:14932/oauth2/callback" // 默认值
	}

	// 构建注册请求
	req := &ClientRegistrationRequest{
		ClientName:   "OIDC Relying Party",
		RedirectURIs: []string{redirectURI},
		ClientType:   "rp",
	}

	// 向IdP注册
	resp, err := s.registerWithIdP(req)
	if err != nil {
		return fmt.Errorf("register with IdP: %w", err)
	}

	// 保存客户端配置
	clientConfig := &RPClientConfig{
		ClientID:     resp.ClientID,
		ClientSecret: resp.ClientSecret,
		RedirectURI:  redirectURI,
	}

	if err := s.saveClientConfig(clientConfig); err != nil {
		return fmt.Errorf("save client config: %w", err)
	}

	// 向Broker注册RP凭据
	reqBroker := &RegisterToBrokerRequest{
		RPClientID:     clientConfig.ClientID,
		RPClientSecret: clientConfig.ClientSecret,
		RPRedirectURI:  clientConfig.RedirectURI,
		RPName:         "OIDC Relying Party",
	}

	if err := s.registerRPWithBroker(reqBroker); err != nil {
		log.Printf("[WARNING/RP] Failed to register RP with Broker: %v", err)
		// 不返回错误，因为RP已经成功注册到IdP
	}

	return nil
}

// ensureBrokerRegistration 确保 RP 在 Broker 注册（如果还没有注册）
func (s *OIDCRPServer) ensureBrokerRegistration(oidcConfig *OIDCConfig) error {
	if s.clientConfig == nil || s.clientConfig.ClientID == "" {
		return fmt.Errorf("no client configuration available")
	}

	// 向Broker注册RP凭据
	reqBroker := &RegisterToBrokerRequest{
		RPClientID:     s.clientConfig.ClientID,
		RPClientSecret: s.clientConfig.ClientSecret,
		RPRedirectURI:  s.clientConfig.RedirectURI,
		RPName:         "OIDC Relying Party",
	}

	if err := s.registerRPWithBroker(reqBroker); err != nil {
		return fmt.Errorf("register with Broker: %w", err)
	}

	log.Printf("[INFO/RP] Successfully ensured Broker registration for client: %s", s.clientConfig.ClientID)
	return nil
}

// 客户端注册相关处理方法

func (s *OIDCRPServer) handleRegisterPage(c *fiber.Ctx) error {
	tmpl, err := template.ParseFiles("./RP/static/oidc_register.html")
	if err != nil {
		log.Printf("[ERROR/RP] Failed to parse register template: %v", err)
		return c.Status(fiber.StatusInternalServerError).SendString("Template error")
	}

	c.Set("Content-Type", "text/html")
	return tmpl.Execute(c.Response().BodyWriter(), nil)
}

func (s *OIDCRPServer) handleRegister(c *fiber.Ctx) error {
	// 记录开始时间
	registerStartTime := time.Now()
	var req ClientRegistrationRequest
	if err := c.BodyParser(&req); err != nil {
		log.Printf("[ERROR/RP] Invalid registration request: %v", err)
		return c.Status(fiber.StatusBadRequest).JSON(RPErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "Invalid JSON format",
		})
	}

	// 验证请求参数
	if req.ClientName == "" || len(req.RedirectURIs) == 0 {
		return c.Status(fiber.StatusBadRequest).JSON(RPErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "Missing required fields: client_name and redirect_uris",
		})
	}

	// 向IdP注册客户端
	resp, err := s.registerWithIdP(&req)
	if err != nil {
		log.Printf("[ERROR/RP] Failed to register with IdP: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(RPErrorResponse{
			Error:            "server_error",
			ErrorDescription: "Failed to register with IdP",
		})
	}

	// 记录结束时间
	registerIdpEndTime := time.Now()
	registerIdpDuration := registerIdpEndTime.Sub(registerStartTime).Milliseconds()
	log.Printf("[INFO/RP] Register with IdP duration: %dms", registerIdpDuration)

	// 保存客户端配置
	clientConfig := &RPClientConfig{
		ClientID:     resp.ClientID,
		ClientSecret: resp.ClientSecret,
		RedirectURI:  req.RedirectURIs[0], // 使用第一个重定向URI
	}
	if debug == true {
		if err := s.saveClientConfig(clientConfig); err != nil {
			log.Printf("[ERROR/RP] Failed to save client config: %v", err)
			return c.Status(fiber.StatusInternalServerError).JSON(RPErrorResponse{
				Error:            "server_error",
				ErrorDescription: "Failed to save client configuration",
			})
		}
	}
	registerBrokerStartTime := time.Now()
	reqBroker := &RegisterToBrokerRequest{
		RPClientID:     clientConfig.ClientID,
		RPClientSecret: clientConfig.ClientSecret,
		RPRedirectURI:  clientConfig.RedirectURI,
		RPName:         req.ClientName,
	}

	// 将RP的客户端凭据提供给Broker，让Broker代理RP与IdP交互
	if err := s.registerRPWithBroker(reqBroker); err != nil {
		log.Printf("[WARNING/RP] Failed to register RP with Broker: %v", err)
		// 不返回错误，因为RP已经成功注册到IdP
	}

	registerBrokerEndTime := time.Now()
	registerBrokerDuration := registerBrokerEndTime.Sub(registerBrokerStartTime).Milliseconds()
	log.Printf("[Test/RP] Register with Broker duration: %dms", registerBrokerDuration)

	// Increment register test counter (thread-safe)
	currentTestNum := atomic.AddInt64(&registerTestCounter, 1)

	// Format result lines - each time on a separate line
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	var lines string
	lines += fmt.Sprintf("Test #%d At: %s\n", currentTestNum, timestamp)
	lines += fmt.Sprintf("  RegisterIdP Duration: %dms\n", registerIdpDuration)
	lines += fmt.Sprintf("  RegisterBroker Duration: %dms\n", registerBrokerDuration)
	lines += "\n" // Add blank line between tests

	// Write to file
	f, err := os.OpenFile("RP/register_latency_test.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("[ERROR/RP] Failed to open register latency file: %v", err)
	} else {
		defer f.Close()
		if _, err := f.WriteString(lines); err != nil {
			log.Printf("[ERROR/RP] Failed to write to register latency file: %v", err)
		}
	}

	log.Printf("[INFO/RP] Successfully registered client: %s", resp.ClientID)
	return c.JSON(resp)
}

func (s *OIDCRPServer) registerWithIdP(req *ClientRegistrationRequest) (*ClientRegistrationResponse, error) {
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

// 向Broker注册RP的客户端凭据，让Broker代理RP与IdP交互
func (s *OIDCRPServer) registerRPWithBroker(req *RegisterToBrokerRequest) error {
	// 构建向Broker注册RP凭据的请求
	requestData := map[string]interface{}{
		"rp_client_id":     req.RPClientID,
		"rp_client_secret": req.RPClientSecret,
		"rp_redirect_uri":  req.RPRedirectURI,
		"rp_name":          req.RPName,
	}

	requestBody, err := json.Marshal(requestData)
	if err != nil {
		return err
	}

	resp, err := http.Post(s.brokerConfig.RegisterURL, "application/json",
		bytes.NewBuffer(requestBody))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("Broker RP registration failed: %d %s", resp.StatusCode, string(body))
	}

	log.Printf("[INFO/RP] Successfully registered RP credentials with Broker")
	return nil
}
