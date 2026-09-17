package broker

import (
	"log"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
)

func StartBrokerServer(shouldRegister bool) {
	app := fiber.New()

	// 添加CORS中间件
	app.Use(cors.New(cors.Config{
		AllowOrigins:     "http://localhost:14930,http://127.0.0.1:14930,http://localhost:14932,http://127.0.0.1:14932",
		AllowMethods:     "GET,POST,HEAD,PUT,DELETE,PATCH,OPTIONS",
		AllowHeaders:     "Origin,Content-Type,Accept,Authorization,X-Requested-With",
		AllowCredentials: true,
	}))
	config := &RuntimeConfig{}
	err := config.Load(brokerRuntimeConfFile)
	if err != nil {
		panic(err)
	}

	app.Static("/static", "./Broker/static")

	// Initialize all servers
	tokenHelper := NewTokenHelper()
	tokenHelper.Issuer = config.Issuer
	// OIDC Server
	oidcServer := NewOIDCBrokerServer(tokenHelper, config.GetOIDCConfig())

	// 如果指定了 -register 参数，执行自动注册
	if shouldRegister {
		log.Println("[INFO/Broker] Auto-registration enabled, registering with IdP...")

		// 检查是否已有 IdP 配置
		if oidcServer.idpConfig == nil || oidcServer.idpConfig.ClientID == "" {
			// 向 IdP 注册 Broker
			if err := oidcServer.autoRegisterWithIdP(); err != nil {
				log.Printf("[ERROR/Broker] Failed to auto-register with IdP: %v", err)
			} else {
				log.Printf("[INFO/Broker] Successfully registered with IdP: %s", oidcServer.idpConfig.ClientID)
			}
		} else {
			log.Printf("[INFO/Broker] Already registered with IdP: %s", oidcServer.idpConfig.ClientID)
		}
	}

	oidcServer.UseOIDC(app)

	// Start the server
	app.Listen(":" + config.Port)
}
