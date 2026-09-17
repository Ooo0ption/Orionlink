package rp

import (
	"log"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
)

func StartRpServer(shouldRegister bool) {
	app := fiber.New()

	// 添加CORS中间件
	app.Use(cors.New(cors.Config{
		AllowOrigins:     "http://localhost:14931,http://127.0.0.1:14931,http://localhost:14930,http://127.0.0.1:14930",
		AllowMethods:     "GET,POST,HEAD,PUT,DELETE,PATCH,OPTIONS",
		AllowHeaders:     "Origin,Content-Type,Accept,Authorization,X-Requested-With",
		AllowCredentials: true,
	}))
	config := &RuntimeConfig{}
	err := config.Load(rpRuntimeConfFile)
	if err != nil {
		panic(err)
	}

	app.Static("/static", "./RP/static")

	// OIDC Server
	oidcServer := NewOIDCRPServer(config.GetOIDCConfig())

	// 如果指定了 -register 参数，执行自动注册
	if shouldRegister {
		log.Println("[INFO/RP] Auto-registration enabled, registering with IdP and Broker...")
		oidcConfig := config.GetOIDCConfig()

		// 检查是否已有配置
		if oidcServer.clientConfig == nil || oidcServer.clientConfig.ClientID == "" {
			// 向 IdP 注册 RP
			if err := oidcServer.autoRegister(oidcConfig); err != nil {
				log.Printf("[ERROR/RP] Failed to auto-register: %v", err)
			} else {
				log.Printf("[INFO/RP] Successfully registered with IdP: %s", oidcServer.clientConfig.ClientID)
			}
		} else {
			log.Printf("[INFO/RP] Client already registered: %s", oidcServer.clientConfig.ClientID)
		}

		// 确保向 Broker 注册（无论是否是新注册）
		if oidcServer.clientConfig != nil && oidcServer.clientConfig.ClientID != "" {
			if err := oidcServer.ensureBrokerRegistration(oidcConfig); err != nil {
				log.Printf("[WARNING/RP] Failed to ensure Broker registration: %v", err)
			}
		}
	}

	oidcServer.UseOIDC(app)

	// Start the server
	log.Println("Starting RP server on port " + config.Port)
	app.Listen(":" + config.Port)
}
