// Entry point for the Broker role: builds the Fiber app and starts listening.
package broker

import (
	"log"
	"strings"

	orionconf "secure-sso/internal/config"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
)

// StartBrokerServer loads the broker runtime config, wires CORS, CSP and static
// assets onto a Fiber app, and serves the /ssso routes until the process exits.
func StartBrokerServer() {
	cfg := orionconf.Get()
	app := fiber.New()

	app.Use(cors.New(cors.Config{
		AllowOrigins:     strings.Join(cfg.BrowserOrigins(), ","),
		AllowMethods:     "GET,POST,HEAD,PUT,DELETE,PATCH,OPTIONS",
		AllowHeaders:     "Origin,Content-Type,Accept,Authorization,X-Requested-With",
		AllowCredentials: true,
	}))

	runtimeConf := &RuntimeConfig{}
	if err := runtimeConf.Load(brokerRuntimeConfFile()); err != nil {
		log.Fatalf("[Broker] load %s: %v", brokerRuntimeConfFile(), err)
	}
	runtimeConf.ApplyEnv(cfg)

	frameSrc := cfg.FrameSrcCSP()
	app.Use(func(c *fiber.Ctx) error {
		c.Set("Content-Security-Policy", frameSrc)
		return c.Next()
	})

	app.Static("/static", cfg.StaticDir("Broker"))

	tokenHelper := NewTokenHelper()
	tokenHelper.Issuer = runtimeConf.Issuer
	sssoServer := NewBrokerClientServer(tokenHelper, runtimeConf.GetSecureSSOConfig())
	sssoServer.UseSecureSSO(app)

	addr := cfg.ListenAddr("broker")
	log.Printf("[Broker] profile=%s issuer=%s listening on %s", cfg.Profile, runtimeConf.Issuer, addr)
	if err := app.Listen(addr); err != nil {
		log.Fatalf("[Broker] listen on %s failed: %v", addr, err)
	}
}
