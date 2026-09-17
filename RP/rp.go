// Entry point for the RP role: builds the Fiber app and starts listening.
package rp

import (
	"log"
	"strings"

	orionconf "secure-sso/internal/config"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
)

// StartRpServer loads the RP runtime config, wires CORS and static assets onto a
// Fiber app, registers with the IdP and broker, and serves the /ssso routes.
func StartRpServer() {
	cfg := orionconf.Get()
	app := fiber.New()

	app.Use(cors.New(cors.Config{
		AllowOrigins:     strings.Join(cfg.BrowserOrigins(), ","),
		AllowMethods:     "GET,POST,HEAD,PUT,DELETE,PATCH,OPTIONS",
		AllowHeaders:     "Origin,Content-Type,Accept,Authorization,X-Requested-With",
		AllowCredentials: true,
	}))

	runtimeConf := &RuntimeConfig{}
	if err := runtimeConf.Load(rpRuntimeConfFile()); err != nil {
		log.Fatalf("[RP] load %s: %v", rpRuntimeConfFile(), err)
	}
	runtimeConf.ApplyEnv(cfg)

	app.Static("/static", cfg.StaticDir("RP"))

	app.Get("/", func(c *fiber.Ctx) error {
		return c.Redirect("/ssso/", fiber.StatusFound)
	})

	sssoServer := NewRPClientServer(runtimeConf.GetSecureSSOConfig())
	sssoServer.UseSecureSSO(app)

	sssoServer.AutoRegister(cfg)

	addr := cfg.ListenAddr("rp")
	log.Printf("[RP] profile=%s public=%s listening on %s", cfg.Profile, cfg.RP.Browser, addr)
	if err := app.Listen(addr); err != nil {
		log.Fatalf("[RP] listen on %s failed: %v", addr, err)
	}
}
