// Entry point for the IdP role: builds the Fiber app and starts listening.
package idp

import (
	"log"
	"strings"

	"secure-sso/internal/config"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
)

// StartIdpServer wires CORS, CSP and static assets onto a Fiber app and serves
// the IdP's /ssso routes until the process exits.
func StartIdpServer() {
	cfg := config.Get()
	app := fiber.New()

	app.Use(cors.New(cors.Config{
		AllowOrigins:     strings.Join(cfg.BrowserOrigins(), ","),
		AllowMethods:     "GET,POST,HEAD,PUT,DELETE,PATCH,OPTIONS",
		AllowHeaders:     "Origin,Content-Type,Accept,Authorization,X-Requested-With",
		AllowCredentials: true,
	}))

	frameSrc := cfg.FrameSrcCSP()
	app.Use(func(c *fiber.Ctx) error {
		c.Set("Content-Security-Policy", frameSrc)
		return c.Next()
	})

	app.Static("/static", cfg.StaticDir("IdP"))
	secureSSO := NewIdPServer()
	secureSSO.UseSecureSSO(app)

	addr := cfg.ListenAddr("idp")
	log.Printf("[IdP] profile=%s issuer=%s listening on %s", cfg.Profile, cfg.Issuer(), addr)
	if err := app.Listen(addr); err != nil {
		log.Fatalf("[IdP] listen on %s failed: %v", addr, err)
	}
}
