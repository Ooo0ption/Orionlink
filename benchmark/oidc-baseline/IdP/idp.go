package idp

import (
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
)

func StartIdpServer() {
	app := fiber.New()

	// 添加CORS中间件
	app.Use(cors.New(cors.Config{
		AllowOrigins:     "http://localhost:14931,http://127.0.0.1:14931,http://localhost:14930,http://127.0.0.1:14930",
		AllowMethods:     "GET,POST,HEAD,PUT,DELETE,PATCH,OPTIONS",
		AllowHeaders:     "Origin,Content-Type,Accept,Authorization,X-Requested-With",
		AllowCredentials: true,
	}))

	app.Static("/static", "./IdP/static")

	// OIDC Server
	oidc := NewOIDCIdPServer()
	oidc.UseOIDC(app)

	app.Listen(":14930")
}
