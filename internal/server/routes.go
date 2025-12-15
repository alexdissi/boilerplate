package server

import (
	"my_project/internal/auth/handler"
	"my_project/internal/auth/repository"
	"my_project/internal/auth/usecase"
	sessionMiddleware "my_project/internal/middleware"
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

func (s *Server) RegisterRoutes() http.Handler {
	e := echo.New()
	e.Use(middleware.RequestLogger())
	e.Use(middleware.Recover())
	e.Use(middleware.SecureWithConfig(middleware.SecureConfig{
		XFrameOptions:         "DENY",
		ContentTypeNosniff:    "nosniff",
		XSSProtection:         "1; mode=block",
		HSTSMaxAge:            31536000,
		HSTSExcludeSubdomains: false,
		ContentSecurityPolicy: "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' https:; connect-src 'self' https:;",
	}))

	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins:     []string{"https://*", "http://*"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"},
		AllowHeaders:     []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	e.Use(middleware.RateLimiterWithConfig(middleware.RateLimiterConfig{
		Store: middleware.NewRateLimiterMemoryStore(100),
		DenyHandler: func(c echo.Context, identifier string, err error) error {
			return c.JSON(http.StatusTooManyRequests, echo.Map{"error": "rate limit exceeded"})
		},
	}))
	e.Use(middleware.BodyLimit("2MB"))
	sessionMiddleware.InitSessionMiddleware(s.db.Pool())

	e.GET("/", s.HelloWorldHandler)

	e.GET("/health", s.healthHandler)
	apiGroup := e.Group("")

	s.setupAuthRoutes(apiGroup)

	return e
}

func (s *Server) HelloWorldHandler(c echo.Context) error {
	resp := map[string]string{
		"message": "Hello World",
	}

	return c.JSON(http.StatusOK, resp)
}

func (s *Server) healthHandler(c echo.Context) error {
	return c.JSON(http.StatusOK, s.db.Health())
}

func (s *Server) setupAuthRoutes(apiGroup *echo.Group) {
	userStore := repository.NewUserStore(s.db)
	authUsecase := usecase.NewUserService(userStore)
	authHandler := handler.NewAuthHandler(authUsecase)
	oauthHandler := handler.NewOAuthHandler(authUsecase)

	authGroup := apiGroup.Group("/auth")
	authHandler.Bind(authGroup)
	oauthHandler.Bind(authGroup)
}
