package server

import (
	"my_project/internal/auth/handler"
	"my_project/internal/auth/repository"
	"my_project/internal/auth/usecase"
	sessionMiddleware "my_project/internal/middleware"
	"my_project/internal/payment/client"
	paymentHandler "my_project/internal/payment/handler"
	paymentRepository "my_project/internal/payment/repository"
	paymentUsecase "my_project/internal/payment/usecase"
	usersHandler "my_project/internal/users/handler"
	usersRepository "my_project/internal/users/repository"
	usersUsecase "my_project/internal/users/usecase"
	"net/http"
	"os"

	passwordValidator "my_project/pkg/validator"

	"github.com/go-playground/validator/v10"
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
	sessionMiddleware.InitSubscriptionMiddleware(s.db.Pool())
	e.GET("/", s.HelloWorldHandler)

	e.GET("/health", s.healthHandler)
	apiGroup := e.Group("")

	s.setupAuthRoutes(apiGroup)
	s.setupUsersRoutes(apiGroup)
	s.setupPaymentRoutes(apiGroup)

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
	authUsecase := usecase.NewUserService(userStore, s.mailer)
	authHandler := handler.NewAuthHandler(authUsecase)
	oauthHandler := handler.NewOAuthHandler(authUsecase)

	authGroup := apiGroup.Group("/auth")
	authHandler.Bind(authGroup)
	oauthHandler.Bind(authGroup)
}

func (s *Server) setupPaymentRoutes(apiGroup *echo.Group) {
	subscriptionStore := paymentRepository.NewSubscriptionRepository(s.db)

	stripeConfig := client.StripeConfig{
		SecretKey:     os.Getenv("STRIPE_SECRET_KEY"),
		WebhookSecret: os.Getenv("STRIPE_WEBHOOK_SECRET"),
		AppUrl:        os.Getenv("APP_URL"),
	}

	stripeProvider, err := client.NewStripeProvider(stripeConfig)
	if err != nil {
		panic("failed to initialize Stripe provider: " + err.Error())
	}

	paymentUsecaseConfig := paymentUsecase.Config{
		PriceProID:      os.Getenv("STRIPE_PRICE_PROFESSIONAL_ID"),
		PriceBusinessID: os.Getenv("STRIPE_PRICE_BUSINESS_ID"),
	}

	paymentUseCase := paymentUsecase.NewPaymentUsecase(subscriptionStore, stripeProvider, paymentUsecaseConfig)
	paymentHandler := paymentHandler.NewPaymentHandler(paymentUseCase)

	paymentGroup := apiGroup.Group("/payment")
	paymentHandler.Bind(paymentGroup)
}

func (s *Server) setupUsersRoutes(apiGroup *echo.Group) {
	userStore := usersRepository.NewUserStore(s.db)
	usersUseCase := usersUsecase.NewUserUsecase(userStore)
	validator := validator.New()
	validator.RegisterValidation("strongpassword", passwordValidator.ValidateStrongPassword)

	usersHandler := usersHandler.NewUserHandler(usersUseCase, validator)

	usersGroup := apiGroup.Group("/users", sessionMiddleware.CookieSessionMiddleware())

	usersHandler.Bind(usersGroup)
}
