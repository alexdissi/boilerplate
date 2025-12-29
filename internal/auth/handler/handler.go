package handler

import (
	"errors"
	"my_project/internal/auth/domain"
	"my_project/internal/auth/usecase"
	"my_project/internal/middleware"
	"my_project/pkg/logger"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
)

type AuthHandler struct {
	usecase usecase.UserUsecase
}

func NewAuthHandler(u usecase.UserUsecase) *AuthHandler {
	return &AuthHandler{
		usecase: u,
	}
}

func (h *AuthHandler) Bind(e *echo.Group) {
	e.POST("/register", h.RegisterUserHandler)
	e.POST("/login", h.LoginUserHandler)
	e.POST("/challenge", h.VerifyTwoFactorHandler)
	e.POST("/logout", h.LogoutUserHandler, middleware.CookieSessionMiddleware())
	e.POST("/forgot-password", h.ForgotPasswordHandler)
	e.POST("/reset-password", h.ResetPasswordHandler)
}

func (h *AuthHandler) RegisterUserHandler(c echo.Context) error {
	var req usecase.RegisterUserInput
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request format"})
	}

	if err := c.Validate(&req); err != nil {
		return err
	}

	ctx := c.Request().Context()
	output, err := h.usecase.RegisterUser(ctx, req)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	return c.JSON(http.StatusCreated, output)
}

func (h *AuthHandler) LoginUserHandler(c echo.Context) error {
	var req usecase.LoginUserInput
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request format"})
	}

	if err := c.Validate(&req); err != nil {
		return err
	}

	ctx := c.Request().Context()
	userAgent := c.Request().UserAgent()
	ipAddress := c.RealIP()
	output, err := h.usecase.LoginUser(ctx, req, userAgent, ipAddress)
	if err != nil {
		switch {
		case errors.Is(err, domain.ErrInvalidCredentials):
			return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Invalid email or password"})
		case errors.Is(err, domain.ErrTooManyLoginAttempts):
			return c.JSON(http.StatusTooManyRequests, map[string]string{"error": "Too many login attempts, please try again later"})
		default:
			logger.Error("Unexpected error in LoginUserHandler:", err)
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
		}
	}

	if !output.RequiresTwoFactor && output.Session.Token != "" {
		cookie := &http.Cookie{
			Name:     "session_token",
			Value:    output.Session.Token,
			Expires:  time.Now().Add(domain.SessionDurationMinutes * time.Minute),
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
		}
		c.SetCookie(cookie)
	}

	return c.JSON(http.StatusOK, output)
}

func (h *AuthHandler) VerifyTwoFactorHandler(c echo.Context) error {
	var req usecase.VerifyTwoFactorInput
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request format"})
	}

	if err := c.Validate(&req); err != nil {
		return err
	}

	ctx := c.Request().Context()
	userAgent := c.Request().UserAgent()
	ipAddress := c.RealIP()
	output, err := h.usecase.VerifyTwoFactor(ctx, req, userAgent, ipAddress)
	if err != nil {
		switch {
		case errors.Is(err, domain.ErrInvalidCredentials):
			return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Invalid email or code"})
		case errors.Is(err, domain.ErrTwoFactorNotEnabled):
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "Two-factor authentication is not enabled for this account"})
		case errors.Is(err, domain.ErrInvalidTwoFactorCode):
			return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Invalid two-factor code"})
		default:
			logger.Error("Unexpected error in VerifyTwoFactorHandler:", err)
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
		}
	}

	if output.Session.Token != "" {
		cookie := &http.Cookie{
			Name:     "session_token",
			Value:    output.Session.Token,
			Expires:  time.Now().Add(domain.SessionDurationMinutes * time.Minute),
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
		}
		c.SetCookie(cookie)
	}

	return c.JSON(http.StatusOK, output)
}

func (h *AuthHandler) LogoutUserHandler(c echo.Context) error {
	token, ok := c.Get("session_token").(string)
	if !ok || token == "" {
		return c.JSON(http.StatusOK, map[string]string{"message": "Logged out successfully"})
	}

	ctx := c.Request().Context()
	result, err := h.usecase.LogoutUser(ctx, token)
	if err != nil {
		logger.Error("Error during logout:", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
	}

	clearCookie := &http.Cookie{
		Name:     "session_token",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	}
	c.SetCookie(clearCookie)

	return c.JSON(http.StatusOK, result)
}

func (h *AuthHandler) ForgotPasswordHandler(c echo.Context) error {
	var req usecase.ForgotPasswordInput
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request format"})
	}

	if err := c.Validate(&req); err != nil {
		return err
	}

	ctx := c.Request().Context()
	output, err := h.usecase.ForgotPassword(ctx, req)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	return c.JSON(http.StatusOK, output)
}

func (h *AuthHandler) ResetPasswordHandler(c echo.Context) error {
	var req usecase.ResetPasswordInput
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request format"})
	}

	if err := c.Validate(&req); err != nil {
		return err
	}

	ctx := c.Request().Context()
	output, err := h.usecase.ResetPassword(ctx, req)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	return c.JSON(http.StatusOK, output)
}
