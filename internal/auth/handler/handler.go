package handler

import (
	"errors"
	"my_project/internal/auth/domain"
	"my_project/internal/auth/usecase"
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
	e.POST("/logout", h.LogoutUserHandler)
}

func (h *AuthHandler) RegisterUserHandler(c echo.Context) error {
	var req usecase.RegisterUserInput
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request format"})
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

	return c.JSON(http.StatusOK, output.User)
}

func (h *AuthHandler) LogoutUserHandler(c echo.Context) error {
	cookie, err := c.Cookie("session_token")
	if err != nil {
		return c.JSON(http.StatusOK, map[string]string{"message": "Logged out successfully"})
	}

	token := cookie.Value
	if token == "" {
		return c.JSON(http.StatusOK, map[string]string{"message": "Logged out successfully"})
	}

	ctx := c.Request().Context()
	result, err := h.usecase.LogoutUser(ctx, usecase.LogoutInput{Token: token})
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
