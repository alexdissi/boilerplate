package handler

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"time"

	"my_project/internal/auth/domain"
	"my_project/internal/auth/usecase"
	"my_project/pkg/logger"

	"github.com/labstack/echo/v4"
)

type OAuthHandler struct {
	usecase usecase.UserUsecase
}

func NewOAuthHandler(u usecase.UserUsecase) *OAuthHandler {
	return &OAuthHandler{usecase: u}
}

func (h *OAuthHandler) Bind(e *echo.Group) {
	e.GET("/google", h.GoogleAuthURL)
	e.GET("/google/callback", h.GoogleCallback)
}

func (h *OAuthHandler) GoogleAuthURL(c echo.Context) error {
	clientID := os.Getenv("GOOGLE_CLIENT_ID")
	if clientID == "" {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "OAuth not configured"})
	}

	b := make([]byte, 32)
	rand.Read(b)
	state := base64.URLEncoding.EncodeToString(b)

	redirectURI := "http://localhost:8080/auth/google/callback"
	if uri := os.Getenv("GOOGLE_REDIRECT_URI"); uri != "" {
		redirectURI = uri
	}

	authURL := "https://accounts.google.com/o/oauth2/v2/auth?" + strings.Join([]string{
		"client_id=" + clientID,
		"redirect_uri=" + redirectURI,
		"response_type=code",
		"scope=email profile",
		"state=" + state,
	}, "&")

	return c.JSON(http.StatusOK, map[string]string{
		"auth_url": authURL,
		"state":    state,
	})
}

func (h *OAuthHandler) GoogleCallback(c echo.Context) error {
	code := c.QueryParam("code")
	if code == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Authorization code required"})
	}

	clientID := os.Getenv("GOOGLE_CLIENT_ID")
	clientSecret := os.Getenv("GOOGLE_CLIENT_SECRET")
	redirectURI := "http://localhost:8080/auth/google/callback"
	if uri := os.Getenv("GOOGLE_REDIRECT_URI"); uri != "" {
		redirectURI = uri
	}

	data := strings.Join([]string{
		"code=" + code,
		"client_id=" + clientID,
		"client_secret=" + clientSecret,
		"redirect_uri=" + redirectURI,
		"grant_type=authorization_code",
	}, "&")

	resp, err := http.Post("https://oauth2.googleapis.com/token", "application/x-www-form-urlencoded", strings.NewReader(data))
	if err != nil {
		logger.Error("Token exchange failed:", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Token exchange failed"})
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Token exchange failed"})
	}

	var token usecase.GoogleTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Token decode failed"})
	}

	ctx := c.Request().Context()
	input := usecase.GoogleAuthInput{AccessToken: token.AccessToken}

	output, err := h.usecase.LoginWithGoogle(ctx, input, c.Request().UserAgent(), c.RealIP())
	if err != nil {
		switch {
		case errors.Is(err, domain.ErrOAuthTokenInvalid):
			return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Invalid token"})
		case errors.Is(err, domain.ErrOAuthEmailRequired):
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "Email required"})
		default:
			logger.Error("OAuth error:", err)
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "OAuth failed"})
		}
	}

	c.SetCookie(&http.Cookie{
		Name:     "session_token",
		Value:    output.Session.Token,
		Expires:  time.Now().Add(domain.SessionDurationMinutes * time.Minute),
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})

	return c.JSON(http.StatusOK, output)
}
