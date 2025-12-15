package handler

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"my_project/internal/auth/domain"
	"my_project/internal/auth/usecase"
	"my_project/pkg/logger"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
)

type OAuthHandler struct {
	usecase usecase.UserUsecase
}

func NewOAuthHandler(u usecase.UserUsecase) *OAuthHandler {
	return &OAuthHandler{
		usecase: u,
	}
}

func (h *OAuthHandler) Bind(e *echo.Group) {
	// Google OAuth routes
	e.GET("/google", h.GoogleAuthURLHandler)
	e.GET("/google/callback", h.GoogleCallbackHandler)
}

func (h *OAuthHandler) GoogleAuthURLHandler(c echo.Context) error {
	stateBytes := make([]byte, 32)
	if _, err := rand.Read(stateBytes); err != nil {
		logger.Error("Failed to generate state parameter:", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to generate OAuth state"})
	}

	state := base64.URLEncoding.EncodeToString(stateBytes)

	clientID := os.Getenv("GOOGLE_CLIENT_ID")
	if clientID == "" {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Google OAuth not configured"})
	}

	redirectURI := fmt.Sprintf("%s/auth/google/callback", "http://localhost:8080") // TODO: make configurable
	authURL := fmt.Sprintf(
		"https://accounts.google.com/o/oauth2/v2/auth?client_id=%s&redirect_uri=%s&response_type=code&scope=email%%20profile&state=%s",
		clientID,
		redirectURI,
		state,
	)

	return c.JSON(http.StatusOK, map[string]string{
		"auth_url": authURL,
		"state":    state,
	})
}

func (h *OAuthHandler) GoogleCallbackHandler(c echo.Context) error {
	code := c.QueryParam("code")

	if code == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Authorization code is required"})
	}

	token, err := h.exchangeCodeForToken(code)
	if err != nil {
		logger.Error("Failed to exchange code for token:", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to exchange authorization code"})
	}

	// Get user info with access token
	ctx := c.Request().Context()
	userAgent := c.Request().UserAgent()
	ipAddress := c.RealIP()

	input := usecase.GoogleAuthInput{
		AccessToken: token.AccessToken,
		IDToken:     "", // We could also get ID token if needed
	}

	output, err := h.usecase.LoginWithGoogle(ctx, input, userAgent, ipAddress)
	if err != nil {
		switch {
		case errors.Is(err, domain.ErrOAuthTokenInvalid):
			return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Invalid Google token"})
		case errors.Is(err, domain.ErrOAuthEmailRequired):
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "Email is required from Google"})
		default:
			logger.Error("Unexpected error in GoogleCallbackHandler:", err)
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Internal server error"})
		}
	}

	// Set session cookie
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

	// Redirect to frontend with success
	// Or return JSON if it's an API flow
	return c.JSON(http.StatusOK, output)
}

func (h *OAuthHandler) exchangeCodeForToken(code string) (*usecase.GoogleTokenResponse, error) {
	clientID := os.Getenv("GOOGLE_CLIENT_ID")
	clientSecret := os.Getenv("GOOGLE_CLIENT_SECRET")
	redirectURI := "http://localhost:8080/auth/google/callback" // TODO: make configurable

	if clientID == "" || clientSecret == "" {
		return nil, errors.New("Google OAuth not configured")
	}

	// Exchange code for token
	tokenURL := "https://oauth2.googleapis.com/token"
	data := fmt.Sprintf(
		"code=%s&client_id=%s&client_secret=%s&redirect_uri=%s&grant_type=authorization_code",
		code,
		clientID,
		clientSecret,
		redirectURI,
	)

	resp, err := http.Post(tokenURL, "application/x-www-form-urlencoded", strings.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("token exchange failed")
	}

	var tokenResp usecase.GoogleTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, err
	}

	return &tokenResp, nil
}
