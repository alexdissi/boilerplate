package handler

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"my_project/internal/auth/domain"
	"my_project/internal/auth/usecase"
	"my_project/pkg/logger"

	"github.com/labstack/echo/v4"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

const (
	oauthStateExpiration = 10 * time.Minute
)

type OAuthHandler struct {
	usecase usecase.UserUsecase
	config  *oauth2.Config
	cache   map[string]string // state -> timestamp for CSRF protection
	mu      sync.RWMutex      // protects cache
}

func NewOAuthHandler(u usecase.UserUsecase) *OAuthHandler {
	return &OAuthHandler{
		usecase: u,
		config: &oauth2.Config{
			Scopes: []string{
				"https://www.googleapis.com/auth/userinfo.email",
				"https://www.googleapis.com/auth/userinfo.profile",
			},
			Endpoint: google.Endpoint,
		},
		cache: make(map[string]string),
	}
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

	state, err := h.generateState()
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to generate state"})
	}

	redirectURI := h.getRedirectURI()
	config := *h.config
	config.ClientID = clientID
	config.ClientSecret = os.Getenv("GOOGLE_CLIENT_SECRET")
	config.RedirectURL = redirectURI

	h.mu.Lock()
	h.cache[state] = time.Now().Format(time.RFC3339)
	h.mu.Unlock()

	return c.JSON(http.StatusOK, map[string]string{
		"auth_url": config.AuthCodeURL(state),
		"state":    state,
	})
}

func (h *OAuthHandler) GoogleCallback(c echo.Context) error {
	code := c.QueryParam("code")
	state := c.QueryParam("state")

	if code == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Authorization code required"})
	}

	if !h.validateState(state) {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid state"})
	}

	h.mu.Lock()
	delete(h.cache, state)
	h.mu.Unlock()

	config := *h.config
	config.ClientID = os.Getenv("GOOGLE_CLIENT_ID")
	config.ClientSecret = os.Getenv("GOOGLE_CLIENT_SECRET")
	config.RedirectURL = h.getRedirectURI()

	token, err := config.Exchange(c.Request().Context(), code)
	if err != nil {
		logger.Error("Token exchange failed:", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Token exchange failed"})
	}

	client := config.Client(c.Request().Context(), token)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		logger.Error("Failed to get user info:", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to get user info"})
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Failed to get user info"})
	}

	var googleUser struct {
		ID            string `json:"id"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"verified_email"`
		Name          string `json:"name"`
		GivenName     string `json:"given_name"`
		FamilyName    string `json:"family_name"`
		Picture       string `json:"picture"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&googleUser); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to decode user info"})
	}

	if googleUser.GivenName == "" && googleUser.FamilyName == "" {
		if googleUser.Name != "" {
			parts := strings.Fields(googleUser.Name)
			if len(parts) >= 1 {
				googleUser.GivenName = parts[0]
			}
			if len(parts) >= 2 {
				googleUser.FamilyName = strings.Join(parts[1:], " ")
			}
		} else {
			emailParts := strings.Split(googleUser.Email, "@")
			if len(emailParts) > 0 {
				googleUser.GivenName = emailParts[0]
			}
		}
	}

	googleUserInfo := &usecase.GoogleUserInfo{
		ID:            googleUser.ID,
		Email:         googleUser.Email,
		EmailVerified: googleUser.EmailVerified,
		Name:          googleUser.Name,
		FirstName:     googleUser.GivenName,
		LastName:      googleUser.FamilyName,
		Picture:       googleUser.Picture,
	}

	ctx := c.Request().Context()
	output, err := h.usecase.LoginWithGoogleInfo(ctx, googleUserInfo, c.Request().UserAgent(), c.RealIP())
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

func (h *OAuthHandler) generateState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

func (h *OAuthHandler) validateState(state string) bool {
	if state == "" {
		return false
	}

	h.mu.RLock()
	timestampStr, exists := h.cache[state]
	h.mu.RUnlock()

	if !exists {
		return false
	}

	timestamp, err := time.Parse(time.RFC3339, timestampStr)
	if err != nil {
		return false
	}

	return time.Since(timestamp) < oauthStateExpiration
}

func (h *OAuthHandler) getRedirectURI() string {
	if uri := os.Getenv("GOOGLE_REDIRECT_URI"); uri != "" {
		return uri
	}
	return "http://localhost:8080/auth/google/callback"
}