package middleware

import (
	"net/http"
	"os"
	"time"

	"github.com/bluele/gcache"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
)

type CachedSession struct {
	UserID string
	Email  string
}

var (
	dbPool       *pgxpool.Pool
	sessionCache = gcache.New(1000).LRU().Expiration(time.Minute * 15).Build()
)

func InitSessionMiddleware(pool *pgxpool.Pool) {
	dbPool = pool
}

func InvalidateSessionCache(sessionToken string) {
	sessionCache.Remove(sessionToken)
}

func CookieSessionMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			cookie, err := c.Cookie("session_token")
			if err != nil || cookie.Value == "" {
				return c.JSON(http.StatusUnauthorized, echo.Map{
					"error": "missing session token",
				})
			}

			sessionToken := cookie.Value

			cachedData, err := sessionCache.Get(sessionToken)
			if err == nil {
				session := cachedData.(CachedSession)
				c.Set("session_token", sessionToken)
				c.Set("user_id", session.UserID)
				c.Set("email", session.Email)
				return next(c)
			}

			ctx := c.Request().Context()

			query := `
				SELECT u.id, u.email
				FROM sessions s
				JOIN users u ON u.id = s.user_id
				WHERE s.session_token = $1
				AND s.expires_at > NOW()
				AND u.is_active = true
			`

			var userID, email string
			err = dbPool.QueryRow(ctx, query, sessionToken).Scan(&userID, &email)
			if err != nil {
				clearCookie := &http.Cookie{
					Name:     "session_token",
					Value:    "",
					Path:     "/",
					HttpOnly: true,
					Secure:   os.Getenv("APP_ENV") == "production",
					SameSite: http.SameSiteStrictMode,
					MaxAge:   -1,
				}
				c.SetCookie(clearCookie)
				return c.JSON(http.StatusUnauthorized, echo.Map{
					"error": "invalid or expired session",
				})
			}

			_ = sessionCache.Set(sessionToken, CachedSession{
				UserID: userID,
				Email:  email,
			})

			c.Set("session_token", sessionToken)
			c.Set("user_id", userID)
			c.Set("email", email)

			return next(c)
		}
	}
}
