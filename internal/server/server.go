package server

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	_ "github.com/joho/godotenv/autoload"

	"my_project/internal/auth/repository"
	"my_project/internal/database"
	"my_project/pkg/crypto"
	"my_project/pkg/logger"
	"my_project/pkg/mailer"
)

type Server struct {
	port int

	db     database.Service
	mailer mailer.Mailer
}

const (
	FROM_EMAIL = "contact@figenn.com"
)

func NewServer() *http.Server {
	port, _ := strconv.Atoi(os.Getenv("PORT"))
	resendAPIKey := os.Getenv("RESEND_API_KEY")
	fromEmail := FROM_EMAIL
	encryptionKey := os.Getenv("ENCRYPTION_KEY")
	if err := crypto.SetEncryptionKey(encryptionKey); err != nil {
		panic("ENCRYPTION_KEY must be set and at least 32 characters long")
	}

	NewServer := &Server{
		port:   port,
		db:     database.New(),
		mailer: mailer.NewResendMailer(resendAPIKey, fromEmail),
	}

	// Start background cleanup worker for expired sessions
	go NewServer.startSessionCleanupWorker()

	// Declare Server config
	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", NewServer.port),
		Handler:      NewServer.RegisterRoutes(),
		IdleTimeout:  time.Minute,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	return server
}

func (s *Server) startSessionCleanupWorker() {
	ticker := time.NewTicker(6 * time.Hour)
	defer ticker.Stop()

	userStore := repository.NewUserStore(s.db)

	// Run cleanup immediately on startup
	ctx := context.Background()
	deleted, err := userStore.DeleteExpiredSessions(ctx)
	if err != nil {
		logger.Error("Failed to cleanup expired sessions on startup:", err)
	} else if deleted > 0 {
		logger.Info("Cleaned up expired sessions on startup", "count", deleted)
	}

	// Then run every 6 hours
	for range ticker.C {
		ctx := context.Background()
		deleted, err := userStore.DeleteExpiredSessions(ctx)
		if err != nil {
			logger.Error("Failed to cleanup expired sessions:", err)
		} else if deleted > 0 {
			logger.Info("Cleaned up expired sessions", "count", deleted)
		}
	}
}
