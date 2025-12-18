package server

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	_ "github.com/joho/godotenv/autoload"

	"my_project/internal/database"
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
	NewServer := &Server{
		port:   port,
		db:     database.New(),
		mailer: mailer.NewResendMailer(resendAPIKey, fromEmail),
	}

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
