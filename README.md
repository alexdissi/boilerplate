# Go Boilerplate API

A modern Go boilerplate with clean architecture, authentication, Stripe payments, and PostgreSQL integration. Designed to quickly start production-ready web applications.

## 🚀 Tech Stack

- **Language**: Go 1.25.4
- **Web Framework**: Echo v4
- **Database**: PostgreSQL with pgx/v5
- **Authentication**: Email/Password + OAuth (Google)
- **Payments**: Stripe with subscription management
- **Emails**: Resend API for transactional emails
- **Testing**: Testcontainers for integration tests
- **Build**: Air (live reload), Goose (migrations), GoReleaser

## 📋 Prerequisites

- Go 1.25.4+
- PostgreSQL
- Docker (optional, for containerized database)
- Make

## ⚙️ Quick Setup

### 1. Clone the project

```bash
git clone <repository-url>
cd boilerplate
```

### 2. Install Go dependencies

```bash
go mod tidy
```

### 3. Configure environment variables

Create a `.env` file in the project root:

```bash
# Database
DATABASE_URL=postgresql://username:password@localhost:5432/your_db?sslmode=disable

# OR configure individual variables
DB_HOST=localhost
DB_PORT=5432
DB_USERNAME=your_username
DB_PASSWORD=your_password
DB_DATABASE=your_database
DB_SSL_MODE=disable

# Server
PORT=8080

# External services
RESEND_API_KEY=your_resend_key
FROM_EMAIL=contact@yourdomain.com
```

### 4. Start the database

**Option A - With Docker (recommended):**
```bash
make docker-run
```

**Option B - Local database:**
```bash
# Start PostgreSQL on port 5432 and create the database
createdb your_database
```

### 5. Run migrations

```bash
make migrate-up
```

### 6. Start the application

```bash
make run
```

The API is now available at `http://localhost:8080`

## 🔨 Available Commands

### Build & Execution

```bash
make all          # Build application and run tests
make build        # Build the application (go build)
make run          # Execute the application
make watch        # Live-reload with Air (recommended for development)
```

### Database

```bash
make docker-run      # Create and start PostgreSQL container
make docker-down     # Shutdown PostgreSQL container
make migrate-up      # Run migrations (installs Goose if needed)
make migrate-down    # Rollback migrations
make create-migration NAME=migration_name  # Create a new migration
```

### Testing

```bash
make test         # Run the test suite
make itest        # Integration tests for database module
make clean        # Clean up build artifacts
```

## 🏗️ Project Architecture

```
boilerplate/
├── cmd/
│   └── api/
│       └── main.go              # Application entry point
├── internal/
│   ├── auth/                    # Authentication module
│   │   ├── domain/             # Business logic
│   │   ├── handler/            # HTTP handlers
│   │   ├── repository/         # Data access layer
│   │   └── usecase/            # Use cases
│   ├── database/               # Database configuration
│   ├── payment/                # Stripe payment module
│   │   ├── domain/             # Payment business logic
│   │   ├── handler/            # Payment handlers
│   │   ├── repository/         # Payment data access
│   │   └── usecase/            # Payment use cases
│   ├── server/                 # Echo server configuration
│   └── middleware/             # HTTP middleware
├── pkg/
│   ├── logger/                 # Logging utility
│   ├── mailer/                 # Email service (Resend)
│   └── password/               # Password utilities
├── migrations/                 # Database migrations
│   ├── 20251213114251_add_user_and_session.sql
│   └── 20251219001947_add_subscription_table.sql
├── .air.toml                   # Air configuration (live reload)
├── .goreleaser.yml             # GoReleaser configuration
└── Makefile                    # Build automation
```

## 🗄️ Database Schema

### Users & Sessions
- **Users**: User management with email/password auth and Google OAuth
- **Sessions**: Session management with authentication tokens
- Features: Password reset tokens, last login tracking

### Subscriptions
- **Subscriptions**: User subscription management with Stripe
- Features: Plans, licenses, status tracking, expiration dates

## 🚀 Development

### Live Reload

For development, use `make watch` which automatically reloads on code changes:

```bash
make watch
```

### Creating New Migrations

```bash
make create-migration NAME=add_new_table
```

### Testing

```bash
make test          # All tests
make itest         # Database integration tests
```

## 🔧 Advanced Configuration

### Optional Environment Variables

```bash
# Advanced DB configuration
DB_MAX_CONNECTIONS=25       # Max pool connections (default: 25)
DB_MAX_IDLE_CONNECTIONS=5   # Max idle connections (default: 5)
DB_MAX_LIFETIME=5m          # Connection lifetime (default: 5m)

# Logging
LOG_LEVEL=info             # debug, info, warn, error
LOG_FORMAT=json            # json or text
```

### OAuth Configuration

To enable Google OAuth authentication:

```bash
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
```

### Stripe Configuration

For payment management:

```bash
STRIPE_SECRET_KEY=sk_test_...
STRIPE_PUBLISHABLE_KEY=pk_test_...
STRIPE_WEBHOOK_SECRET=whsec_...
```

## 📝 Deployment Guide

### Production Build

```bash
make build
./main
```

### With GoReleaser

```bash
goreleaser build --rm-dist
```

### Docker (optional)

The project can be containerized. Create a `Dockerfile`:

```dockerfile
FROM golang:1.25.4-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o main cmd/api/main.go

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/main .
CMD ["./main"]
```

## 🧪 Testing & Quality

The project includes a comprehensive test suite:

- Unit tests for each module
- Integration tests with testcontainers
- API endpoint coverage
- Edge cases and error handling tests

## 🤝 Contributing

1. Fork the project
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔗 Useful Links

- [Echo Documentation](https://echo.labstack.com/docs)
- [pgx Documentation](https://pgx.github.io/pgx/v5/)
- [Stripe Go Documentation](https://stripe.com/docs/api/go)
- [Resend Documentation](https://resend.com/docs/api-reference/introduction)

---

**Ready to develop?** Check out the module documentation in `internal/` to discover the detailed architecture of each component.