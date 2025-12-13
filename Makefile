# Simple Makefile for a Go project

# Build the application
all: build test

build:
	@echo "Building..."
	
	
	@go build -o main cmd/api/main.go

# Run the application
run:
	@go run cmd/api/main.go
# Create DB container
docker-run:
	@if docker compose up --build 2>/dev/null; then \
		: ; \
	else \
		echo "Falling back to Docker Compose V1"; \
		docker-compose up --build; \
	fi

# Shutdown DB container
docker-down:
	@if docker compose down 2>/dev/null; then \
		: ; \
	else \
		echo "Falling back to Docker Compose V1"; \
		docker-compose down; \
	fi

# Test the application
test:
	@echo "Testing..."
	@go test ./... -v
# Integrations Tests for the application
itest:
	@echo "Running integration tests..."
	@go test ./internal/database -v

# Clean the binary
clean:
	@echo "Cleaning..."
	@rm -f main

# Live Reload
watch:
	@if command -v air > /dev/null; then \
            air; \
            echo "Watching...";\
        else \
            read -p "Go's 'air' is not installed on your machine. Do you want to install it? [Y/n] " choice; \
            if [ "$$choice" != "n" ] && [ "$$choice" != "N" ]; then \
                go install github.com/air-verse/air@latest; \
                air; \
                echo "Watching...";\
            else \
                echo "You chose not to install air. Exiting..."; \
                exit 1; \
            fi; \
        fi

# Database migrations with goose (local)
migrate-up:
	@echo "Loading .env..."
	@if [ -f .env ]; then export $$(cat .env | grep -v '^#' | xargs); fi; \
	if command -v goose > /dev/null; then \
		goose -dir ./migrations postgres "user=$$DB_USERNAME password=$$DB_PASSWORD dbname=$$DB_DATABASE sslmode=$$DB_SSL_MODE host=$$DB_HOST port=$$DB_PORT" up; \
	else \
		echo "Goose is not installed. Installing..."; \
		go install github.com/pressly/goose/v3/cmd/goose@latest; \
		goose -dir ./migrations postgres "user=$$DB_USERNAME password=$$DB_PASSWORD dbname=$$DB_DATABASE sslmode=$$DB_SSL_MODE host=$$DB_HOST port=$$DB_PORT" up; \
	fi

migrate-down:
	@echo "Loading .env..."
	@if [ -f .env ]; then export $$(cat .env | grep -v '^#' | xargs); fi; \
	if command -v goose > /dev/null; then \
		goose -dir ./migrations postgres "user=$$DB_USERNAME password=$$DB_PASSWORD dbname=$$DB_DATABASE sslmode=$$DB_SSL_MODE host=$$DB_HOST port=$$DB_PORT" down; \
	else \
		echo "Goose is not installed. Installing..."; \
		go install github.com/pressly/goose/v3/cmd/goose@latest; \
		goose -dir ./migrations postgres "user=$$DB_USERNAME password=$$DB_PASSWORD dbname=$$DB_DATABASE sslmode=$$DB_SSL_MODE host=$$DB_HOST port=$$DB_PORT" down; \
	fi

create-migration:
	@if [ -z "$(NAME)" ]; then \
		echo "Usage: make create-migration NAME=migration_name"; \
		exit 1; \
	fi; \
	if command -v goose > /dev/null; then \
		goose -dir ./migrations create $(NAME) sql; \
	else \
		echo "Goose is not installed. Installing..."; \
		go install github.com/pressly/goose/v3/cmd/goose@latest; \
		goose -dir ./migrations create $(NAME) sql; \
	fi

.PHONY: all build run test clean watch docker-run docker-down itest migrate-up migrate-down create-migration
