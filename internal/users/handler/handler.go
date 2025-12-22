package handler

import (
	"errors"
	"fmt"
	"my_project/internal/users/domain"
	"my_project/internal/users/usecase"
	"net/http"
	"os"
	"strings"

	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
)

type UserHandler struct {
	usecase   usecase.UserUsecase
	validator *validator.Validate
}

func NewUserHandler(u usecase.UserUsecase, v *validator.Validate) *UserHandler {
	return &UserHandler{
		usecase:   u,
		validator: v,
	}
}

func (h *UserHandler) Bind(e *echo.Group) {
	e.GET("/me", h.GetUserProfile)
	e.PATCH("/me", h.UpdateUserProfile)
	e.POST("/change-password", h.ChangePassword)
	e.POST("/profile-picture", h.UploadProfilePicture)
}

func (h *UserHandler) GetUserProfile(c echo.Context) error {
	userID, ok := c.Get("user_id").(string)
	if !ok || userID == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Unauthorized"})
	}
	ctx := c.Request().Context()
	output, err := h.usecase.GetUserProfile(ctx, userID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	return c.JSON(http.StatusOK, output)
}

func (h *UserHandler) UpdateUserProfile(c echo.Context) error {
	userID, ok := c.Get("user_id").(string)
	if !ok || userID == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Unauthorized"})
	}

	var req usecase.UpdateUserRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request format"})
	}

	if err := h.validator.Struct(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Validation failed: " + err.Error()})
	}

	if req.Email == nil && req.FirstName == nil && req.LastName == nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "At least one field must be provided"})
	}

	ctx := c.Request().Context()
	output, err := h.usecase.UpdateUserProfile(ctx, userID, req)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	return c.JSON(http.StatusOK, output)
}

func (h *UserHandler) ChangePassword(c echo.Context) error {
	userID, ok := c.Get("user_id").(string)
	if !ok || userID == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Unauthorized"})
	}

	var req usecase.ChangePasswordRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request format"})
	}

	if err := h.validator.Struct(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Validation failed: " + err.Error()})
	}

	if req.CurrentPassword == req.NewPassword {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "New password must be different from current password"})
	}

	ctx := c.Request().Context()
	err := h.usecase.ChangePassword(ctx, userID, req)
	if err != nil {
		if errors.Is(err, domain.ErrInvalidCurrentPassword) {
			return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Current password is incorrect"})
		}
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	return c.JSON(http.StatusOK, map[string]string{"message": "Password changed successfully"})
}

func (h *UserHandler) UploadProfilePicture(c echo.Context) error {
	userID, ok := c.Get("user_id").(string)
	if !ok || userID == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Unauthorized"})
	}

	file, header, err := c.Request().FormFile("profile_picture")
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "No file uploaded"})
	}
	defer file.Close()

	// Validate file size (max 2MB)
	if header.Size > 2*1024*1024 {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "File too large (max 2MB)"})
	}

	// Generate unique filename and URL
	ext := ""
	if lastDot := strings.LastIndex(header.Filename, "."); lastDot > 0 {
		ext = header.Filename[lastDot:]
	}
	fileName := uuid.New().String() + ext
	publicURL := fmt.Sprintf("https://user-profiles.%s.r2.cloudflarestorage.com/profile-pictures/%s/%s",
		os.Getenv("R2_ACCOUNT_ID"), userID, fileName)

	// Update user profile picture in database
	ctx := c.Request().Context()
	_, err = h.usecase.UpdateUserProfile(ctx, userID, usecase.UpdateUserRequest{
		Email:          nil,
		FirstName:      nil,
		LastName:       nil,
		ProfilePicture: &publicURL,
	})
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to update profile"})
	}

	return c.JSON(http.StatusOK, map[string]any{
		"message": "Profile picture uploaded successfully",
		"url":     publicURL,
	})
}
