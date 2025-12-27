package handler

import (
	"errors"
	"my_project/internal/users/domain"
	"my_project/internal/users/usecase"
	"net/http"

	"github.com/go-playground/validator/v10"
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
	e.DELETE("/me", h.DeleteUser)
	e.POST("/change-password", h.ChangePassword)
	e.POST("/2fa/setup", h.SetupTwoFactor)
	e.POST("/2fa/enable", h.EnableTwoFactor)
	e.POST("/2fa/disable", h.DisableTwoFactor)
	e.POST("/avatar", h.UploadAvatar)
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
		switch {
		case errors.Is(err, domain.ErrInvalidCurrentPassword):
			return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Current password is incorrect"})
		case errors.Is(err, domain.ErrPasswordVerificationFailed):
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Password verification failed"})
		case errors.Is(err, domain.ErrPasswordProcessingFailed):
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to process new password"})
		case errors.Is(err, domain.ErrUserUpdateFailed):
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to update password"})
		default:
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}
	}

	return c.JSON(http.StatusOK, map[string]string{"message": "Password changed successfully"})
}

func (h *UserHandler) DeleteUser(c echo.Context) error {
	userID, ok := c.Get("user_id").(string)
	if !ok || userID == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Unauthorized"})
	}

	ctx := c.Request().Context()
	err := h.usecase.DeleteUser(ctx, userID)
	if err != nil {
		switch {
		case errors.Is(err, domain.ErrUserNotFound):
			return c.JSON(http.StatusNotFound, map[string]string{"error": "User not found"})
		case errors.Is(err, domain.ErrInvalidUserID):
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid user ID"})
		default:
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}
	}

	return c.JSON(http.StatusOK, map[string]string{"message": "User deleted successfully"})
}
func (h *UserHandler) UploadAvatar(c echo.Context) error {
	userID, ok := c.Get("user_id").(string)
	if !ok || userID == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Unauthorized"})
	}
	fileHeader, err := c.FormFile("avatar")
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Avatar file is required"})
	}

	const maxFileSize = 3 * 1024 * 1024
	if fileHeader.Size > maxFileSize {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "File size exceeds 3MB limit"})
	}

	ctx := c.Request().Context()
	avatarURL, err := h.usecase.UploadAvatar(ctx, userID, fileHeader)
	if err != nil {
		switch {
		case errors.Is(err, domain.ErrInvalidUserID):
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid user ID"})
		case errors.Is(err, domain.ErrInvalidFileFormat):
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid file format. Only JPG, JPEG, PNG, GIF, and WEBP are allowed"})
		case errors.Is(err, domain.ErrUserNotFound):
			return c.JSON(http.StatusNotFound, map[string]string{"error": "User not found"})
		default:
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to upload avatar"})
		}
	}

	return c.JSON(http.StatusOK, map[string]string{
		"message":    "Avatar uploaded successfully",
		"avatar_url": avatarURL,
	})
}

func (h *UserHandler) SetupTwoFactor(c echo.Context) error {
	userID, ok := c.Get("user_id").(string)
	if !ok || userID == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Unauthorized"})
	}

	ctx := c.Request().Context()
	response, err := h.usecase.SetupTwoFactor(ctx, userID)
	if err != nil {
		switch {
		case errors.Is(err, domain.ErrInvalidUserID):
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid user ID"})
		case errors.Is(err, domain.ErrTwoFactorAlreadyEnabled):
			return c.JSON(http.StatusConflict, map[string]string{"error": "Two-factor authentication already enabled"})
		default:
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to setup two-factor authentication"})
		}
	}

	return c.JSON(http.StatusOK, response)
}

func (h *UserHandler) EnableTwoFactor(c echo.Context) error {
	userID, ok := c.Get("user_id").(string)
	if !ok || userID == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Unauthorized"})
	}

	var req usecase.EnableTwoFactorRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request format"})
	}

	if err := h.validator.Struct(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Validation failed"})
	}

	ctx := c.Request().Context()
	response, err := h.usecase.EnableTwoFactor(ctx, userID, req)
	if err != nil {
		switch {
		case errors.Is(err, domain.ErrInvalidUserID):
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid user ID"})
		case errors.Is(err, domain.ErrTwoFactorAlreadyEnabled):
			return c.JSON(http.StatusConflict, map[string]string{"error": "Two-factor authentication already enabled"})
		case errors.Is(err, domain.ErrInvalidTwoFactorCode):
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid two-factor code"})
		default:
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to enable two-factor authentication"})
		}
	}

	return c.JSON(http.StatusOK, response)
}

func (h *UserHandler) DisableTwoFactor(c echo.Context) error {
	userID, ok := c.Get("user_id").(string)
	if !ok || userID == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Unauthorized"})
	}

	var req usecase.DisableTwoFactorRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request format"})
	}

	if err := h.validator.Struct(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Validation failed"})
	}

	ctx := c.Request().Context()
	err := h.usecase.DisableTwoFactor(ctx, userID, req)
	if err != nil {
		switch {
		case errors.Is(err, domain.ErrInvalidUserID):
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid user ID"})
		case errors.Is(err, domain.ErrTwoFactorNotEnabled):
			return c.JSON(http.StatusConflict, map[string]string{"error": "Two-factor authentication not enabled"})
		case errors.Is(err, domain.ErrInvalidTwoFactorCode):
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid two-factor code"})
		default:
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Failed to disable two-factor authentication"})
		}
	}

	return c.JSON(http.StatusOK, map[string]string{"message": "Two-factor authentication disabled successfully"})
}
