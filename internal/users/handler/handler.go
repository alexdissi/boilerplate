package handler

import (
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
