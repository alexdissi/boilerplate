package handler

import (
	"my_project/internal/middleware"
	"my_project/internal/users/usecase"
	"net/http"

	"github.com/labstack/echo/v4"
)

type UserHandler struct {
	usecase usecase.UserUsecase
}

func NewUserHandler(u usecase.UserUsecase) *UserHandler {
	return &UserHandler{
		usecase: u,
	}
}

func (h *UserHandler) Bind(e *echo.Group) {
	e.GET("/me", h.GetUserProfile, middleware.CookieSessionMiddleware())
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
