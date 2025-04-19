package handlers

import (
	"go-refresh-acesstoken-with-redis/auth" // Use your actual module name
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
)

type ProtectedHandler struct {
	logger *slog.Logger
}

func NewProtectedHandler(logger *slog.Logger) *ProtectedHandler {
	return &ProtectedHandler{logger: logger}
}

// GetData godoc
// @Summary Get protected data
// @Description Accesses a protected endpoint requiring a valid access token.
// @Tags protected
// @Security BearerAuth
// @Produce json
// @Success 200 {object} gin.H "Protected data for the user"
// @Failure 401 {object} gin.H "Unauthorized"
// @Router /protected/data [get]
func (h *ProtectedHandler) GetData(c *gin.Context) {
	// UserID was set in the context by the AuthMiddleware
	userID, exists := c.Get(auth.UserIDKey)
	if !exists {
		// This shouldn't happen if middleware is applied correctly
		h.logger.Error("Protected route accessed without UserID in context", "path", c.Request.URL.Path)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not identify user"})
		return
	}

	userIDStr, ok := userID.(string)
	if !ok {
		h.logger.Error("Protected route: UserID in context is not a string", "path", c.Request.URL.Path, "type", "%T", userID)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid user identifier format"})
		return
	}

	h.logger.Info("Accessed protected data", "userID", userIDStr)

	// Example: Return data specific to the user
	c.JSON(http.StatusOK, gin.H{
		"message": "This is protected data",
		"user_id": userIDStr,
		"data":    "some_secret_information_for_" + userIDStr,
	})
}
