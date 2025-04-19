package handlers

import (
	"context"
	"errors"
	"go-refresh-acesstoken-with-redis/auth"    // Use your actual module name
	"go-refresh-acesstoken-with-redis/storage" // Use your actual module name
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

type AuthHandler struct {
	tokenService *auth.TokenService
	redisStore   *storage.RedisStore
	logger       *slog.Logger
}

func NewAuthHandler(ts *auth.TokenService, rs *storage.RedisStore, logger *slog.Logger) *AuthHandler {
	return &AuthHandler{
		tokenService: ts,
		redisStore:   rs,
		logger:       logger,
	}
}

// LoginRequest - Structure for login request body
type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// Login godoc
// @Summary User login
// @Description Authenticates a user and returns access and refresh tokens.
// @Tags auth
// @Accept json
// @Produce json
// @Param login body LoginRequest true "Login Credentials"
// @Success 200 {object} auth.TokenDetails "Successfully authenticated"
// @Failure 400 {object} gin.H "Invalid input"
// @Failure 401 {object} gin.H "Authentication failed"
// @Failure 500 {object} gin.H "Internal server error"
// @Router /login [post]
func (h *AuthHandler) Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Warn("Login failed: Invalid request body", "error", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body: " + err.Error()})
		return
	}

	// --- !!! Placeholder: Implement actual user authentication logic here !!! ---
	// 1. Fetch user from your database based on req.Username
	// 2. Compare the provided req.Password with the stored hashed password (use bcrypt)
	// Example check (replace with real logic):
	if req.Username != "testuser" || req.Password != "password123" {
		h.logger.Warn("Login failed: Invalid credentials", "username", req.Username)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password"})
		return
	}
	userID := "user-123" // Replace with the actual user ID from your database
	// --- End Placeholder ---

	h.logger.Info("Authentication successful", "username", req.Username, "userID", userID)

	// Generate tokens
	td, err := h.tokenService.GenerateTokens(userID)
	if err != nil {
		h.logger.Error("Login failed: Could not generate tokens", "userID", userID, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate tokens"})
		return
	}

	// Store refresh token metadata in Redis
	ctx := context.Background() // Use request context if available and makes sense
	err = h.redisStore.StoreRefreshToken(ctx, userID, td.RefreshUUID, h.tokenService.Cfg.RefreshTokenLifespan)
	if err != nil {
		h.logger.Error("Login failed: Could not store refresh token", "refreshUUID", td.RefreshUUID, "userID", userID, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store refresh token"})
		return
	}

	h.logger.Info("Login successful, tokens generated", "userID", userID, "accessUUID", td.AccessUUID, "refreshUUID", td.RefreshUUID)
	c.JSON(http.StatusOK, gin.H{
		"access_token":  td.AccessToken,
		"refresh_token": td.RefreshToken,
		// Optionally return expiry times if needed by the client
		// "access_token_expires_at": td.AccessTokenExpires.Unix(),
		// "refresh_token_expires_at": td.RefreshTokenExpires.Unix(),
	})
}

// RefreshTokenRequest - Structure for refresh token request body
type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

// Refresh godoc
// @Summary Refresh access token
// @Description Provides a new access token using a valid refresh token.
// @Tags auth
// @Accept json
// @Produce json
// @Param refresh body RefreshTokenRequest true "Refresh Token"
// @Success 200 {object} map[string]string "New access token"
// @Failure 400 {object} gin.H "Invalid input"
// @Failure 401 {object} gin.H "Invalid or expired refresh token"
// @Failure 500 {object} gin.H "Internal server error"
// @Router /refresh [post]
func (h *AuthHandler) Refresh(c *gin.Context) {
	var req RefreshTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Warn("Token refresh failed: Invalid request body", "error", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body: " + err.Error()})
		return
	}

	// 1. Validate the refresh token structure and signature
	token, err := h.tokenService.ValidateToken(req.RefreshToken, h.tokenService.Cfg.RefreshTokenSecret)
	if err != nil {
		h.logger.Warn("Token refresh failed: Invalid refresh token", "error", err)
		// Distinguish expired from other invalid errors if needed
		if errors.Is(err, jwt.ErrTokenExpired) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "refresh token has expired"})
		} else {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid refresh token"})
		}
		return
	}

	// 2. Extract claims (ensure it has RefreshUUID and UserID)
	refreshClaims, err := auth.ExtractRefreshClaims(token)
	if err != nil {
		h.logger.Warn("Token refresh failed: Could not extract refresh claims", "error", err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid refresh token claims"})
		return
	}

	// 3. Validate against Redis store
	ctx := context.Background() // Use request context
	storedUserID, err := h.redisStore.ValidateRefreshToken(ctx, refreshClaims.RefreshUUID)
	if err != nil {
		// Error already logged in ValidateRefreshToken
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired refresh token"})
		return
	}

	// Optional: Check if the UserID from the token matches the one stored in Redis
	if storedUserID != refreshClaims.UserID {
		h.logger.Error("Token refresh failed: UserID mismatch", "tokenUserID", refreshClaims.UserID, "redisUserID", storedUserID, "refreshUUID", refreshClaims.RefreshUUID)
		// Security measure: If mismatch, invalidate the token in Redis immediately
		_ = h.redisStore.DeleteRefreshToken(ctx, refreshClaims.RefreshUUID)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid refresh token (user mismatch)"})
		return
	}

	// --- Refresh Token Rotation (Optional but Recommended) ---
	// For better security, invalidate the old refresh token and issue a new one along with the new access token.
	// If you don't rotate, skip the deletion and generation of a new refresh token.

	// 4. Delete the old refresh token from Redis
	err = h.redisStore.DeleteRefreshToken(ctx, refreshClaims.RefreshUUID)
	if err != nil {
		// Log the error but might proceed if deletion failed, though it's not ideal
		h.logger.Error("Token refresh: Failed to delete old refresh token, proceeding...", "refreshUUID", refreshClaims.RefreshUUID, "error", err)
		// Depending on policy, you might want to return an error here instead.
	}
	// --- End Rotation Step ---

	// 5. Generate *new* tokens (both access and potentially refresh if rotating)
	newTd, err := h.tokenService.GenerateTokens(refreshClaims.UserID) // Generate for the validated user
	if err != nil {
		h.logger.Error("Token refresh failed: Could not generate new tokens", "userID", refreshClaims.UserID, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate new tokens"})
		return
	}

	// 6. Store the *new* refresh token details in Redis (only if rotating refresh tokens)
	err = h.redisStore.StoreRefreshToken(ctx, refreshClaims.UserID, newTd.RefreshUUID, h.tokenService.Cfg.RefreshTokenLifespan)
	if err != nil {
		// This is critical. If storing the new refresh token fails, the user might be locked out after the new access token expires.
		h.logger.Error("Token refresh critical error: Could not store new refresh token", "newRefreshUUID", newTd.RefreshUUID, "userID", refreshClaims.UserID, "error", err)
		// You might want to try deleting the newly generated access token info or handle this state carefully.
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store new refresh token state"})
		return
	}
	// --- End Rotation Step ---

	h.logger.Info("Token refresh successful", "userID", refreshClaims.UserID, "oldRefreshUUID", refreshClaims.RefreshUUID, "newAccessUUID", newTd.AccessUUID, "newRefreshUUID", newTd.RefreshUUID)

	// 7. Send back the new tokens
	c.JSON(http.StatusOK, gin.H{
		"access_token": newTd.AccessToken,
		// Send the new refresh token ONLY if you are rotating them
		"refresh_token": newTd.RefreshToken,
	})
}

// LogoutRequest - Structure for logout (might need refresh token to invalidate)
type LogoutRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

// Logout godoc
// @Summary User logout
// @Description Invalidates the user's refresh token. Requires refresh token.
// @Tags auth
// @Accept json
// @Produce json
// @Param logout body LogoutRequest true "Refresh Token to invalidate"
// @Success 200 {object} gin.H "Successfully logged out"
// @Failure 400 {object} gin.H "Invalid input"
// @Failure 401 {object} gin.H "Invalid refresh token"
// @Failure 500 {object} gin.H "Internal server error"
// @Router /logout [post]
// Note: An alternative is requiring the Access Token via AuthMiddleware and extracting RefreshUUID if embedded.
// Sending the refresh token explicitly makes the endpoint's purpose clear.
func (h *AuthHandler) Logout(c *gin.Context) {
	var req LogoutRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Warn("Logout failed: Invalid request body", "error", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body: " + err.Error()})
		return
	}

	// 1. Validate the refresh token structure (optional but good practice)
	token, err := h.tokenService.ValidateToken(req.RefreshToken, h.tokenService.Cfg.RefreshTokenSecret)
	// We ignore expiry errors here, as we just need the ID to delete it.
	if err != nil && !errors.Is(err, jwt.ErrTokenExpired) {
		h.logger.Warn("Logout failed: Invalid refresh token format", "error", err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid refresh token format"})
		return
	}

	// 2. Extract the RefreshUUID from the claims
	refreshClaims, err := auth.ExtractRefreshClaims(token)
	if err != nil {
		h.logger.Warn("Logout failed: Could not extract refresh claims from provided token", "error", err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid refresh token claims"})
		return
	}

	// 3. Delete the refresh token from Redis using its UUID
	ctx := context.Background() // Use request context
	err = h.redisStore.DeleteRefreshToken(ctx, refreshClaims.RefreshUUID)
	if err != nil {
		// Log error but still return success as the goal is invalidation attempt
		h.logger.Error("Logout: Failed to delete refresh token from Redis, but proceeding", "refreshUUID", refreshClaims.RefreshUUID, "error", err)
	} else {
		h.logger.Info("Logout successful: Refresh token invalidated", "userID", refreshClaims.UserID, "refreshUUID", refreshClaims.RefreshUUID)
	}

	c.JSON(http.StatusOK, gin.H{"message": "Successfully logged out"})
}
