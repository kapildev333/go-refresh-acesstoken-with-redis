package auth

import (
	"errors"
	"fmt"
	_ "go-refresh-acesstoken-with-redis/config"
	"log/slog"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

const (
	AuthorizationHeaderKey  = "Authorization"
	AuthorizationTypeBearer = "Bearer"
	AuthorizationPayloadKey = "authorization_payload" // Key for storing claims in context
	UserIDKey               = "user_id"               // Key for storing userID in context
)

// AuthMiddleware creates a Gin middleware for JWT authentication
func AuthMiddleware(tokenService *TokenService, logger *slog.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader(AuthorizationHeaderKey)
		if len(authHeader) == 0 {
			err := errors.New("authorization header is not provided")
			logger.Warn("Auth middleware failed", "path", c.Request.URL.Path, "error", err)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			return
		}

		fields := strings.Fields(authHeader)
		if len(fields) < 2 {
			err := errors.New("invalid authorization header format")
			logger.Warn("Auth middleware failed", "path", c.Request.URL.Path, "error", err)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			return
		}

		authType := strings.ToLower(fields[0])
		if authType != strings.ToLower(AuthorizationTypeBearer) {
			err := fmt.Errorf("unsupported authorization type %s", authType)
			logger.Warn("Auth middleware failed", "path", c.Request.URL.Path, "type", authType, "error", err)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			return
		}

		accessToken := fields[1]
		token, err := tokenService.ValidateToken(accessToken, tokenService.Cfg.AccessTokenSecret)
		if err != nil {
			logger.Warn("Auth middleware failed: Invalid token", "path", c.Request.URL.Path, "error", err)
			// Check for specific JWT errors like expiry
			if errors.Is(err, jwt.ErrTokenExpired) {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "token has expired"})
			} else {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			}
			return
		}

		// Extract claims (we stored Claims struct during creation)
		claims, ok := token.Claims.(*Claims)
		if !ok || !token.Valid {
			logger.Error("Auth middleware failed: Invalid token claims", "path", c.Request.URL.Path)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token claims"})
			return
		}

		// Set user information in the context for downstream handlers
		c.Set(AuthorizationPayloadKey, claims) // Store full claims if needed
		c.Set(UserIDKey, claims.UserID)        // Store UserID directly for convenience

		logger.Debug("Auth middleware success", "path", c.Request.URL.Path, "userID", claims.UserID)
		c.Next() // Proceed to the next handler
	}
}
