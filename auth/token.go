package auth

import (
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"go-refresh-acesstoken-with-redis/config"
	"go-refresh-acesstoken-with-redis/storage"
	"log/slog"
	"time"
)

// TokenDetails holds the metadata about the generated tokens
type TokenDetails struct {
	AccessToken         string
	RefreshToken        string
	AccessUUID          string
	RefreshUUID         string
	AccessTokenExpires  time.Time
	RefreshTokenExpires time.Time
}

// Claims defines the structure of the JWT claims
type Claims struct {
	UserID string `json:"user_id"`
	// We embed jwt.RegisteredClaims to include standard claims like exp, iat, nbf
	jwt.RegisteredClaims
}

// RefreshClaims specifically for refresh tokens, includes its own UUID
type RefreshClaims struct {
	UserID      string `json:"user_id"`
	RefreshUUID string `json:"refresh_uuid"` // Unique identifier for this refresh token instance
	jwt.RegisteredClaims
}

type TokenService struct {
	Cfg        *config.Config
	redisStore *storage.RedisStore
	logger     *slog.Logger
}

func NewTokenService(cfg *config.Config, redisStore *storage.RedisStore, logger *slog.Logger) *TokenService {
	return &TokenService{
		Cfg:        cfg,
		redisStore: redisStore,
		logger:     logger,
	}
}

// GenerateTokens creates new access and refresh tokens for a given user ID
func (ts *TokenService) GenerateTokens(userID string) (*TokenDetails, error) {
	td := &TokenDetails{}
	var err error

	// ---- Access Token ----
	td.AccessUUID = uuid.NewString() // Generate a unique ID for the access token
	td.AccessTokenExpires = time.Now().Add(ts.Cfg.AccessTokenLifespan)

	accessClaims := Claims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(td.AccessTokenExpires),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "your-app-name", // Replace with your app name/identifier
			Subject:   userID,
			ID:        td.AccessUUID, // Use AccessUUID as JWT ID (jti)
		},
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	td.AccessToken, err = accessToken.SignedString([]byte(ts.Cfg.AccessTokenSecret))
	if err != nil {
		ts.logger.Error("Failed to sign access token", "userID", userID, "error", err)
		return nil, fmt.Errorf("failed to sign access token: %w", err)
	}

	// ---- Refresh Token ----
	td.RefreshUUID = uuid.NewString() // Generate a unique ID for the refresh token
	td.RefreshTokenExpires = time.Now().Add(ts.Cfg.RefreshTokenLifespan)

	refreshClaims := RefreshClaims{
		UserID:      userID,
		RefreshUUID: td.RefreshUUID, // Include the refresh token's unique ID in its claims
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(td.RefreshTokenExpires),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "your-app-name", // Replace with your app name/identifier
			Subject:   userID,
			ID:        td.RefreshUUID, // Use RefreshUUID as JWT ID (jti)
		},
	}

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	td.RefreshToken, err = refreshToken.SignedString([]byte(ts.Cfg.RefreshTokenSecret))
	if err != nil {
		ts.logger.Error("Failed to sign refresh token", "userID", userID, "error", err)
		return nil, fmt.Errorf("failed to sign refresh token: %w", err)
	}

	ts.logger.Info("Generated new tokens", "userID", userID, "accessUUID", td.AccessUUID, "refreshUUID", td.RefreshUUID)
	return td, nil
}

// ValidateToken parses and validates a JWT token string
func (ts *TokenService) ValidateToken(tokenString string, secret string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secret), nil
	})

	if err != nil {
		ts.logger.Warn("Token validation failed", "error", err)
		return nil, err // Returns specific errors like TokenExpiredError etc.
	}

	if !token.Valid {
		ts.logger.Warn("Token provided is invalid")
		return nil, fmt.Errorf("invalid token")
	}

	return token, nil
}

// ExtractUserIDFromToken extracts the user ID from a validated JWT token's claims
func ExtractUserIDFromToken(token *jwt.Token) (string, error) {
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", fmt.Errorf("invalid token claims type")
	}

	userID, ok := claims["user_id"].(string)
	if !ok {
		return "", fmt.Errorf("user_id claim not found or not a string")
	}
	return userID, nil
}

// ExtractRefreshClaims extracts custom RefreshClaims from a validated refresh token
func ExtractRefreshClaims(token *jwt.Token) (*RefreshClaims, error) {
	claims, ok := token.Claims.(*RefreshClaims) // Try direct assertion first for efficiency
	if ok && token.Valid {
		return claims, nil
	}

	// Fallback if direct assertion fails (maybe parsed as MapClaims initially)
	mapClaims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid refresh token claims")
	}

	userID, userIDOk := mapClaims["user_id"].(string)
	refreshUUID, refreshUUIDOk := mapClaims["refresh_uuid"].(string)
	if !userIDOk || !refreshUUIDOk {
		return nil, fmt.Errorf("missing required claims in refresh token")
	}

	// Reconstruct RegisteredClaims if needed, although we primarily need UserID and RefreshUUID
	// For simplicity, we only populate the required fields here.
	// You might need to parse ExpiresAt, etc., if your logic depends on them directly from claims
	// after validation, but usually ValidateToken handles expiry checks.
	extractedClaims := &RefreshClaims{
		UserID:      userID,
		RefreshUUID: refreshUUID,
		// RegisteredClaims: ..., // Populate if needed
	}
	return extractedClaims, nil
}
