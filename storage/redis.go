package storage

import (
	"context"
	"fmt"
	"go-refresh-acesstoken-with-redis/config" // Use your actual module name
	"log/slog"
	"time"

	"github.com/redis/go-redis/v9"
)

type RedisStore struct {
	Client *redis.Client
	logger *slog.Logger
}

func NewRedisStore(cfg *config.Config, logger *slog.Logger) (*RedisStore, error) {
	rdb := redis.NewClient(&redis.Options{
		Addr:     cfg.RedisAddr,
		Password: cfg.RedisPassword,
		DB:       cfg.RedisDB,
	})

	// Ping Redis to check connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := rdb.Ping(ctx).Result(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	logger.Info("Successfully connected to Redis", "address", cfg.RedisAddr)
	return &RedisStore{Client: rdb, logger: logger}, nil
}

// StoreRefreshToken stores the refresh token details (UUID -> UserID) with expiry
func (rs *RedisStore) StoreRefreshToken(ctx context.Context, userID string, tokenID string, expiresIn time.Duration) error {
	err := rs.Client.Set(ctx, tokenID, userID, expiresIn).Err()
	if err != nil {
		rs.logger.Error("Failed to store refresh token in Redis", "tokenID", tokenID, "userID", userID, "error", err)
		return fmt.Errorf("failed to store refresh token: %w", err)
	}
	rs.logger.Debug("Stored refresh token in Redis", "tokenID", tokenID, "userID", userID, "expiresIn", expiresIn)
	return nil
}

// ValidateRefreshToken checks if the token ID exists in Redis and returns the associated UserID
func (rs *RedisStore) ValidateRefreshToken(ctx context.Context, tokenID string) (string, error) {
	userID, err := rs.Client.Get(ctx, tokenID).Result()
	if err == redis.Nil {
		rs.logger.Warn("Refresh token not found in Redis or expired", "tokenID", tokenID)
		return "", fmt.Errorf("refresh token not found or expired")
	} else if err != nil {
		rs.logger.Error("Failed to validate refresh token in Redis", "tokenID", tokenID, "error", err)
		return "", fmt.Errorf("failed to validate refresh token: %w", err)
	}
	rs.logger.Debug("Validated refresh token in Redis", "tokenID", tokenID, "userID", userID)
	return userID, nil
}

// DeleteRefreshToken deletes a refresh token by its ID
func (rs *RedisStore) DeleteRefreshToken(ctx context.Context, tokenID string) error {
	deletedCount, err := rs.Client.Del(ctx, tokenID).Result()
	if err != nil {
		rs.logger.Error("Failed to delete refresh token from Redis", "tokenID", tokenID, "error", err)
		return fmt.Errorf("failed to delete refresh token: %w", err)
	}
	if deletedCount == 0 {
		rs.logger.Warn("Attempted to delete non-existent refresh token", "tokenID", tokenID)
		// Depending on the use case (logout), this might not be an error
		// return fmt.Errorf("refresh token not found for deletion")
	} else {
		rs.logger.Info("Deleted refresh token from Redis", "tokenID", tokenID)
	}
	return nil
}

// Close closes the Redis connection
func (rs *RedisStore) Close() error {
	return rs.Client.Close()
}
