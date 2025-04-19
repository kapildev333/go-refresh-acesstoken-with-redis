package config

import (
	"log"
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	Port                 string
	AccessTokenSecret    string
	RefreshTokenSecret   string
	AccessTokenLifespan  time.Duration
	RefreshTokenLifespan time.Duration
	RedisAddr            string
	RedisPassword        string
	RedisDB              int
}

var Env *Config

func LoadConfig() {
	// Attempt to load .env file, primarily for local development.
	// In production/Docker, rely on environment variables set directly.
	err := godotenv.Load()
	if err != nil {
		log.Println("No .env file found, reading from environment variables")
	}

	accessLifespan, err := strconv.Atoi(getEnv("ACCESS_TOKEN_LIFESPAN", "15"))
	if err != nil {
		log.Fatalf("Error parsing ACCESS_TOKEN_LIFESPAN: %v", err)
	}

	refreshLifespan, err := strconv.Atoi(getEnv("REFRESH_TOKEN_LIFESPAN", "10080")) // 7 days
	if err != nil {
		log.Fatalf("Error parsing REFRESH_TOKEN_LIFESPAN: %v", err)
	}

	redisDB, err := strconv.Atoi(getEnv("REDIS_DB", "0"))
	if err != nil {
		log.Fatalf("Error parsing REDIS_DB: %v", err)
	}

	Env = &Config{
		Port:                 getEnv("PORT", "8080"),
		AccessTokenSecret:    getEnv("ACCESS_SECRET", ""),  // No default for secrets!
		RefreshTokenSecret:   getEnv("REFRESH_SECRET", ""), // No default for secrets!
		AccessTokenLifespan:  time.Duration(accessLifespan) * time.Minute,
		RefreshTokenLifespan: time.Duration(refreshLifespan) * time.Minute,
		RedisAddr:            getEnv("REDIS_ADDR", "localhost:6379"),
		RedisPassword:        getEnv("REDIS_PASSWORD", ""),
		RedisDB:              redisDB,
	}

	// Basic validation
	if Env.AccessTokenSecret == "" || Env.RefreshTokenSecret == "" {
		log.Fatal("FATAL: JWT Secrets (ACCESS_SECRET, REFRESH_SECRET) must be set in environment variables.")
	}
}

func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}
