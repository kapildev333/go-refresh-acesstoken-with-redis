package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go-refresh-acesstoken-with-redis/auth"
	"go-refresh-acesstoken-with-redis/config"
	"go-refresh-acesstoken-with-redis/handlers"
	"go-refresh-acesstoken-with-redis/storage"

	"github.com/gin-gonic/gin"
)

// @title           JWT Auth API with Redis
// @version         1.0
// @description     This is a sample server for JWT authentication with Access and Refresh Tokens using Redis.
// @termsOfService  http://swagger.io/terms/

// @contact.name   API Support
// @contact.url    http://www.swagger.io/support
// @contact.email  support@swagger.io

// @license.name  Apache 2.0
// @license.url   http://www.apache.org/licenses/LICENSE-2.0.html

// @host      localhost:8080
// @BasePath  /api/v1

// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description Type "Bearer" followed by a space and JWT token.

func main() {
	// Setup structured logging
	logLevel := slog.LevelDebug // Make this configurable (e.g., via env var)
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel}))
	slog.SetDefault(logger) // Set as default logger

	// Load configuration
	config.LoadConfig()
	cfg := config.Env
	logger.Info("Configuration loaded", "port", cfg.Port, "redis_addr", cfg.RedisAddr)

	// Initialize Redis Store
	redisStore, err := storage.NewRedisStore(cfg, logger.With("component", "redis"))
	if err != nil {
		logger.Error("Failed to initialize Redis store", "error", err)
		os.Exit(1)
	}
	defer func() {
		if err := redisStore.Close(); err != nil {
			logger.Error("Error closing Redis connection", "error", err)
		}
	}()
	logger.Info("Redis store initialized")

	// Initialize Services
	tokenService := auth.NewTokenService(cfg, redisStore, logger.With("component", "token_service"))
	logger.Info("Token service initialized")

	// Initialize Handlers
	authHandler := handlers.NewAuthHandler(tokenService, redisStore, logger.With("component", "auth_handler"))
	protectedHandler := handlers.NewProtectedHandler(logger.With("component", "protected_handler"))
	logger.Info("Handlers initialized")

	// Setup Gin Router
	// gin.SetMode(gin.ReleaseMode) // Set to ReleaseMode in production
	router := gin.New()

	// Middleware
	router.Use(gin.Recovery()) // Recover from panics
	// Custom structured logging middleware
	router.Use(LoggingMiddleware(logger))

	// Setup routes
	api := router.Group("/api/v1")
	{
		// Auth routes
		authRoutes := api.Group("/auth")
		{
			// No authentication needed for login/refresh
			authRoutes.POST("/login", authHandler.Login)
			authRoutes.POST("/refresh", authHandler.Refresh)
			// Logout might require the refresh token itself or extract info from access token
			// If extracting from access token, it needs auth middleware first
			// For this example, logout takes refresh token in body, so no middleware here.
			authRoutes.POST("/logout", authHandler.Logout)
		}

		// Protected routes (require valid access token)
		protected := api.Group("/protected")
		protected.Use(auth.AuthMiddleware(tokenService, logger.With("component", "auth_middleware"))) // Apply auth middleware
		{
			protected.GET("/data", protectedHandler.GetData)
			// Add other protected routes here
		}
	}

	// Default route for health check or basic info
	router.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok", "service": "auth-api"})
	})

	// Setup HTTP Server
	server := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      router,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in a goroutine
	go func() {
		logger.Info("Starting server", "address", server.Addr)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("Server failed to start", "error", err)
			os.Exit(1)
		}
	}()

	// Graceful Shutdown Handling
	quit := make(chan os.Signal, 1)
	// syscall.SIGINT: Ctrl+C
	// syscall.SIGTERM: Sent by Docker/Kubernetes on stop
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit // Block until a signal is received

	logger.Info("Shutting down server...")

	// Create a context with timeout for shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second) // 10-second shutdown timeout
	defer cancel()

	// Attempt graceful shutdown
	if err := server.Shutdown(ctx); err != nil {
		logger.Error("Server forced to shutdown", "error", err)
		os.Exit(1) // Exit with error if shutdown fails
	}

	logger.Info("Server exiting gracefully")
	os.Exit(0) // Exit cleanly
}

// LoggingMiddleware provides structured logging for each request
func LoggingMiddleware(logger *slog.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		raw := c.Request.URL.RawQuery

		// Process request
		c.Next()

		// Log details after request is handled
		latency := time.Since(start)
		statusCode := c.Writer.Status()
		clientIP := c.ClientIP()
		method := c.Request.Method

		logAttrs := []slog.Attr{
			slog.Int("status", statusCode),
			slog.String("method", method),
			slog.String("path", path),
			slog.String("ip", clientIP),
			slog.Duration("latency", latency),
		}

		if raw != "" {
			logAttrs = append(logAttrs, slog.String("query", raw))
		}

		// Log errors specifically if any occurred within Gin handlers
		if len(c.Errors) > 0 {
			for _, e := range c.Errors.Errors() {
				logger.Error("Request Error", append(logAttrs, slog.String("error", e)))
			}
		} else {
			logger.LogAttrs(context.Background(), slog.LevelInfo, "Request Handled", logAttrs...)
		}

	}
}
