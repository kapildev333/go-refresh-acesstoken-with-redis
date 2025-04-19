# Stage 1: Build the Go application
FROM golang:1.22-alpine AS builder

# Set working directory
WORKDIR /app

# Copy Go module files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy the rest of the source code
COPY . .

# Build the application statically linked
# CGO_ENABLED=0 prevents usage of C libraries (like netgo for DNS lookups)
# -ldflags="-w -s" strips debug info and symbols, reducing binary size
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /server ./cmd/server/main.go


# Stage 2: Create the final lightweight image
FROM alpine:latest

# Security context: Run as a non-root user
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
USER appuser

WORKDIR /home/appuser

# Copy the built binary from the builder stage
COPY --from=builder /server /home/appuser/server

# Expose the port the application runs on (read from ENV later if needed)
# This is documentation; the actual port binding happens in docker-compose or run command
EXPOSE 8080

# Command to run the application
# The actual PORT env var will be set by docker-compose
CMD ["./server"]