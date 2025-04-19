# JWT Authentication with Redis

This project is a Go-based application that implements JWT authentication with access and refresh tokens, using Redis for token management. The application is containerized using Docker and Docker Compose for easy deployment.

## Features

- **JWT Authentication**: Secure access and refresh token implementation.
- **Redis Integration**: Token storage and management using Redis.
- **Protected Endpoints**: Access to protected routes with valid tokens.
- **Dockerized**: Multi-stage Docker build for lightweight production images.
- **Environment Configuration**: Configurable via `.env` file.
- **Scalable Architecture**: Easily extendable and deployable.

---

## Project Structure

```
.
├── cmd/
│   └── server/
│       └── main.go          # Application entry point
├── handlers/
│   └── protected_handlers.go # Protected route handlers
├── auth/
│   └── middleware.go        # JWT authentication middleware
├── .env                     # Environment variables
├── Dockerfile               # Multi-stage Docker build
├── docker-compose.yml       # Docker Compose configuration
├── go.mod                   # Go module dependencies
└── README.md                # Project documentation
```

---

## Prerequisites

- **Go**: Version 1.22 or later
- **Docker**: Version 20.10 or later
- **Docker Compose**: Version 1.29 or later

---

## Setup Instructions

### 1. Clone the Repository

```bash
git clone https://github.com/your-username/your-repo.git
cd your-repo
```

### 2. Configure Environment Variables

Edit the `.env` file to configure the application. Example:

```dotenv
# Application Port
PORT=8080

# JWT Secrets
ACCESS_SECRET="your_access_secret"
REFRESH_SECRET="your_refresh_secret"

# Token Lifespans (in minutes)
ACCESS_TOKEN_LIFESPAN=15
REFRESH_TOKEN_LIFESPAN=10080

# Redis Config
REDIS_ADDR="redis:6379"
REDIS_PASSWORD=""
REDIS_DB=0
```

### 3. Build and Run with Docker Compose

```bash
docker-compose up --build
```

This will start the application and Redis in separate containers.

---

## API Endpoints

### Protected Endpoint

- **URL**: `/protected/data`
- **Method**: `GET`
- **Headers**:
    - `Authorization: Bearer <access_token>`
- **Response**:
    - **200 OK**: Returns protected data.
    - **401 Unauthorized**: Invalid or missing token.

---

## Development

### Run Locally

1. Install dependencies:

   ```bash
   go mod download
   ```

2. Run the application:

   ```bash
   go run cmd/server/main.go
   ```

### Build the Application

```bash
go build -o server ./cmd/server/main.go
```

---

## Docker Details

### Multi-Stage Build

The `Dockerfile` uses a multi-stage build to create a lightweight production image:

1. **Builder Stage**: Compiles the Go application.
2. **Final Stage**: Runs the application as a non-root user in an Alpine-based image.

### Docker Compose

- **App Service**: Runs the Go application.
- **Redis Service**: Runs Redis for token storage.

---

## Environment Variables

| Variable                 | Description                          | Default Value |
|--------------------------|--------------------------------------|---------------|
| `PORT`                   | Application port                     | `8080`        |
| `ACCESS_SECRET`          | JWT access token secret              | None          |
| `REFRESH_SECRET`         | JWT refresh token secret             | None          |
| `ACCESS_TOKEN_LIFESPAN`  | Access token lifespan (in minutes)   | `15`          |
| `REFRESH_TOKEN_LIFESPAN` | Refresh token lifespan (in minutes)  | `10080`       |
| `REDIS_ADDR`             | Redis address                        | `redis:6379`  |
| `REDIS_PASSWORD`         | Redis password                       | None          |
| `REDIS_DB`               | Redis database index                 | `0`           |

---

## Logging

The application uses `slog` for structured logging. Logs include:

- **Info**: Successful operations.
- **Error**: Issues like missing or invalid tokens.

---

## Security

- **Secrets**: Use strong, random strings for `ACCESS_SECRET` and `REFRESH_SECRET`.
- **Redis Password**: Set a password for Redis in production.
- **Non-Root User**: The application runs as a non-root user in the Docker container.

---

