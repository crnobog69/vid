# Build stage
FROM golang:1.21-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git gcc musl-dev

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY *.go ./
COPY *.html ./

# Build the application with optimizations
RUN CGO_ENABLED=1 GOOS=linux go build -a -ldflags="-s -w" -installsuffix cgo -o vid main.go

# Final stage
FROM alpine:latest

# Install runtime dependencies
RUN apk --no-cache add ca-certificates tzdata sqlite

WORKDIR /app

# Copy the binary from builder
COPY --from=builder /app/vid .

# Create data directory for database
RUN mkdir -p /app/data

# Expose port
EXPOSE 13888

# Set default environment variables
ENV PORT=13888
ENV DOMAIN=vid.crnbg.org
ENV DB_PATH=/app/data/vid.db
ENV USE_REDIS=false
ENV USER_SIGNUP=true

# Run the application
CMD ["./vid"]
