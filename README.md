# vid - URL Shortener

Modern URL shortener with user management, Redis caching, and admin panel. Built with Go.

## Features

- URL shortening with custom short codes
- User authentication and personal dashboards
- Admin panel with user and link management
- Redis caching for fast performance
- Click tracking and statistics
- Catppuccin Mocha theme
- Serbian language UI (You can manually translate by changing `.html` files)

## Quick Start

### With Docker Compose (Recommended)

1. **Start everything:**

   ```bash
   docker compose up -d
   ```

   ```bash
   sudo docker compose ud -d
   ```

2. **Access:**
   - App: http://localhost:13888
   - Login: `admin@vid.crnbg.org` / `changeme`

3. **Stop:**
   ```bash
   docker-compose down
   ```

### Local Development

1. **Start Redis:**
   ```bash
   docker run -d -p 6379:6379 redis:7-alpine
   ```

2. **Build and run:**
   ```bash
   go build -o vid main.go
   ./vid
   ```

3. **Access:** http://localhost:13888

## Configuration

Copy `.env.example` and customize:

```bash
PORT=13888
DOMAIN=vid.crnbg.org

# Redis (optional)
USE_REDIS=true
REDIS_ADDR=localhost:6379

# Admin user
ADMIN_EMAIL=admin@vid.crnbg.org
ADMIN_PASSWORD=changeme

# Access control
USER_SIGNUP=true              # Allow new user registration
REQUIRE_LOGIN=false           # Require login to use shortener
ALLOW_ANONYMOUS_CUSTOM_LINKS=true  # Allow custom links without login
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `13888` | Server port |
| `DOMAIN` | `vid.crnbg.org` | Your domain |
| `USE_REDIS` | `true` | Enable Redis caching |
| `REDIS_ADDR` | `localhost:6379` | Redis address |
| `REDIS_PASSWORD` | `` | Redis password |
| `ADMIN_EMAIL` | `admin@vid.crnbg.org` | Admin email |
| `ADMIN_PASSWORD` | `changeme` | Admin password |
| `USER_SIGNUP` | `true` | Allow user registration |
| `REQUIRE_LOGIN` | `false` | Require login for shortening |
| `ALLOW_ANONYMOUS_CUSTOM_LINKS` | `true` | Allow custom links for anonymous |
| `SESSION_SECRET` | (required) | Session encryption key |

## Generate Secure Passwords

```bash
# Session secret
openssl rand -hex 32

# Redis password  
openssl rand -base64 32

# Database password
openssl rand -hex 32
```

## Tech Stack

- **Backend:** Go 1.19+
- **Database:** SQLite
- **Cache:** Redis 7
- **Sessions:** gorilla/sessions
- **Theme:** Catppuccin Mocha

## Admin Panel

Access at `/admin` with credentials:
- Default: `admin@vid.crnbg.org` / `changeme`

Features:
- View all links and users
- Delete links and users
- Change user passwords
- Create new users
- Platform statistics

---

[**Built for vid.crnbg.org**](https://vid.crnbg.org)
