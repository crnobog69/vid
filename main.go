package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/gorilla/sessions"
	_ "github.com/mattn/go-sqlite3"
)

//go:embed vid.html login.html signup.html admin.html user.html
var content embed.FS

var ctx = context.Background()
var store *sessions.CookieStore

type Database struct {
	db    *sql.DB
	redis *redis.Client
}

type Config struct {
	Port                      string
	Domain                    string
	DBPath                    string
	RedisAddr                 string
	RedisPassword             string
	RedisDB                   int
	AdminEmail                string
	AdminPassword             string
	UserSignup                bool
	UseRedis                  bool
	SessionSecret             string
	RequireLogin              bool
	AllowAnonymousCustomLinks bool
}

func loadConfig() *Config {
	config := &Config{
		Port:                      getEnv("PORT", "13888"),
		Domain:                    getEnv("DOMAIN", "vid.crnbg.org"),
		DBPath:                    getEnv("DB_PATH", "./vid.db"),
		RedisAddr:                 getEnv("REDIS_ADDR", "localhost:6379"),
		RedisPassword:             getEnv("REDIS_PASSWORD", ""),
		RedisDB:                   getEnvInt("REDIS_DB", 0),
		AdminEmail:                getEnv("ADMIN_EMAIL", "admin@vid.crnbg.org"),
		AdminPassword:             getEnv("ADMIN_PASSWORD", "changeme"),
		UserSignup:                getEnvBool("USER_SIGNUP", true),
		UseRedis:                  getEnvBool("USE_REDIS", true),
		SessionSecret:             getEnv("SESSION_SECRET", "change-this-secret-key-in-production"),
		RequireLogin:              getEnvBool("REQUIRE_LOGIN", false),
		AllowAnonymousCustomLinks: getEnvBool("ALLOW_ANONYMOUS_CUSTOM_LINKS", true),
	}
	return config
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intVal, err := strconv.Atoi(value); err == nil {
			return intVal
		}
	}
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolVal, err := strconv.ParseBool(value); err == nil {
			return boolVal
		}
	}
	return defaultValue
}

func NewDatabase(config *Config) (*Database, error) {
	db, err := sql.Open("sqlite3", config.DBPath)
	if err != nil {
		return nil, err
	}

	// Create tables
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE NOT NULL,
			email TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			is_admin BOOLEAN DEFAULT 0,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);

		CREATE TABLE IF NOT EXISTS links (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			short_code TEXT UNIQUE NOT NULL,
			original_url TEXT NOT NULL,
			user_id INTEGER,
			clicks INTEGER DEFAULT 0,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES users(id)
		);

		CREATE INDEX IF NOT EXISTS idx_short_code ON links(short_code);
	`)
	if err != nil {
		return nil, err
	}

	// Create admin user if doesn't exist
	var count int
	db.QueryRow("SELECT COUNT(*) FROM users WHERE email = ?", config.AdminEmail).Scan(&count)
	if count == 0 {
		passwordHash := hashPassword(config.AdminPassword)
		_, err = db.Exec(
			"INSERT INTO users (username, email, password_hash, is_admin) VALUES (?, ?, ?, ?)",
			"admin", config.AdminEmail, passwordHash, true,
		)
		if err != nil {
			log.Printf("Warning: Could not create admin user: %v", err)
		} else {
			log.Printf("Admin user created with email: %s", config.AdminEmail)
		}
	}

	var rdb *redis.Client
	if config.UseRedis {
		rdb = redis.NewClient(&redis.Options{
			Addr:     config.RedisAddr,
			Password: config.RedisPassword,
			DB:       config.RedisDB,
		})

		// Test Redis connection
		if err := rdb.Ping(ctx).Err(); err != nil {
			log.Printf("Warning: Redis connection failed: %v. Falling back to SQLite only.", err)
			rdb = nil
		} else {
			log.Printf("Redis connected at %s", config.RedisAddr)
		}
	}

	return &Database{db: db, redis: rdb}, nil
}

func hashPassword(password string) string {
	hash := sha256.Sum256([]byte(password))
	return hex.EncodeToString(hash[:])
}

func (d *Database) CreateUser(username, email, password string) error {
	passwordHash := hashPassword(password)
	_, err := d.db.Exec(
		"INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
		username, email, passwordHash,
	)
	return err
}

func (d *Database) AuthenticateUser(email, password string) (int, string, bool, error) {
	var id int
	var username string
	var passwordHash string
	var isAdmin bool

	err := d.db.QueryRow(
		"SELECT id, username, password_hash, is_admin FROM users WHERE email = ?",
		email,
	).Scan(&id, &username, &passwordHash, &isAdmin)

	if err != nil {
		return 0, "", false, err
	}

	if passwordHash != hashPassword(password) {
		return 0, "", false, fmt.Errorf("invalid password")
	}

	return id, username, isAdmin, nil
}

func (d *Database) DeleteUser(username string) error {
	// First delete all links by this user
	_, err := d.db.Exec("DELETE FROM links WHERE user_id = (SELECT id FROM users WHERE username = ?)", username)
	if err != nil {
		return err
	}
	
	// Then delete the user
	_, err = d.db.Exec("DELETE FROM users WHERE username = ?", username)
	return err
}

func (d *Database) ChangeUserPassword(username, newPassword string) error {
	passwordHash := hashPassword(newPassword)
	_, err := d.db.Exec("UPDATE users SET password_hash = ? WHERE username = ?", passwordHash, username)
	return err
}

func (d *Database) SaveLink(shortCode, url string, userID *int) error {
	// Save to SQLite
	_, err := d.db.Exec(
		"INSERT INTO links (short_code, original_url, user_id) VALUES (?, ?, ?)",
		shortCode, url, userID,
	)
	if err != nil {
		return err
	}

	// Save to Redis if available
	if d.redis != nil {
		d.redis.Set(ctx, "link:"+shortCode, url, 0)
		d.redis.Set(ctx, "clicks:"+shortCode, 0, 0)
	}

	return nil
}

func (d *Database) GetLink(shortCode string) (string, bool) {
	var url string

	// Try Redis first if available
	if d.redis != nil {
		url, err := d.redis.Get(ctx, "link:"+shortCode).Result()
		if err == nil {
			// Increment clicks in Redis
			d.redis.Incr(ctx, "clicks:"+shortCode)
			// Also update SQLite in background
			go d.db.Exec("UPDATE links SET clicks = clicks + 1 WHERE short_code = ?", shortCode)
			return url, true
		}
	}

	// Fallback to SQLite
	err := d.db.QueryRow("SELECT original_url FROM links WHERE short_code = ?", shortCode).Scan(&url)
	if err != nil {
		return "", false
	}

	// Increment click count
	d.db.Exec("UPDATE links SET clicks = clicks + 1 WHERE short_code = ?", shortCode)

	// Cache in Redis if available
	if d.redis != nil {
		d.redis.Set(ctx, "link:"+shortCode, url, 0)
	}

	return url, true
}

func (d *Database) GetLinkStats(shortCode string) (clicks int64, createdAt time.Time, err error) {
	// Try Redis first for clicks
	if d.redis != nil {
		clicks, _ = d.redis.Get(ctx, "clicks:"+shortCode).Int64()
	}

	// Get from SQLite
	err = d.db.QueryRow(
		"SELECT clicks, created_at FROM links WHERE short_code = ?",
		shortCode,
	).Scan(&clicks, &createdAt)

	return
}

func (d *Database) ShortCodeExists(shortCode string) bool {
	// Check Redis first if available
	if d.redis != nil {
		exists, err := d.redis.Exists(ctx, "link:"+shortCode).Result()
		if err == nil && exists > 0 {
			return true
		}
	}

	// Check SQLite
	var count int
	d.db.QueryRow("SELECT COUNT(*) FROM links WHERE short_code = ?", shortCode).Scan(&count)
	return count > 0
}

func (d *Database) GetAllLinks() ([]map[string]interface{}, error) {
	rows, err := d.db.Query(`
		SELECT l.short_code, l.original_url, l.clicks, l.created_at, u.username
		FROM links l
		LEFT JOIN users u ON l.user_id = u.id
		ORDER BY l.created_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	links := make([]map[string]interface{}, 0)
	for rows.Next() {
		var shortCode, originalUrl string
		var clicks int
		var createdAt time.Time
		var username sql.NullString

		if err := rows.Scan(&shortCode, &originalUrl, &clicks, &createdAt, &username); err != nil {
			continue
		}

		link := map[string]interface{}{
			"shortCode":   shortCode,
			"originalUrl": originalUrl,
			"clicks":      clicks,
			"createdAt":   createdAt,
		}

		if username.Valid {
			link["username"] = username.String
		}

		links = append(links, link)
	}

	return links, nil
}

func (d *Database) GetAllUsers() ([]map[string]interface{}, error) {
	rows, err := d.db.Query(`
		SELECT username, email, is_admin, created_at
		FROM users
		ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	users := make([]map[string]interface{}, 0)
	for rows.Next() {
		var username, email string
		var isAdmin bool
		var createdAt time.Time

		if err := rows.Scan(&username, &email, &isAdmin, &createdAt); err != nil {
			continue
		}

		users = append(users, map[string]interface{}{
			"username":  username,
			"email":     email,
			"isAdmin":   isAdmin,
			"createdAt": createdAt,
		})
	}

	return users, nil
}

func (d *Database) GetStats() (map[string]interface{}, error) {
	var totalLinks, totalUsers int
	var totalClicks int64

	d.db.QueryRow("SELECT COUNT(*) FROM links").Scan(&totalLinks)
	d.db.QueryRow("SELECT COUNT(*) FROM users").Scan(&totalUsers)
	d.db.QueryRow("SELECT COALESCE(SUM(clicks), 0) FROM links").Scan(&totalClicks)

	return map[string]interface{}{
		"totalLinks": totalLinks,
		"totalUsers": totalUsers,
		"totalClicks": totalClicks,
	}, nil
}

func (d *Database) DeleteLink(shortCode string) error {
	// Delete from Redis if available
	if d.redis != nil {
		d.redis.Del(ctx, "link:"+shortCode, "clicks:"+shortCode)
	}

	// Delete from SQLite
	_, err := d.db.Exec("DELETE FROM links WHERE short_code = ?", shortCode)
	return err
}

func (d *Database) Close() error {
	if d.redis != nil {
		d.redis.Close()
	}
	return d.db.Close()
}

type ShortenRequest struct {
	URL        string  `json:"url"`
	CustomCode *string `json:"customCode,omitempty"`
}

type ShortenResponse struct {
	ShortURL string `json:"shortUrl"`
	Code     string `json:"code"`
}

type StatsResponse struct {
	ShortCode string `json:"shortCode"`
	Clicks    int64  `json:"clicks"`
	CreatedAt string `json:"createdAt"`
}

type AuthRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Username string `json:"username,omitempty"`
}

type AuthResponse struct {
	Username string `json:"username"`
	IsAdmin  bool   `json:"isAdmin"`
}

var database *Database
var appConfig *Config

func main() {
	appConfig = loadConfig()
	store = sessions.NewCookieStore([]byte(appConfig.SessionSecret))

	var err error
	database, err = NewDatabase(appConfig)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer database.Close()

	log.Printf("Starting URL Shortener on port %s", appConfig.Port)
	log.Printf("Domain: %s", appConfig.Domain)
	log.Printf("Database: %s", appConfig.DBPath)
	log.Printf("Redis: %s (enabled: %v)", appConfig.RedisAddr, appConfig.UseRedis)
	log.Printf("User Signup: %v", appConfig.UserSignup)
	log.Printf("Admin Email: %s", appConfig.AdminEmail)

	// Public routes
	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/login", handleLoginPage)
	http.HandleFunc("/signup", handleSignupPage)
	http.HandleFunc("/user", requireAuth(handleUserPage))
	
	// API routes
	http.HandleFunc("/api/shorten", handleShorten)
	http.HandleFunc("/api/stats/", handleStats)
	http.HandleFunc("/api/login", handleLogin)
	http.HandleFunc("/api/signup", handleSignup)
	http.HandleFunc("/api/logout", handleLogout)
	http.HandleFunc("/api/config", handleConfig)
	http.HandleFunc("/api/user/session", handleUserSession)
	http.HandleFunc("/api/user/links", requireAuth(handleUserLinks))
	http.HandleFunc("/api/user/links/", requireAuth(handleUserDeleteLink))
	
	// Admin routes
	http.HandleFunc("/admin", requireAdmin(handleAdminPage))
	http.HandleFunc("/api/admin/stats", requireAdmin(handleAdminStats))
	http.HandleFunc("/api/admin/links", requireAdmin(handleAdminLinks))
	http.HandleFunc("/api/admin/users", handleAdminUsersRoute)
	http.HandleFunc("/api/admin/users/", requireAdmin(handleAdminUserActions))
	http.HandleFunc("/api/admin/links/", requireAdmin(handleAdminDeleteLink))

	log.Fatal(http.ListenAndServe(":"+appConfig.Port, nil))
}

func getSession(r *http.Request) (*sessions.Session, error) {
	return store.Get(r, "vid-session")
}

func requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, err := getSession(r)
		if err != nil || session.Values["userID"] == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, err := getSession(r)
		if err != nil || session.Values["isAdmin"] != true {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/" {
		data, err := content.ReadFile("vid.html")
		if err != nil {
			http.Error(w, "Error reading file", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(data)
		return
	}

	shortCode := strings.TrimPrefix(r.URL.Path, "/")
	if url, exists := database.GetLink(shortCode); exists {
		http.Redirect(w, r, url, http.StatusMovedPermanently)
		return
	}

	http.NotFound(w, r)
}

func handleLoginPage(w http.ResponseWriter, r *http.Request) {
	data, err := content.ReadFile("login.html")
	if err != nil {
		http.Error(w, "Error reading file", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(data)
}

func handleSignupPage(w http.ResponseWriter, r *http.Request) {
	data, err := content.ReadFile("signup.html")
	if err != nil {
		http.Error(w, "Error reading file", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(data)
}

func handleAdminPage(w http.ResponseWriter, r *http.Request) {
	data, err := content.ReadFile("admin.html")
	if err != nil {
		http.Error(w, "Error reading file", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(data)
}

func handleConfig(w http.ResponseWriter, r *http.Request) {
	// Check if user is logged in
	session, _ := getSession(r)
	_, isLoggedIn := session.Values["userID"].(int)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"userSignup":                appConfig.UserSignup,
		"requireLogin":              appConfig.RequireLogin,
		"allowAnonymousCustomLinks": appConfig.AllowAnonymousCustomLinks,
		"isLoggedIn":                isLoggedIn,
	})
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req AuthRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	userID, username, isAdmin, err := database.AuthenticateUser(req.Email, req.Password)
	if err != nil {
		http.Error(w, "Неисправни акредитиви", http.StatusUnauthorized)
		return
	}

	session, _ := getSession(r)
	session.Values["userID"] = userID
	session.Values["username"] = username
	session.Values["isAdmin"] = isAdmin
	session.Save(r, w)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(AuthResponse{
		Username: username,
		IsAdmin:  isAdmin,
	})
}

func handleSignup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !appConfig.UserSignup {
		http.Error(w, "Регистрација је онемогућена", http.StatusForbidden)
		return
	}

	var req AuthRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if err := database.CreateUser(req.Username, req.Email, req.Password); err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint") {
			http.Error(w, "Корисничко име или е-пошта већ постоје", http.StatusConflict)
		} else {
			http.Error(w, "Грешка приликом креирања налога", http.StatusInternalServerError)
		}
		return
	}

	w.WriteHeader(http.StatusCreated)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	session, _ := getSession(r)
	session.Options.MaxAge = -1
	session.Save(r, w)
	w.WriteHeader(http.StatusOK)
}

func handleShorten(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Check if login is required
	session, _ := getSession(r)
	userID, isLoggedIn := session.Values["userID"].(int)
	
	if appConfig.RequireLogin && !isLoggedIn {
		http.Error(w, "Морате бити пријављени да бисте користили скраћивач", http.StatusUnauthorized)
		return
	}

	var req ShortenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.URL == "" {
		http.Error(w, "URL is required", http.StatusBadRequest)
		return
	}

	if !strings.HasPrefix(req.URL, "http://") && !strings.HasPrefix(req.URL, "https://") {
		http.Error(w, "URL must start with http:// or https://", http.StatusBadRequest)
		return
	}

	var shortCode string

	if req.CustomCode != nil && *req.CustomCode != "" {
		// Check if custom links are allowed for anonymous users
		if !isLoggedIn && !appConfig.AllowAnonymousCustomLinks {
			http.Error(w, "Морате бити пријављени да бисте користили прилагођене линкове", http.StatusUnauthorized)
			return
		}
		customCode := *req.CustomCode
		
		if len(customCode) < 3 || len(customCode) > 20 {
			http.Error(w, "Custom code must be between 3 and 20 characters", http.StatusBadRequest)
			return
		}
		
		if !isAlphanumeric(customCode) {
			http.Error(w, "Custom code must contain only letters and numbers", http.StatusBadRequest)
			return
		}

		if database.ShortCodeExists(customCode) {
			http.Error(w, "Custom code already taken", http.StatusConflict)
			return
		}

		shortCode = customCode
	} else {
		shortCode = generateShortCode()
		for database.ShortCodeExists(shortCode) {
			shortCode = generateShortCode()
		}
	}

	// Store user ID if logged in
	var userIDPtr *int
	if isLoggedIn {
		userIDPtr = &userID
	}

	if err := database.SaveLink(shortCode, req.URL, userIDPtr); err != nil {
		http.Error(w, "Failed to save link", http.StatusInternalServerError)
		log.Printf("Error saving link: %v", err)
		return
	}

	shortURL := fmt.Sprintf("https://%s/%s", appConfig.Domain, shortCode)

	response := ShortenResponse{
		ShortURL: shortURL,
		Code:     shortCode,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func handleStats(w http.ResponseWriter, r *http.Request) {
	shortCode := strings.TrimPrefix(r.URL.Path, "/api/stats/")

	if shortCode == "" {
		http.Error(w, "Short code required", http.StatusBadRequest)
		return
	}

	clicks, createdAt, err := database.GetLinkStats(shortCode)
	if err != nil {
		http.Error(w, "Link not found", http.StatusNotFound)
		return
	}

	response := StatsResponse{
		ShortCode: shortCode,
		Clicks:    clicks,
		CreatedAt: createdAt.Format("2006-01-02 15:04:05"),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func handleAdminStats(w http.ResponseWriter, r *http.Request) {
	stats, err := database.GetStats()
	if err != nil {
		http.Error(w, "Error fetching stats", http.StatusInternalServerError)
		return
	}

	session, _ := getSession(r)
	username := session.Values["username"].(string)
	stats["adminEmail"] = username

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func handleAdminLinks(w http.ResponseWriter, r *http.Request) {
	links, err := database.GetAllLinks()
	if err != nil {
		http.Error(w, "Error fetching links", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(links)
}

func handleAdminUsers(w http.ResponseWriter, r *http.Request) {
	users, err := database.GetAllUsers()
	if err != nil {
		http.Error(w, "Error fetching users", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(users)
}

func handleAdminDeleteLink(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	shortCode := strings.TrimPrefix(r.URL.Path, "/api/admin/links/")
	
	if err := database.DeleteLink(shortCode); err != nil {
		http.Error(w, "Error deleting link", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func handleUserPage(w http.ResponseWriter, r *http.Request) {
	data, err := content.ReadFile("user.html")
	if err != nil {
		http.Error(w, "Error reading file", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(data)
}

func handleUserSession(w http.ResponseWriter, r *http.Request) {
	session, err := getSession(r)
	if err != nil || session.Values["userID"] == nil {
		http.Error(w, "Not logged in", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"username": session.Values["username"],
		"isAdmin":  session.Values["isAdmin"],
	})
}

func handleUserLinks(w http.ResponseWriter, r *http.Request) {
	session, _ := getSession(r)
	userID := session.Values["userID"].(int)
	username := session.Values["username"].(string)

	rows, err := database.db.Query(`
		SELECT short_code, original_url, clicks, created_at
		FROM links
		WHERE user_id = ?
		ORDER BY created_at DESC
	`, userID)
	if err != nil {
		http.Error(w, "Error fetching links", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var links []map[string]interface{}
	for rows.Next() {
		var shortCode, originalUrl string
		var clicks int
		var createdAt time.Time

		if err := rows.Scan(&shortCode, &originalUrl, &clicks, &createdAt); err != nil {
			continue
		}

		links = append(links, map[string]interface{}{
			"shortCode":   shortCode,
			"originalUrl": originalUrl,
			"clicks":      clicks,
			"createdAt":   createdAt,
		})
	}

	if links == nil {
		links = []map[string]interface{}{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"username": username,
		"links":    links,
	})
}

func handleUserDeleteLink(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	session, _ := getSession(r)
	userID := session.Values["userID"].(int)
	shortCode := strings.TrimPrefix(r.URL.Path, "/api/user/links/")

	// Verify the link belongs to the user
	var linkUserID sql.NullInt64
	err := database.db.QueryRow("SELECT user_id FROM links WHERE short_code = ?", shortCode).Scan(&linkUserID)
	if err != nil || !linkUserID.Valid || int(linkUserID.Int64) != userID {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if err := database.DeleteLink(shortCode); err != nil {
		http.Error(w, "Error deleting link", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func handleAdminUsersRoute(w http.ResponseWriter, r *http.Request) {
	session, err := getSession(r)
	if err != nil || session.Values["isAdmin"] != true {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if r.Method == http.MethodPost {
		// Create new user (admin can bypass USER_SIGNUP setting)
		var req AuthRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		if err := database.CreateUser(req.Username, req.Email, req.Password); err != nil {
			if strings.Contains(err.Error(), "UNIQUE constraint") {
				http.Error(w, "Корисничко име или е-пошта већ постоје", http.StatusConflict)
			} else {
				http.Error(w, "Грешка приликом креирања налога", http.StatusInternalServerError)
			}
			return
		}

		w.WriteHeader(http.StatusCreated)
	} else {
		// Get all users
		handleAdminUsers(w, r)
	}
}

func handleAdminUserActions(w http.ResponseWriter, r *http.Request) {
	// Extract username from path: /api/admin/users/{username} or /api/admin/users/{username}/password
	path := strings.TrimPrefix(r.URL.Path, "/api/admin/users/")
	parts := strings.Split(path, "/")
	username := parts[0]

	if len(parts) == 2 && parts[1] == "password" && r.Method == http.MethodPut {
		// Change password
		var req struct {
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		if len(req.Password) < 6 {
			http.Error(w, "Лозинка мора имати најмање 6 карактера", http.StatusBadRequest)
			return
		}

		if err := database.ChangeUserPassword(username, req.Password); err != nil {
			http.Error(w, "Грешка приликом промене лозинке", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method == http.MethodDelete {
		// Delete user
		if err := database.DeleteUser(username); err != nil {
			http.Error(w, "Грешка приликом брисања корисника", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

func handleRedirect(w http.ResponseWriter, r *http.Request) {
	shortCode := strings.TrimPrefix(r.URL.Path, "/r/")

	if url, exists := database.GetLink(shortCode); exists {
		http.Redirect(w, r, url, http.StatusMovedPermanently)
		return
	}

	http.NotFound(w, r)
}

func generateShortCode() string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	const length = 6

	result := make([]byte, length)
	for i := range result {
		num, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		result[i] = charset[num.Int64()]
	}

	return string(result)
}

func isAlphanumeric(s string) bool {
	for _, r := range s {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			return false
		}
	}
	return true
}
