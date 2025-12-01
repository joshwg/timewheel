package handlers

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/josh/timewheel/db"
	"github.com/josh/timewheel/middleware"
	"github.com/josh/timewheel/models"
	"golang.org/x/crypto/bcrypt"
)

// PINSetupPageHandler shows the PIN setup page
func PINSetupPageHandler(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetCurrentUser(r)

	// Get error message from query parameter
	errorMsg := ""
	errorType := r.URL.Query().Get("error")
	switch errorType {
	case "pins_do_not_match":
		errorMsg = "PINs do not match. Please try again."
	case "invalid_pin_format":
		errorMsg = "PIN must be exactly 4 digits."
	case "missing_pin":
		errorMsg = "Both PIN fields are required."
	case "server_error":
		errorMsg = "An error occurred. Please try again later."
	}

	data := map[string]interface{}{
		"Title": "Setup PIN - Time Wheel",
		"Year":  time.Now().Year(),
		"User":  user,
		"Error": errorMsg,
	}

	if err := templates.ExecuteTemplate(w, "pin_setup.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// PINSetupHandler handles PIN setup
func PINSetupHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/pin/setup", http.StatusSeeOther)
		return
	}

	currentUser := middleware.GetCurrentUser(r)

	pin := r.FormValue("pin")
	confirmPIN := r.FormValue("confirm_pin")

	// Validate PIN
	if pin == "" || confirmPIN == "" {
		http.Redirect(w, r, "/pin/setup?error=missing_pin", http.StatusSeeOther)
		return
	}

	if pin != confirmPIN {
		http.Redirect(w, r, "/pin/setup?error=pins_do_not_match", http.StatusSeeOther)
		return
	}

	if len(pin) != models.PINLength {
		http.Redirect(w, r, "/pin/setup?error=invalid_pin_format", http.StatusSeeOther)
		return
	}

	// Verify PIN is numeric
	for _, char := range pin {
		if char < '0' || char > '9' {
			http.Redirect(w, r, "/pin/setup?error=invalid_pin_format", http.StatusSeeOther)
			return
		}
	}

	// Hash PIN
	pinHash, err := bcrypt.GenerateFromPassword([]byte(pin), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("Error hashing PIN: %v", err)
		http.Redirect(w, r, "/pin/setup?error=server_error", http.StatusSeeOther)
		return
	}

	// Update user's PIN
	_, err = db.DB.Exec(
		"UPDATE users SET pin_hash = ?, updated_at = ? WHERE id = ?",
		string(pinHash), time.Now(), currentUser.ID,
	)
	if err != nil {
		log.Printf("Error saving PIN: %v", err)
		http.Redirect(w, r, "/pin/setup?error=server_error", http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, "/account?success=pin_setup_complete", http.StatusSeeOther)
}

// PINLoginPageHandler shows the PIN login page
func PINLoginPageHandler(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	if username == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Look up user to verify PIN exists
	var user models.User
	var pinHash sql.NullString
	err := db.DB.QueryRow(
		"SELECT id, username, email, password_hash, pin_hash, is_admin, created_at, updated_at FROM users WHERE LOWER(username) = LOWER(?)",
		username,
	).Scan(&user.ID, &user.Username, &user.Email, &user.PasswordHash, &pinHash, &user.IsAdmin, &user.CreatedAt, &user.UpdatedAt)

	if pinHash.Valid {
		user.PINHash = pinHash.String
	}

	if err != nil || user.PINHash == "" {
		// User not found or no PIN configured
		http.Redirect(w, r, "/login?error=pin_not_setup", http.StatusSeeOther)
		return
	}

	// Get or create browser ID
	browserID, err := getBrowserID(r, w, user.ID)
	if err != nil {
		log.Printf("Error getting browser ID: %v", err)
		http.Redirect(w, r, "/login?error=server_error", http.StatusSeeOther)
		return
	}

	// Check if PIN attempts are locked
	var failedAttempts int
	var lockedUntil sql.NullTime
	err = db.DB.QueryRow(
		"SELECT failed_attempts, locked_until FROM pin_attempts WHERE user_id = ? AND browser_id = ?",
		user.ID, browserID,
	).Scan(&failedAttempts, &lockedUntil)

	// Initialize attempt record if it doesn't exist
	if err == sql.ErrNoRows {
		_, err = db.DB.Exec(
			"INSERT INTO pin_attempts (user_id, browser_id, failed_attempts, locked_until) VALUES (?, ?, 0, NULL)",
			user.ID, browserID,
		)
		if err != nil {
			log.Printf("Error creating PIN attempt record: %v", err)
		}
		failedAttempts = 0
	}

	// Check if locked
	isLocked := false
	if lockedUntil.Valid && lockedUntil.Time.After(time.Now()) {
		isLocked = true
	}

	// Get error message from query parameter
	errorMsg := ""
	errorType := r.URL.Query().Get("error")
	switch errorType {
	case "invalid_pin":
		errorMsg = "Invalid PIN. Please try again."
	case "pin_locked":
		errorMsg = "Too many failed attempts. Please use your password to login."
	case "missing_pin":
		errorMsg = "PIN is required."
	case "server_error":
		errorMsg = "An error occurred. Please try again later."
	}

	data := map[string]interface{}{
		"Title":          "PIN Login - Time Wheel",
		"Year":           time.Now().Year(),
		"Username":       user.Username,
		"FailedAttempts": failedAttempts,
		"IsLocked":       isLocked,
		"Error":          errorMsg,
	}

	if err := templates.ExecuteTemplate(w, "pin_login.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// PINLoginHandler handles PIN login
func PINLoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	username := r.FormValue("username")
	pin := r.FormValue("pin")

	if username == "" {
		http.Redirect(w, r, "/login?error=missing_fields", http.StatusSeeOther)
		return
	}

	if pin == "" {
		http.Redirect(w, r, "/login?error=missing_fields", http.StatusSeeOther)
		return
	}

	// Look up user
	var user models.User
	var pinHash sql.NullString
	err := db.DB.QueryRow(
		"SELECT id, username, email, password_hash, pin_hash, is_admin, created_at, updated_at FROM users WHERE LOWER(username) = LOWER(?)",
		username,
	).Scan(&user.ID, &user.Username, &user.Email, &user.PasswordHash, &pinHash, &user.IsAdmin, &user.CreatedAt, &user.UpdatedAt)

	if pinHash.Valid {
		user.PINHash = pinHash.String
	}

	if err != nil {
		log.Printf("Error finding user: %v", err)
		http.Redirect(w, r, "/login?error=invalid_credentials", http.StatusSeeOther)
		return
	}

	if user.PINHash == "" {
		http.Redirect(w, r, "/login?error=pin_not_setup", http.StatusSeeOther)
		return
	}

	// Get or create browser ID
	browserID, err := getBrowserID(r, w, user.ID)
	if err != nil {
		log.Printf("Error getting browser ID: %v", err)
		http.Redirect(w, r, "/pin-login?username="+username+"&error=server_error", http.StatusSeeOther)
		return
	}

	// Check if PIN attempts are locked
	var failedAttempts int
	var lockedUntil sql.NullTime
	err = db.DB.QueryRow(
		"SELECT failed_attempts, locked_until FROM pin_attempts WHERE user_id = ? AND browser_id = ?",
		user.ID, browserID,
	).Scan(&failedAttempts, &lockedUntil)

	// Initialize attempt record if it doesn't exist
	if err == sql.ErrNoRows {
		_, err = db.DB.Exec(
			"INSERT INTO pin_attempts (user_id, browser_id, failed_attempts, locked_until) VALUES (?, ?, 0, NULL)",
			user.ID, browserID,
		)
		if err != nil {
			log.Printf("Error creating PIN attempt record: %v", err)
			http.Redirect(w, r, "/pin-login?username="+username+"&error=server_error", http.StatusSeeOther)
			return
		}
		failedAttempts = 0
	}

	// Check if locked
	if lockedUntil.Valid && lockedUntil.Time.After(time.Now()) {
		http.Redirect(w, r, "/login?error=pin_locked", http.StatusSeeOther)
		return
	}

	// If lock has expired, reset attempts
	if lockedUntil.Valid && lockedUntil.Time.Before(time.Now()) {
		_, err = db.DB.Exec(
			"UPDATE pin_attempts SET failed_attempts = 0, locked_until = NULL WHERE user_id = ? AND browser_id = ?",
			user.ID, browserID,
		)
		if err != nil {
			log.Printf("Error resetting PIN attempts: %v", err)
		}
		failedAttempts = 0
	}

	// Verify PIN
	err = bcrypt.CompareHashAndPassword([]byte(user.PINHash), []byte(pin))
	if err != nil {
		// Increment failed attempts
		failedAttempts++
		if failedAttempts >= models.MaxPINAttempts {
			// Lock for 15 minutes
			lockUntil := time.Now().Add(15 * time.Minute)
			_, err = db.DB.Exec(
				"UPDATE pin_attempts SET failed_attempts = ?, locked_until = ? WHERE user_id = ? AND browser_id = ?",
				failedAttempts, lockUntil, user.ID, browserID,
			)
			if err != nil {
				log.Printf("Error updating PIN attempts: %v", err)
			}
			http.Redirect(w, r, "/login?error=pin_locked", http.StatusSeeOther)
			return
		} else {
			_, err = db.DB.Exec(
				"UPDATE pin_attempts SET failed_attempts = ? WHERE user_id = ? AND browser_id = ?",
				failedAttempts, user.ID, browserID,
			)
			if err != nil {
				log.Printf("Error updating PIN attempts: %v", err)
			}
			http.Redirect(w, r, "/pin-login?username="+username+"&error=invalid_pin", http.StatusSeeOther)
			return
		}
	}

	// PIN is correct - reset failed attempts
	_, err = db.DB.Exec(
		"UPDATE pin_attempts SET failed_attempts = 0, locked_until = NULL WHERE user_id = ? AND browser_id = ?",
		user.ID, browserID,
	)
	if err != nil {
		log.Printf("Error resetting PIN attempts: %v", err)
	}

	// Create session
	sessionToken, err := generateSessionToken()
	if err != nil {
		log.Printf("Error generating session token: %v", err)
		http.Redirect(w, r, "/pin-login?username="+username+"&error=server_error", http.StatusSeeOther)
		return
	}

	expiresAt := time.Now().Add(24 * time.Hour) // Session valid for 24 hours
	_, err = db.DB.Exec(
		"INSERT INTO sessions (user_id, session_token, last_activity, expires_at) VALUES (?, ?, ?, ?)",
		user.ID, sessionToken, time.Now(), expiresAt,
	)
	if err != nil {
		log.Printf("Error creating session: %v", err)
		http.Redirect(w, r, "/pin-login?username="+username+"&error=server_error", http.StatusSeeOther)
		return
	}

	// Set cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    sessionToken,
		Path:     "/",
		Expires:  expiresAt,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

// getBrowserID gets or creates a browser fingerprint ID
func getBrowserID(r *http.Request, w http.ResponseWriter, userID int) (string, error) {
	// Check if browser already has a PIN cookie
	cookie, err := r.Cookie("pin_browser")
	if err == nil && cookie.Value != "" {
		// Verify this browser ID exists for this user
		var exists int
		err = db.DB.QueryRow(
			"SELECT COUNT(*) FROM pin_cookies WHERE user_id = ? AND browser_id = ?",
			userID, cookie.Value,
		).Scan(&exists)
		if err == nil && exists > 0 {
			return cookie.Value, nil
		}
	}

	// Generate new browser ID
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	browserID := hex.EncodeToString(b)

	// Get browser fingerprint
	userAgent := r.Header.Get("User-Agent")
	ipAddress := r.RemoteAddr
	// Remove port from IP address
	if idx := strings.LastIndex(ipAddress, ":"); idx != -1 {
		ipAddress = ipAddress[:idx]
	}

	// Save browser ID
	expiresAt := time.Now().Add(365 * 24 * time.Hour) // Cookie valid for 1 year
	_, err = db.DB.Exec(
		"INSERT INTO pin_cookies (user_id, browser_id, user_agent, ip_address, expires_at) VALUES (?, ?, ?, ?, ?)",
		userID, browserID, userAgent, ipAddress, expiresAt,
	)
	if err != nil {
		return "", err
	}

	// Set cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "pin_browser",
		Value:    browserID,
		Path:     "/",
		Expires:  expiresAt,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	return browserID, nil
}
