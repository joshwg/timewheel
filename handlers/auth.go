package handlers

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/josh/timewheel/db"
	"github.com/josh/timewheel/middleware"
	"github.com/josh/timewheel/models"
	"golang.org/x/crypto/bcrypt"
)

var templates *template.Template

// Email validation regex - RFC 5322 simplified
var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)

// InitTemplates initializes all templates
func InitTemplates() {
	templates = template.Must(template.ParseGlob("templates/*.html"))
}

// validateEmail checks if the email address is valid
func validateEmail(email string) bool {
	return emailRegex.MatchString(email)
}

// checkDefaultAdminExists checks if user "super" exists with password "abcd1234" (case-insensitive)
func checkDefaultAdminExists() bool {
	var passwordHash string
	err := db.DB.QueryRow(
		"SELECT password_hash FROM users WHERE LOWER(username) = LOWER(?)",
		"super",
	).Scan(&passwordHash)

	if err != nil {
		return false
	}

	// Check if password is still "abcd1234"
	err = bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte("abcd1234"))
	return err == nil
}

// LoginPageHandler shows the login page
func LoginPageHandler(w http.ResponseWriter, r *http.Request) {
	// Check if already logged in
	if cookie, err := r.Cookie("session_token"); err == nil {
		if _, _, err := validateSessionForHandler(cookie.Value); err == nil {
			http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
			return
		}
	}

	// Check if default admin exists with default password
	showDefaultAdmin := checkDefaultAdminExists()

	// Get error message from query parameter
	errorMsg := ""
	errorType := r.URL.Query().Get("error")
	switch errorType {
	case "invalid_credentials":
		errorMsg = "Invalid username/email or password. Please try again."
	case "invalid_pin":
		errorMsg = "Invalid PIN. Please try again."
	case "pin_locked":
		errorMsg = "Too many failed PIN attempts. Please use your password to login."
	case "pin_not_setup":
		errorMsg = "PIN not set up for this account. Please use password login."
	case "missing_fields":
		errorMsg = "Username/email and password are required."
	case "invalid_method":
		errorMsg = "Invalid request method."
	case "server_error":
		errorMsg = "An error occurred. Please try again later."
	}

	data := map[string]interface{}{
		"Title":            "Login - Time Wheel",
		"Year":             time.Now().Year(),
		"Expired":          r.URL.Query().Get("expired") == "1",
		"Timeout":          r.URL.Query().Get("timeout") == "1",
		"Deleted":          r.URL.Query().Get("deleted") == "1",
		"ShowDefaultAdmin": showDefaultAdmin,
		"Error":            errorMsg,
	}

	if err := templates.ExecuteTemplate(w, "login.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// RegisterPageHandler shows the registration page
func RegisterPageHandler(w http.ResponseWriter, r *http.Request) {
	data := map[string]interface{}{
		"Title": "Register - Time Wheel",
		"Year":  time.Now().Year(),
	}

	if err := templates.ExecuteTemplate(w, "register.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// LoginHandler handles user login
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/login?error=invalid_method", http.StatusSeeOther)
		return
	}

	usernameOrEmail := strings.TrimSpace(r.FormValue("username_or_email"))
	password := r.FormValue("password")

	if usernameOrEmail == "" || password == "" {
		http.Redirect(w, r, "/login?error=missing_fields", http.StatusSeeOther)
		return
	}

	// Find user by username or email (case-insensitive)
	var user models.User
	var pinHash sql.NullString
	err := db.DB.QueryRow(
		"SELECT id, username, email, password_hash, pin_hash, is_admin, created_at, updated_at FROM users WHERE LOWER(username) = LOWER(?) OR LOWER(email) = LOWER(?)",
		usernameOrEmail, usernameOrEmail,
	).Scan(&user.ID, &user.Username, &user.Email, &user.PasswordHash, &pinHash, &user.IsAdmin, &user.CreatedAt, &user.UpdatedAt)

	if pinHash.Valid {
		user.PINHash = pinHash.String
	}

	if err != nil {
		if err == sql.ErrNoRows {
			http.Redirect(w, r, "/login?error=invalid_credentials", http.StatusSeeOther)
			return
		}
		log.Printf("Database error: %v", err)
		http.Redirect(w, r, "/login?error=server_error", http.StatusSeeOther)
		return
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		http.Redirect(w, r, "/login?error=invalid_credentials", http.StatusSeeOther)
		return
	}

	// Reset PIN attempts if browser has PIN cookie (password login resets lockout)
	if pinCookie, err := r.Cookie("pin_browser"); err == nil {
		db.DB.Exec(
			"UPDATE pin_attempts SET failed_attempts = 0, locked_until = NULL WHERE user_id = ? AND browser_id = ?",
			user.ID, pinCookie.Value,
		)
	}

	// Create session
	sessionToken, err := generateSessionToken()
	if err != nil {
		log.Printf("Error generating session token: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	expiresAt := time.Now().Add(24 * time.Hour) // Session valid for 24 hours
	_, err = db.DB.Exec(
		"INSERT INTO sessions (user_id, session_token, last_activity, expires_at) VALUES (?, ?, ?, ?)",
		user.ID, sessionToken, time.Now(), expiresAt,
	)
	if err != nil {
		log.Printf("Error creating session: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
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

// RegisterHandler handles user registration
func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username := strings.TrimSpace(r.FormValue("username"))
	email := strings.TrimSpace(r.FormValue("email"))
	password := r.FormValue("password")
	confirmPassword := r.FormValue("confirm_password")

	// Validation
	if username == "" || email == "" || password == "" {
		http.Error(w, "Username, email and password are required", http.StatusBadRequest)
		return
	}

	if len(username) < 3 {
		http.Error(w, "Username must be at least 3 characters", http.StatusBadRequest)
		return
	}

	// Validate username contains only allowed characters: alphanumeric and #$_-+=.
	if !isValidUsername(username) {
		http.Error(w, "Username can only contain letters, numbers, and the symbols: #$_-+=.", http.StatusBadRequest)
		return
	}

	// Validate email format
	if !validateEmail(email) {
		http.Error(w, "Invalid email address format", http.StatusBadRequest)
		return
	}

	if password != confirmPassword {
		http.Error(w, "Passwords do not match", http.StatusBadRequest)
		return
	}

	if len(password) < 6 {
		http.Error(w, "Password must be at least 6 characters", http.StatusBadRequest)
		return
	}

	// Check for existing username or email (case-insensitive)
	var exists int
	err := db.DB.QueryRow(
		"SELECT COUNT(*) FROM users WHERE LOWER(username) = LOWER(?) OR LOWER(email) = LOWER(?)",
		username, email,
	).Scan(&exists)
	if err != nil {
		log.Printf("Error checking existing user: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if exists > 0 {
		// Determine which field conflicts
		var usernameExists int
		db.DB.QueryRow("SELECT COUNT(*) FROM users WHERE LOWER(username) = LOWER(?)", username).Scan(&usernameExists)
		if usernameExists > 0 {
			http.Error(w, "Username already taken", http.StatusConflict)
		} else {
			http.Error(w, "Email already registered", http.StatusConflict)
		}
		return
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("Error hashing password: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Create user (preserves case as entered)
	_, err = db.DB.Exec(
		"INSERT INTO users (username, email, password_hash, is_admin) VALUES (?, ?, ?, ?)",
		username, email, string(hashedPassword), false,
	)
	if err != nil {
		log.Printf("Error creating user: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/login?registered=1", http.StatusSeeOther)
}

// LogoutHandler handles user logout
func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_token")
	if err == nil {
		// Delete session from database
		db.DB.Exec("DELETE FROM sessions WHERE session_token = ?", cookie.Value)
	}

	// Clear cookie
	http.SetCookie(w, &http.Cookie{
		Name:   "session_token",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})

	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// DashboardHandler shows the user dashboard
func DashboardHandler(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetCurrentUser(r)

	// Get error or success message from query parameters
	errorMsg := r.URL.Query().Get("error")
	successMsg := r.URL.Query().Get("success")

	// Check if user has a PIN configured
	var pinExists bool
	err := db.DB.QueryRow(
		"SELECT EXISTS(SELECT 1 FROM users WHERE id = ? AND pin_hash IS NOT NULL AND pin_hash != '')",
		user.ID,
	).Scan(&pinExists)
	if err != nil {
		log.Printf("Error checking PIN status: %v", err)
		pinExists = false
	}

	data := map[string]interface{}{
		"Title":   "Dashboard - Time Wheel",
		"Year":    time.Now().Year(),
		"User":    user,
		"Message": "Welcome to your dashboard",
		"Error":   errorMsg,
		"Success": successMsg,
		"HasPIN":  pinExists,
	}

	if err := templates.ExecuteTemplate(w, "dashboard.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// AccountHandler shows the account info page
func AccountHandler(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetCurrentUser(r)

	// Get error or success message from query parameters
	errorMsg := r.URL.Query().Get("error")
	successMsg := r.URL.Query().Get("success")

	// Check if user has a PIN configured
	var pinExists bool
	err := db.DB.QueryRow(
		"SELECT EXISTS(SELECT 1 FROM users WHERE id = ? AND pin_hash IS NOT NULL AND pin_hash != '')",
		user.ID,
	).Scan(&pinExists)
	if err != nil {
		log.Printf("Error checking PIN status: %v", err)
		pinExists = false
	}

	data := map[string]interface{}{
		"Title":   "Account Info - Time Wheel",
		"Year":    time.Now().Year(),
		"User":    user,
		"Error":   errorMsg,
		"Success": successMsg,
		"HasPIN":  pinExists,
	}

	if err := templates.ExecuteTemplate(w, "account.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// AdminPanelHandler shows the admin panel
func AdminPanelHandler(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetCurrentUser(r)

	// Get all users
	rows, err := db.DB.Query(
		"SELECT id, username, email, is_admin, created_at FROM users ORDER BY created_at DESC",
	)
	if err != nil {
		log.Printf("Error fetching users: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var users []models.UserResponse
	for rows.Next() {
		var u models.UserResponse
		if err := rows.Scan(&u.ID, &u.Username, &u.Email, &u.IsAdmin, &u.CreatedAt); err != nil {
			log.Printf("Error scanning user: %v", err)
			continue
		}
		users = append(users, u)
	}

	data := map[string]interface{}{
		"Title": "Admin Panel - Time Wheel",
		"Year":  time.Now().Year(),
		"User":  user,
		"Users": users,
	}

	if err := templates.ExecuteTemplate(w, "admin.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// CreateUserHandler allows admins to create new users
func CreateUserHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username := strings.TrimSpace(r.FormValue("username"))
	email := strings.TrimSpace(r.FormValue("email"))
	password := r.FormValue("password")
	isAdmin := r.FormValue("is_admin") == "true"

	// Validation
	if username == "" || email == "" || password == "" {
		http.Error(w, "Username, email and password are required", http.StatusBadRequest)
		return
	}

	if len(username) < 3 {
		http.Error(w, "Username must be at least 3 characters", http.StatusBadRequest)
		return
	}

	// Validate username contains only allowed characters
	if !isValidUsername(username) {
		http.Error(w, "Username can only contain letters, numbers, and the symbols: #$_-+=.", http.StatusBadRequest)
		return
	}

	// Validate email format
	if !validateEmail(email) {
		http.Error(w, "Invalid email address format", http.StatusBadRequest)
		return
	}

	if len(password) < 6 {
		http.Error(w, "Password must be at least 6 characters", http.StatusBadRequest)
		return
	}

	// Check for existing username or email (case-insensitive)
	var exists int
	err := db.DB.QueryRow(
		"SELECT COUNT(*) FROM users WHERE LOWER(username) = LOWER(?) OR LOWER(email) = LOWER(?)",
		username, email,
	).Scan(&exists)
	if err != nil {
		log.Printf("Error checking existing user: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if exists > 0 {
		// Determine which field conflicts
		var usernameExists int
		db.DB.QueryRow("SELECT COUNT(*) FROM users WHERE LOWER(username) = LOWER(?)", username).Scan(&usernameExists)
		if usernameExists > 0 {
			http.Error(w, "Username already taken", http.StatusConflict)
		} else {
			http.Error(w, "Email already registered", http.StatusConflict)
		}
		return
	}

	// Hash password
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("Error hashing password: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Create user
	_, err = db.DB.Exec(
		"INSERT INTO users (username, email, password_hash, is_admin, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
		username, email, string(passwordHash), isAdmin, time.Now(), time.Now(),
	)
	if err != nil {
		log.Printf("Error creating user: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
}

// UpdateUserHandler allows admins to update user information
func UpdateUserHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	currentUser := middleware.GetCurrentUser(r)
	userIDStr := r.FormValue("user_id")
	userID, err := strconv.Atoi(userIDStr)
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	action := r.FormValue("action")

	// Prevent admins from deleting themselves
	if userID == currentUser.ID && action == "delete" {
		http.Error(w, "Admin users cannot delete themselves. Please have another admin delete your account.", http.StatusForbidden)
		return
	}

	// Prevent admins from removing their own admin status if they're the only admin
	if userID == currentUser.ID && action == "toggle_admin" {
		var adminCount int
		err := db.DB.QueryRow("SELECT COUNT(*) FROM users WHERE is_admin = 1").Scan(&adminCount)
		if err != nil {
			log.Printf("Error counting admins: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		if adminCount <= 1 {
			http.Error(w, "Cannot remove your own admin status. You are the only administrator.", http.StatusForbidden)
			return
		}

		http.Error(w, "Cannot remove your own admin status. Please have another admin do this.", http.StatusForbidden)
		return
	}

	switch action {
	case "edit":
		// Admin can edit username, email, and optionally password
		newUsername := strings.TrimSpace(r.FormValue("username"))
		newEmail := strings.TrimSpace(r.FormValue("email"))
		newPassword := r.FormValue("password")

		// Validate username
		if newUsername == "" {
			http.Error(w, "Username is required", http.StatusBadRequest)
			return
		}
		if len(newUsername) < 3 {
			http.Error(w, "Username must be at least 3 characters", http.StatusBadRequest)
			return
		}
		if !isValidUsername(newUsername) {
			http.Error(w, "Username can only contain letters, numbers, and the symbols: #$_-+=.", http.StatusBadRequest)
			return
		}

		// Validate email
		if !validateEmail(newEmail) {
			http.Error(w, "Invalid email address format", http.StatusBadRequest)
			return
		}

		// Check for username/email conflicts with other users
		var exists int
		err = db.DB.QueryRow(
			"SELECT COUNT(*) FROM users WHERE id != ? AND (LOWER(username) = LOWER(?) OR LOWER(email) = LOWER(?))",
			userID, newUsername, newEmail,
		).Scan(&exists)
		if err != nil {
			log.Printf("Error checking existing user: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		if exists > 0 {
			http.Error(w, "Username or email already taken by another user", http.StatusConflict)
			return
		}

		// Update username and email
		_, err = db.DB.Exec(
			"UPDATE users SET username = ?, email = ?, updated_at = ? WHERE id = ?",
			newUsername, newEmail, time.Now(), userID,
		)
		if err != nil {
			log.Printf("Error updating user: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// If password is provided, update it
		if newPassword != "" {
			if len(newPassword) < 6 {
				http.Error(w, "Password must be at least 6 characters", http.StatusBadRequest)
				return
			}

			passwordHash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
			if err != nil {
				log.Printf("Error hashing password: %v", err)
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}

			_, err = db.DB.Exec(
				"UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?",
				passwordHash, time.Now(), userID,
			)
			if err != nil {
				log.Printf("Error updating password: %v", err)
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}
		}

	case "toggle_admin":
		_, err = db.DB.Exec(
			"UPDATE users SET is_admin = NOT is_admin, updated_at = ? WHERE id = ?",
			time.Now(), userID,
		)
	case "delete":
		// Admins can delete any other user (including other admins), just not themselves
		_, err = db.DB.Exec("DELETE FROM users WHERE id = ?", userID)
	default:
		http.Error(w, "Invalid action", http.StatusBadRequest)
		return
	}

	if err != nil {
		log.Printf("Error updating user: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
}

// UpdateProfileHandler allows regular users to update their own email and password
func UpdateProfileHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	currentUser := middleware.GetCurrentUser(r)

	newEmail := strings.TrimSpace(r.FormValue("email"))
	currentPassword := r.FormValue("current_password")
	newPassword := r.FormValue("new_password")
	confirmPassword := r.FormValue("confirm_password")

	// Validate current password first
	if currentPassword == "" {
		http.Redirect(w, r, "/account?error=password_required", http.StatusSeeOther)
		return
	}

	err := bcrypt.CompareHashAndPassword([]byte(currentUser.PasswordHash), []byte(currentPassword))
	if err != nil {
		http.Redirect(w, r, "/account?error=incorrect_password", http.StatusSeeOther)
		return
	}

	// Validate email
	if !validateEmail(newEmail) {
		http.Redirect(w, r, "/account?error=invalid_email", http.StatusSeeOther)
		return
	}

	// Check if email is taken by another user
	var exists int
	err = db.DB.QueryRow(
		"SELECT COUNT(*) FROM users WHERE id != ? AND LOWER(email) = LOWER(?)",
		currentUser.ID, newEmail,
	).Scan(&exists)
	if err != nil {
		log.Printf("Error checking existing email: %v", err)
		http.Redirect(w, r, "/account?error=server_error", http.StatusSeeOther)
		return
	}
	if exists > 0 {
		http.Redirect(w, r, "/account?error=email_taken", http.StatusSeeOther)
		return
	}

	// Update email
	_, err = db.DB.Exec(
		"UPDATE users SET email = ?, updated_at = ? WHERE id = ?",
		newEmail, time.Now(), currentUser.ID,
	)
	if err != nil {
		log.Printf("Error updating email: %v", err)
		http.Redirect(w, r, "/account?error=server_error", http.StatusSeeOther)
		return
	}

	// If new password provided, validate and update it
	if newPassword != "" {
		if newPassword != confirmPassword {
			http.Redirect(w, r, "/account?error=password_mismatch", http.StatusSeeOther)
			return
		}

		if len(newPassword) < 6 {
			http.Redirect(w, r, "/account?error=password_too_short", http.StatusSeeOther)
			return
		}

		passwordHash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
		if err != nil {
			log.Printf("Error hashing password: %v", err)
			http.Redirect(w, r, "/account?error=server_error", http.StatusSeeOther)
			return
		}

		_, err = db.DB.Exec(
			"UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?",
			passwordHash, time.Now(), currentUser.ID,
		)
		if err != nil {
			log.Printf("Error updating password: %v", err)
			http.Redirect(w, r, "/account?error=server_error", http.StatusSeeOther)
			return
		}
	}

	http.Redirect(w, r, "/account?success=profile_updated", http.StatusSeeOther)
}

// InvalidatePINHandler allows users to remove their PIN configuration
func InvalidatePINHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	currentUser := middleware.GetCurrentUser(r)

	// Clear PIN hash from users table
	_, err := db.DB.Exec(
		"UPDATE users SET pin_hash = NULL, updated_at = ? WHERE id = ?",
		time.Now(), currentUser.ID,
	)
	if err != nil {
		log.Printf("Error clearing PIN: %v", err)
		http.Redirect(w, r, "/account?error=pin_clear_failed", http.StatusSeeOther)
		return
	}

	// Delete all PIN attempts for this user
	_, err = db.DB.Exec("DELETE FROM pin_attempts WHERE user_id = ?", currentUser.ID)
	if err != nil {
		log.Printf("Error deleting PIN attempts: %v", err)
		// Continue anyway - PIN hash is already cleared
	}

	// Delete all PIN cookies for this user
	_, err = db.DB.Exec("DELETE FROM pin_cookies WHERE user_id = ?", currentUser.ID)
	if err != nil {
		log.Printf("Error deleting PIN cookies: %v", err)
		// Continue anyway - PIN hash is already cleared
	}

	http.Redirect(w, r, "/account?success=pin_removed", http.StatusSeeOther)
}

// DeleteAccountHandler allows users to delete their own account
func DeleteAccountHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	currentUser := middleware.GetCurrentUser(r)

	// Prevent admin users from deleting themselves
	if currentUser.IsAdmin {
		http.Error(w, "Admin users cannot delete themselves. Please have another admin delete your account.", http.StatusForbidden)
		return
	}

	// Verify password for confirmation
	password := r.FormValue("password")
	if password == "" {
		http.Error(w, "Password is required for account deletion", http.StatusBadRequest)
		return
	}

	// Verify the password
	err := bcrypt.CompareHashAndPassword([]byte(currentUser.PasswordHash), []byte(password))
	if err != nil {
		http.Error(w, "Incorrect password", http.StatusUnauthorized)
		return
	}

	// Delete all user data (sessions, PIN attempts, PIN cookies will cascade due to FK constraints)
	_, err = db.DB.Exec("DELETE FROM users WHERE id = ?", currentUser.ID)
	if err != nil {
		log.Printf("Error deleting user account: %v", err)
		http.Error(w, "Failed to delete account", http.StatusInternalServerError)
		return
	}

	// Clear the session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})

	// Clear the PIN cookie if exists
	http.SetCookie(w, &http.Cookie{
		Name:     "pin_browser",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})

	// Redirect to home with a message
	http.Redirect(w, r, "/login?deleted=1", http.StatusSeeOther)
}

// Helper functions

// isValidUsername checks if username contains only allowed characters
// Allowed: alphanumeric (a-z, A-Z, 0-9) and symbols: #$_-+=.
func isValidUsername(username string) bool {
	const allowedSymbols = "#$_-+=."

	for _, char := range username {
		isAlphanumeric := unicode.IsLetter(char) || unicode.IsDigit(char)
		isAllowedSymbol := strings.ContainsRune(allowedSymbols, char)

		if !isAlphanumeric && !isAllowedSymbol {
			return false
		}
	}
	return true
}

func generateSessionToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func validateSessionForHandler(token string) (*models.User, *models.Session, error) {
	var session models.Session
	var user models.User

	query := `
		SELECT s.id, s.user_id, s.session_token, s.created_at, s.last_activity, s.expires_at,
		       u.id, u.username, u.email, u.password_hash, u.pin_hash, u.is_admin, u.created_at, u.updated_at
		FROM sessions s
		JOIN users u ON s.user_id = u.id
		WHERE s.session_token = ? AND s.expires_at > ?
	`

	var pinHash sql.NullString
	err := db.DB.QueryRow(query, token, time.Now()).Scan(
		&session.ID, &session.UserID, &session.SessionToken,
		&session.CreatedAt, &session.LastActivity, &session.ExpiresAt,
		&user.ID, &user.Username, &user.Email, &user.PasswordHash, &pinHash,
		&user.IsAdmin, &user.CreatedAt, &user.UpdatedAt,
	)

	if pinHash.Valid {
		user.PINHash = pinHash.String
	}

	if err != nil {
		return nil, nil, err
	}

	return &user, &session, nil
}

// API handlers for JSON responses

// APIUsersHandler returns all users (admin only)
func APIUsersHandler(w http.ResponseWriter, r *http.Request) {
	rows, err := db.DB.Query(
		"SELECT id, username, email, is_admin, created_at FROM users ORDER BY created_at DESC",
	)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Database error"})
		return
	}
	defer rows.Close()

	var users []models.UserResponse
	for rows.Next() {
		var u models.UserResponse
		if err := rows.Scan(&u.ID, &u.Username, &u.Email, &u.IsAdmin, &u.CreatedAt); err != nil {
			continue
		}
		users = append(users, u)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(users)
}
