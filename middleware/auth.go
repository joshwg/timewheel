package middleware

import (
	"context"
	"database/sql"
	"log"
	"net/http"
	"time"

	"github.com/josh/timewheel/db"
	"github.com/josh/timewheel/models"
)

// ContextKey is a custom type for context keys
type ContextKey string

const (
	// UserContextKey is the key for storing user in context
	UserContextKey ContextKey = "user"
)

// AuthRequired middleware checks if user is authenticated
func AuthRequired(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session_token")
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		user, session, err := validateSession(cookie.Value)
		if err != nil {
			// Session invalid or expired
			http.SetCookie(w, &http.Cookie{
				Name:   "session_token",
				Value:  "",
				Path:   "/",
				MaxAge: -1,
			})
			http.Redirect(w, r, "/login?expired=1", http.StatusSeeOther)
			return
		}

		// Check for 30-minute inactivity timeout
		if time.Since(session.LastActivity) > models.SessionTimeout {
			// Session expired due to inactivity
			deleteSession(session.SessionToken)
			http.SetCookie(w, &http.Cookie{
				Name:   "session_token",
				Value:  "",
				Path:   "/",
				MaxAge: -1,
			})
			http.Redirect(w, r, "/login?timeout=1", http.StatusSeeOther)
			return
		}

		// Update last activity time
		updateSessionActivity(session.SessionToken)

		// Add user to context
		ctx := context.WithValue(r.Context(), UserContextKey, user)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

// AdminRequired middleware checks if user is an administrator
func AdminRequired(next http.HandlerFunc) http.HandlerFunc {
	return AuthRequired(func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value(UserContextKey).(*models.User)

		if !user.IsAdmin {
			http.Error(w, "Forbidden: Admin access required", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// validateSession checks if a session token is valid
func validateSession(token string) (*models.User, *models.Session, error) {
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
		if err == sql.ErrNoRows {
			return nil, nil, err
		}
		log.Printf("Error validating session: %v", err)
		return nil, nil, err
	}

	return &user, &session, nil
}

// updateSessionActivity updates the last_activity timestamp of a session
func updateSessionActivity(token string) {
	_, err := db.DB.Exec(
		"UPDATE sessions SET last_activity = ? WHERE session_token = ?",
		time.Now(), token,
	)
	if err != nil {
		log.Printf("Error updating session activity: %v", err)
	}
}

// deleteSession removes a session from the database
func deleteSession(token string) {
	_, err := db.DB.Exec("DELETE FROM sessions WHERE session_token = ?", token)
	if err != nil {
		log.Printf("Error deleting session: %v", err)
	}
}

// GetCurrentUser retrieves the current user from the request context
func GetCurrentUser(r *http.Request) *models.User {
	if user, ok := r.Context().Value(UserContextKey).(*models.User); ok {
		return user
	}
	return nil
}
