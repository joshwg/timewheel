package models

import (
	"database/sql"
	"time"
)

// Session timeout duration (30 minutes)
const SessionTimeout = 30 * time.Minute

// PIN configuration
const (
	PINLength       = 4
	MaxPINAttempts  = 3
	PINLockDuration = 24 * time.Hour
)

// User represents a user in the system
type User struct {
	ID           int
	Username     string
	Email        string
	PasswordHash string
	PINHash      string
	IsAdmin      bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// UserResponse is the user data sent to clients (without sensitive data)
type UserResponse struct {
	ID        int       `json:"id"`
	Username  string    `json:"username"`
	Email     string    `json:"email"`
	IsAdmin   bool      `json:"is_admin"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ToUserResponse converts a User to UserResponse
func (u *User) ToUserResponse() UserResponse {
	return UserResponse{
		ID:        u.ID,
		Username:  u.Username,
		Email:     u.Email,
		IsAdmin:   u.IsAdmin,
		CreatedAt: u.CreatedAt,
		UpdatedAt: u.UpdatedAt,
	}
}

// Session represents a user session
type Session struct {
	ID           int
	UserID       int
	SessionToken string
	CreatedAt    time.Time
	LastActivity time.Time
	ExpiresAt    time.Time
}

// PINAttempt tracks failed PIN login attempts per browser
type PINAttempt struct {
	ID             int
	UserID         int
	BrowserID      string
	FailedAttempts int
	LockedUntil    sql.NullTime
	LastAttempt    time.Time
}

// PINCookie stores browser-specific PIN authentication cookies
type PINCookie struct {
	ID        int
	UserID    int
	BrowserID string
	CreatedAt time.Time
	LastUsed  time.Time
	ExpiresAt sql.NullTime
}
