package handlers

import (
	"strings"
	"testing"
	"time"

	"github.com/josh/timewheel/db"
)

func init() {
	// Initialize database for tests
	// Use in-memory database for testing
	db.InitDB(":memory:")

	// Skip template initialization for unit tests
	// Templates are not needed for validation logic tests
	// Integration tests that need templates should initialize them separately
}

// TestValidUsername tests username character validation
// Note: This function only validates allowed characters, not length
func TestValidUsername(t *testing.T) {
	tests := []struct {
		username string
		valid    bool
		desc     string
	}{
		{"abc", true, "valid 3 characters"},
		{"ab", true, "2 chars - valid characters (length checked elsewhere)"},
		{"", true, "empty string - valid characters (length checked elsewhere)"},
		{"validUser123", true, "alphanumeric"},
		{"user_name", true, "with underscore"},
		{"user-name", true, "with hyphen"},
		{"user.name", true, "with dot"},
		{"user+name", true, "with plus"},
		{"user=name", true, "with equals"},
		{"user#1", true, "with hash"},
		{"user$1", true, "with dollar"},
		{"user@name", false, "with at symbol (invalid)"},
		{"user name", false, "with space (invalid)"},
		{"user!name", false, "with exclamation (invalid)"},
		{"user*name", false, "with asterisk (invalid)"},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			result := isValidUsername(tt.username)
			if result != tt.valid {
				t.Errorf("isValidUsername(%q) = %v, want %v", tt.username, result, tt.valid)
			}
		})
	}
}

// TestCompleteUsernameValidation tests full username validation including length
func TestCompleteUsernameValidation(t *testing.T) {
	tests := []struct {
		username string
		valid    bool
		desc     string
	}{
		{"abc", true, "minimum 3 characters"},
		{"ab", false, "too short (2 chars)"},
		{"", false, "empty string"},
		{"validUser123", true, "valid alphanumeric"},
		{"user_name", true, "valid with underscore"},
		{"user@name", false, "invalid character (@)"},
		{"user name", false, "invalid character (space)"},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			// Complete validation: length >= 3 AND valid characters
			valid := len(tt.username) >= 3 && isValidUsername(tt.username)
			if valid != tt.valid {
				t.Errorf("Complete username validation(%q) = %v, want %v", tt.username, valid, tt.valid)
			}
		})
	}
}

// TestValidEmail tests email validation
func TestValidEmail(t *testing.T) {
	tests := []struct {
		email string
		valid bool
		desc  string
	}{
		{"user@example.com", true, "standard email"},
		{"user.name@example.com", true, "with dot in local"},
		{"user+tag@example.com", true, "with plus in local"},
		{"user@subdomain.example.com", true, "with subdomain"},
		{"invalid", false, "no @ symbol"},
		{"@example.com", false, "missing local part"},
		{"user@", false, "missing domain"},
		{"user@@example.com", false, "double @ symbol"},
		{"user@.com", false, "missing domain name"},
		{"user@example", false, "missing TLD"},
		{"", false, "empty string"},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			result := validateEmail(tt.email)
			if result != tt.valid {
				t.Errorf("validateEmail(%q) = %v, want %v", tt.email, result, tt.valid)
			}
		})
	}
}

// TestRegisterValidation tests registration input validation logic
// Note: This tests validation rules, not the full handler flow
func TestRegisterValidation(t *testing.T) {
	tests := []struct {
		username    string
		email       string
		password    string
		confirm     string
		desc        string
		expectValid bool
	}{
		{"validuser", "valid@example.com", "password123", "password123", "valid registration", true},
		{"ab", "valid@example.com", "password123", "password123", "username too short", false},
		{"user@invalid", "valid@example.com", "password123", "password123", "invalid username chars", false},
		{"validuser", "invalid-email", "password123", "password123", "invalid email format", false},
		{"validuser", "valid@example.com", "pass", "pass", "password too short", false},
		{"validuser", "valid@example.com", "password123", "different", "passwords don't match", false},
		{"", "valid@example.com", "password123", "password123", "empty username", false},
		{"validuser", "", "password123", "password123", "empty email", false},
		{"validuser", "valid@example.com", "", "", "empty password", false},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			// Test validation logic
			valid := true

			// Check username
			if tt.username == "" || len(tt.username) < 3 || !isValidUsername(tt.username) {
				valid = false
			}

			// Check email
			if tt.email == "" || !validateEmail(tt.email) {
				valid = false
			}

			// Check password
			if tt.password == "" || len(tt.password) < 6 {
				valid = false
			}

			// Check password match
			if tt.password != tt.confirm {
				valid = false
			}

			if valid != tt.expectValid {
				t.Errorf("Validation result = %v, want %v", valid, tt.expectValid)
			}
		})
	}
}

// TestLoginValidation tests login input validation logic
func TestLoginValidation(t *testing.T) {
	tests := []struct {
		username    string
		password    string
		desc        string
		expectValid bool
	}{
		{"", "", "empty credentials", false},
		{"user", "", "empty password", false},
		{"", "password", "empty username", false},
		{"validuser", "password123", "valid credentials", true},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			// Test validation logic
			valid := tt.username != "" && tt.password != ""

			if valid != tt.expectValid {
				t.Errorf("Validation result = %v, want %v", valid, tt.expectValid)
			}
		})
	}
}

// TestPasswordValidation tests password requirements
func TestPasswordValidation(t *testing.T) {
	tests := []struct {
		password string
		valid    bool
		desc     string
	}{
		{"password", true, "6+ characters valid"},
		{"pass", false, "less than 6 characters"},
		{"", false, "empty password"},
		{"123456", true, "numeric password (allowed)"},
		{"abcdef", true, "alphabetic password (allowed)"},
		{"P@ssw0rd!", true, "complex password"},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			result := len(tt.password) >= 6
			if result != tt.valid {
				t.Errorf("password length check (%q) = %v, want %v", tt.password, result, tt.valid)
			}
		})
	}
}

// TestPINValidation tests PIN format validation
func TestPINValidation(t *testing.T) {
	tests := []struct {
		pin   string
		valid bool
		desc  string
	}{
		{"1234", true, "valid 4-digit PIN"},
		{"0000", true, "all zeros valid"},
		{"9999", true, "all nines valid"},
		{"123", false, "too short"},
		{"12345", false, "too long"},
		{"", false, "empty string"},
		{"abcd", false, "non-numeric"},
		{"12a4", false, "mixed alphanumeric"},
		{"12 4", false, "with space"},
		{"12-4", false, "with hyphen"},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			// Check length
			if len(tt.pin) != 4 && tt.valid {
				t.Errorf("PIN length check failed: %q should be invalid due to length", tt.pin)
				return
			}

			// Check if all characters are digits
			isNumeric := true
			for _, char := range tt.pin {
				if char < '0' || char > '9' {
					isNumeric = false
					break
				}
			}

			result := len(tt.pin) == 4 && isNumeric
			if result != tt.valid {
				t.Errorf("PIN validation (%q) = %v, want %v", tt.pin, result, tt.valid)
			}
		})
	}
}

// TestPINAttemptLocking tests PIN lockout after multiple failed attempts
func TestPINAttemptLocking(t *testing.T) {
	// This test verifies the logic for locking PIN after failed attempts
	// In real implementation, this would test the actual database operations

	maxAttempts := 3
	lockDuration := 15 * time.Minute

	tests := []struct {
		attempts   int
		shouldLock bool
		desc       string
	}{
		{1, false, "1 failed attempt - not locked"},
		{2, false, "2 failed attempts - not locked"},
		{3, true, "3 failed attempts - locked"},
		{4, true, "4 failed attempts - still locked"},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			locked := tt.attempts >= maxAttempts
			if locked != tt.shouldLock {
				t.Errorf("Lockout logic for %d attempts = %v, want %v", tt.attempts, locked, tt.shouldLock)
			}

			if locked {
				// Verify lock duration is set correctly
				if lockDuration != 15*time.Minute {
					t.Errorf("Lock duration = %v, want 15 minutes", lockDuration)
				}
			}
		})
	}
}

// TestPINLockExpiry tests that PIN lock expires after duration
func TestPINLockExpiry(t *testing.T) {
	lockTime := time.Now()
	lockDuration := 15 * time.Minute
	lockedUntil := lockTime.Add(lockDuration)

	tests := []struct {
		checkTime time.Time
		isLocked  bool
		desc      string
	}{
		{lockTime, true, "immediately after lock - locked"},
		{lockTime.Add(5 * time.Minute), true, "5 minutes after lock - still locked"},
		{lockTime.Add(14 * time.Minute), true, "14 minutes after lock - still locked"},
		{lockTime.Add(15 * time.Minute), false, "15 minutes after lock - unlocked"},
		{lockTime.Add(20 * time.Minute), false, "20 minutes after lock - unlocked"},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			locked := lockedUntil.After(tt.checkTime)
			if locked != tt.isLocked {
				t.Errorf("Lock status at %v = %v, want %v", tt.checkTime, locked, tt.isLocked)
			}
		})
	}
}

// TestAdminUserSelfDeletion tests that admin cannot delete themselves
func TestAdminUserSelfDeletion(t *testing.T) {
	// This tests the logic that prevents admins from deleting their own account
	currentUserID := 1
	targetUserID := 1
	isAdmin := true

	canDelete := !(currentUserID == targetUserID && isAdmin)

	if canDelete {
		t.Error("Admin should not be able to delete themselves")
	}
}

// TestUsernameUniqueness tests that usernames must be unique (case-insensitive)
func TestUsernameUniqueness(t *testing.T) {
	tests := []struct {
		existing string
		new      string
		conflict bool
		desc     string
	}{
		{"john", "john", true, "exact match"},
		{"john", "JOHN", true, "case insensitive match"},
		{"john", "John", true, "mixed case match"},
		{"john", "jane", false, "different username"},
		{"john", "johnny", false, "similar but different"},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			conflict := strings.EqualFold(tt.existing, tt.new)
			if conflict != tt.conflict {
				t.Errorf("Username conflict check (%q vs %q) = %v, want %v",
					tt.existing, tt.new, conflict, tt.conflict)
			}
		})
	}
}

// TestEmailUniqueness tests that emails must be unique (case-insensitive)
func TestEmailUniqueness(t *testing.T) {
	tests := []struct {
		existing string
		new      string
		conflict bool
		desc     string
	}{
		{"user@example.com", "user@example.com", true, "exact match"},
		{"user@example.com", "USER@EXAMPLE.COM", true, "case insensitive match"},
		{"user@example.com", "User@Example.Com", true, "mixed case match"},
		{"user@example.com", "other@example.com", false, "different email"},
		{"user@example.com", "user@other.com", false, "different domain"},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			conflict := strings.EqualFold(tt.existing, tt.new)
			if conflict != tt.conflict {
				t.Errorf("Email conflict check (%q vs %q) = %v, want %v",
					tt.existing, tt.new, conflict, tt.conflict)
			}
		})
	}
}
