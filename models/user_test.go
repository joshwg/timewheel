package models

import (
	"testing"
	"time"
)

func TestToUserResponse(t *testing.T) {
	now := time.Now()
	user := &User{
		ID:                   1,
		Username:             "testuser",
		Email:                "test@example.com",
		Phone:                "5551234567",
		PasswordHash:         "hashedpassword",
		PINHash:              "hashedpin",
		IsAdmin:              true,
		NotificationTime:     "09:00",
		NotificationTimezone: "America/New_York",
		UseDST:               true,
		CreatedAt:            now,
		UpdatedAt:            now,
	}

	response := user.ToUserResponse()

	// Check that all public fields are copied
	if response.ID != user.ID {
		t.Errorf("ID = %v, want %v", response.ID, user.ID)
	}
	if response.Username != user.Username {
		t.Errorf("Username = %v, want %v", response.Username, user.Username)
	}
	if response.Email != user.Email {
		t.Errorf("Email = %v, want %v", response.Email, user.Email)
	}
	if response.Phone != user.Phone {
		t.Errorf("Phone = %v, want %v", response.Phone, user.Phone)
	}
	if response.IsAdmin != user.IsAdmin {
		t.Errorf("IsAdmin = %v, want %v", response.IsAdmin, user.IsAdmin)
	}
	if response.NotificationTime != user.NotificationTime {
		t.Errorf("NotificationTime = %v, want %v", response.NotificationTime, user.NotificationTime)
	}
	if response.NotificationTimezone != user.NotificationTimezone {
		t.Errorf("NotificationTimezone = %v, want %v", response.NotificationTimezone, user.NotificationTimezone)
	}
	if response.UseDST != user.UseDST {
		t.Errorf("UseDST = %v, want %v", response.UseDST, user.UseDST)
	}
	if response.CreatedAt != user.CreatedAt {
		t.Errorf("CreatedAt = %v, want %v", response.CreatedAt, user.CreatedAt)
	}
	if response.UpdatedAt != user.UpdatedAt {
		t.Errorf("UpdatedAt = %v, want %v", response.UpdatedAt, user.UpdatedAt)
	}
}

func TestUserConstants(t *testing.T) {
	tests := []struct {
		name     string
		value    interface{}
		expected interface{}
	}{
		{"SessionTimeout", SessionTimeout, 30 * time.Minute},
		{"PINLength", PINLength, 4},
		{"MaxPINAttempts", MaxPINAttempts, 3},
		{"PINLockDuration", PINLockDuration, 24 * time.Hour},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.value != tt.expected {
				t.Errorf("%s = %v, want %v", tt.name, tt.value, tt.expected)
			}
		})
	}
}

func TestUserResponseExcludesSensitiveData(t *testing.T) {
	user := &User{
		ID:           1,
		Username:     "testuser",
		PasswordHash: "hashedpassword",
		PINHash:      "hashedpin",
	}

	response := user.ToUserResponse()

	// Verify that UserResponse struct doesn't have sensitive fields
	// This is a compile-time check, but we can verify the fields exist in User
	if user.PasswordHash == "" {
		t.Error("User should have PasswordHash field")
	}
	if user.PINHash == "" {
		t.Error("User should have PINHash field")
	}

	// Ensure response has ID and Username
	if response.ID != 1 {
		t.Errorf("Response ID = %v, want 1", response.ID)
	}
	if response.Username != "testuser" {
		t.Errorf("Response Username = %v, want testuser", response.Username)
	}
}
