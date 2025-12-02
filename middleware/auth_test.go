package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/josh/timewheel/models"
)

func TestGetCurrentUser(t *testing.T) {
	user := &models.User{
		ID:       1,
		Username: "testuser",
		Email:    "test@example.com",
		IsAdmin:  false,
	}

	ctx := context.WithValue(context.Background(), UserContextKey, user)

	result := GetCurrentUser(&http.Request{}.WithContext(ctx))

	if result == nil {
		t.Fatal("GetCurrentUser() returned nil")
	}

	if result.ID != user.ID {
		t.Errorf("ID = %v, want %v", result.ID, user.ID)
	}
	if result.Username != user.Username {
		t.Errorf("Username = %v, want %v", result.Username, user.Username)
	}
}

func TestGetCurrentUserNilContext(t *testing.T) {
	result := GetCurrentUser(&http.Request{})

	if result != nil {
		t.Errorf("GetCurrentUser() with empty context = %v, want nil", result)
	}
}

func TestAuthRequiredWithoutCookie(t *testing.T) {
	handler := AuthRequired(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/dashboard", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	// Should redirect to login
	if w.Code != http.StatusSeeOther {
		t.Errorf("Status code = %v, want %v", w.Code, http.StatusSeeOther)
	}

	location := w.Header().Get("Location")
	if location != "/login" {
		t.Errorf("Redirect location = %v, want /login", location)
	}
}

func TestAdminRequiredWithoutCookie(t *testing.T) {
	handler := AdminRequired(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/admin", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	// Should redirect to login
	if w.Code != http.StatusSeeOther {
		t.Errorf("Status code = %v, want %v", w.Code, http.StatusSeeOther)
	}

	location := w.Header().Get("Location")
	if location != "/login" {
		t.Errorf("Redirect location = %v, want /login", location)
	}
}

func TestContextKey(t *testing.T) {
	key := UserContextKey
	expected := ContextKey("user")

	if key != expected {
		t.Errorf("UserContextKey = %v, want %v", key, expected)
	}
}
