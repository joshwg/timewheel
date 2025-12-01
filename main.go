package main

import (
	"html/template"
	"log"
	"net/http"
	"time"

	"github.com/josh/timewheel/db"
	"github.com/josh/timewheel/handlers"
	"github.com/josh/timewheel/middleware"
)

var templates *template.Template

func main() {
	// Initialize database
	if err := db.InitDB("timewheel.db"); err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.CloseDB()

	// Initialize templates
	handlers.InitTemplates()
	templates = template.Must(template.ParseGlob("templates/*.html"))

	// Start session cleanup routine
	go sessionCleanupRoutine()

	// Serve static files
	fs := http.FileServer(http.Dir("static"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))

	// Public routes
	http.HandleFunc("/login", handlers.LoginPageHandler)
	// Registration disabled - admins create users via admin panel
	// http.HandleFunc("/register", handlers.RegisterPageHandler)
	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/about", aboutHandler)

	// Authentication routes
	http.HandleFunc("/api/login", handlers.LoginHandler)
	// Registration disabled - admins create users via admin panel
	// http.HandleFunc("/api/register", handlers.RegisterHandler)
	http.HandleFunc("/logout", handlers.LogoutHandler)

	// PIN routes
	http.HandleFunc("/pin-login", handlers.PINLoginPageHandler)
	http.HandleFunc("/pin/login", handlers.PINLoginHandler)
	http.HandleFunc("/pin/setup", middleware.AuthRequired(handlers.PINSetupPageHandler))
	http.HandleFunc("/pin/setup/save", middleware.AuthRequired(handlers.PINSetupHandler))
	http.HandleFunc("/pin/invalidate", middleware.AuthRequired(handlers.InvalidatePINHandler))

	// Protected routes
	http.HandleFunc("/dashboard", middleware.AuthRequired(handlers.DashboardHandler))
	http.HandleFunc("/account", middleware.AuthRequired(handlers.AccountHandler))
	http.HandleFunc("/api/time", middleware.AuthRequired(timeAPIHandler))
	http.HandleFunc("/account/update", middleware.AuthRequired(handlers.UpdateProfileHandler))
	http.HandleFunc("/account/delete", middleware.AuthRequired(handlers.DeleteAccountHandler))

	// Admin routes
	http.HandleFunc("/admin/users", middleware.AdminRequired(handlers.AdminPanelHandler))
	http.HandleFunc("/admin/users/create", middleware.AdminRequired(handlers.CreateUserHandler))
	http.HandleFunc("/admin/users/update", middleware.AdminRequired(handlers.UpdateUserHandler))
	http.HandleFunc("/api/admin/users", middleware.AdminRequired(handlers.APIUsersHandler))

	// Start server
	port := ":8080"
	log.Printf("Server starting on http://localhost%s", port)
	if err := http.ListenAndServe(port, nil); err != nil {
		log.Fatal(err)
	}
}

// sessionCleanupRoutine periodically cleans up expired sessions
func sessionCleanupRoutine() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		db.CleanupExpiredSessions()
		log.Println("Cleaned up expired sessions")
	}
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	// Redirect root path to login page
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func aboutHandler(w http.ResponseWriter, r *http.Request) {
	data := map[string]interface{}{
		"Title": "About - Time Wheel",
		"Year":  time.Now().Year(),
	}

	if err := templates.ExecuteTemplate(w, "about.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func timeAPIHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"time":"` + time.Now().Format(time.RFC3339) + `"}`))
}
