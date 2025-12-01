package db

import (
	"database/sql"
	"log"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

var DB *sql.DB

// InitDB initializes the database connection and creates tables
func InitDB(dbPath string) error {
	var err error
	DB, err = sql.Open("sqlite3", dbPath)
	if err != nil {
		return err
	}

	// Test connection
	if err = DB.Ping(); err != nil {
		return err
	}

	// Create tables
	if err = createTables(); err != nil {
		return err
	}

	// Create default admin user if not exists
	if err = createDefaultAdmin(); err != nil {
		return err
	}

	return nil
}

// CloseDB closes the database connection
func CloseDB() error {
	if DB != nil {
		return DB.Close()
	}
	return nil
}

// createTables creates the necessary database tables
func createTables() error {
	schema := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL UNIQUE COLLATE NOCASE,
		email TEXT NOT NULL UNIQUE COLLATE NOCASE,
		phone TEXT,
		password_hash TEXT NOT NULL,
		pin_hash TEXT,
		notification_time TEXT DEFAULT '09:00',
		notification_timezone TEXT DEFAULT 'America/New_York',
		use_dst BOOLEAN NOT NULL DEFAULT 1,
		is_admin BOOLEAN NOT NULL DEFAULT 0,
		is_admin BOOLEAN NOT NULL DEFAULT 0,
		is_admin BOOLEAN NOT NULL DEFAULT 0,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS sessions (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		session_token TEXT NOT NULL UNIQUE,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		last_activity DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		expires_at DATETIME NOT NULL,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS pin_attempts (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		browser_id TEXT NOT NULL,
		failed_attempts INTEGER NOT NULL DEFAULT 0,
		locked_until DATETIME,
		last_attempt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(user_id, browser_id),
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS pin_cookies (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		browser_id TEXT NOT NULL,
		user_agent TEXT,
		ip_address TEXT,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		last_used DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		expires_at DATETIME,
		UNIQUE(user_id, browser_id),
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS time_cards (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		title TEXT NOT NULL,
		description TEXT,
		send_sms BOOLEAN NOT NULL DEFAULT 0,
		send_email BOOLEAN NOT NULL DEFAULT 0,
		repeat_type TEXT NOT NULL CHECK(repeat_type IN ('weekly', 'monthly', 'yearly')),
		repeat_every INTEGER NOT NULL DEFAULT 1 CHECK(repeat_every >= 1 AND repeat_every <= 100),
		day_of_week INTEGER DEFAULT 0 CHECK(day_of_week >= 0 AND day_of_week <= 6),
		day_of_month INTEGER DEFAULT 1 CHECK(day_of_month >= 1 AND day_of_month <= 31),
		next_due DATETIME NOT NULL,
		last_sent DATETIME,
		reminder_days INTEGER DEFAULT 0 CHECK(reminder_days >= 0 AND reminder_days <= 10),
		reminder_count INTEGER DEFAULT 0 CHECK(reminder_count >= 0),
		last_reminder_sent DATETIME,
		is_active BOOLEAN NOT NULL DEFAULT 1,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS time_card_logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		time_card_id INTEGER NOT NULL,
		user_id INTEGER NOT NULL,
		log_type TEXT NOT NULL CHECK(log_type IN ('sent', 'completed', 'reminder_sent')),
		message TEXT,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (time_card_id) REFERENCES time_cards(id) ON DELETE CASCADE,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
	);

	CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(session_token);
	CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
	CREATE INDEX IF NOT EXISTS idx_pin_attempts_user_browser ON pin_attempts(user_id, browser_id);
	CREATE INDEX IF NOT EXISTS idx_pin_cookies_user_browser ON pin_cookies(user_id, browser_id);
	CREATE INDEX IF NOT EXISTS idx_time_cards_user ON time_cards(user_id);
	CREATE INDEX IF NOT EXISTS idx_time_cards_next_due ON time_cards(next_due);
	CREATE INDEX IF NOT EXISTS idx_time_cards_active ON time_cards(is_active);
	CREATE INDEX IF NOT EXISTS idx_time_card_logs_card ON time_card_logs(time_card_id);
	CREATE INDEX IF NOT EXISTS idx_time_card_logs_user ON time_card_logs(user_id);
	CREATE INDEX IF NOT EXISTS idx_time_card_logs_type ON time_card_logs(log_type);
	`

	_, err := DB.Exec(schema)
	if err != nil {
		return err
	}

	// Run migrations
	if err := migrateReminderFields(); err != nil {
		return err
	}
	if err := migrateNotificationTime(); err != nil {
		return err
	}
	return migrateUseDST()
}

// createDefaultAdmin creates a default admin user if none exists
func createDefaultAdmin() error {
	var count int
	err := DB.QueryRow("SELECT COUNT(*) FROM users WHERE is_admin = 1").Scan(&count)
	if err != nil {
		return err
	}

	// If admin exists, skip
	if count > 0 {
		return nil
	}

	// Create default admin with password "abcd1234"
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte("abcd1234"), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	_, err = DB.Exec(
		"INSERT INTO users (username, email, password_hash, is_admin, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
		"super", "changeme@domain.com", string(hashedPassword), true, time.Now(), time.Now(),
	)

	if err == nil {
		log.Printf("Default admin: username=super, email=changeme@domain.com, password=abcd1234")
	}

	return err
}

// migrateReminderFields updates the time_cards table to use new reminder tracking fields
func migrateReminderFields() error {
	// Check if reminder_sent column exists (old schema)
	var columnExists int
	err := DB.QueryRow(`
		SELECT COUNT(*) FROM pragma_table_info('time_cards') 
		WHERE name = 'reminder_sent'
	`).Scan(&columnExists)

	if err != nil {
		return err
	}

	// If old column exists, migrate to new schema
	if columnExists > 0 {
		log.Println("Migrating reminder fields...")

		// SQLite doesn't support DROP COLUMN, so we need to recreate the table
		_, err = DB.Exec(`
			CREATE TABLE time_cards_new (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				user_id INTEGER NOT NULL,
				title TEXT NOT NULL,
				description TEXT,
				send_sms BOOLEAN NOT NULL DEFAULT 0,
				send_email BOOLEAN NOT NULL DEFAULT 0,
				repeat_type TEXT NOT NULL CHECK(repeat_type IN ('weekly', 'monthly', 'yearly')),
				repeat_every INTEGER NOT NULL DEFAULT 1 CHECK(repeat_every >= 1 AND repeat_every <= 100),
				day_of_week INTEGER DEFAULT 0 CHECK(day_of_week >= 0 AND day_of_week <= 6),
				day_of_month INTEGER DEFAULT 1 CHECK(day_of_month >= 1 AND day_of_month <= 31),
				next_due DATETIME NOT NULL,
				last_sent DATETIME,
				reminder_days INTEGER DEFAULT 0 CHECK(reminder_days >= 0 AND reminder_days <= 10),
				reminder_count INTEGER DEFAULT 0 CHECK(reminder_count >= 0),
				last_reminder_sent DATETIME,
				is_active BOOLEAN NOT NULL DEFAULT 1,
				created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
				updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
				FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
			);

			INSERT INTO time_cards_new 
				(id, user_id, title, description, send_sms, send_email, repeat_type, repeat_every, 
				 day_of_week, day_of_month, next_due, last_sent, reminder_days, reminder_count, 
				 last_reminder_sent, is_active, created_at, updated_at)
			SELECT 
				id, user_id, title, description, send_sms, send_email, repeat_type, repeat_every,
				day_of_week, day_of_month, next_due, last_sent, reminder_days, 
				0, NULL, is_active, created_at, updated_at
			FROM time_cards;

			DROP TABLE time_cards;
			ALTER TABLE time_cards_new RENAME TO time_cards;

			CREATE INDEX IF NOT EXISTS idx_time_cards_user ON time_cards(user_id);
			CREATE INDEX IF NOT EXISTS idx_time_cards_next_due ON time_cards(next_due);
			CREATE INDEX IF NOT EXISTS idx_time_cards_active ON time_cards(is_active);
		`)

		if err != nil {
			return err
		}

		log.Println("Migration completed successfully")
	}

	return nil
}

// migrateNotificationTime adds notification_time and notification_timezone fields to users table if they don't exist
func migrateNotificationTime() error {
	// Check if notification_time column exists
	var timeColumnExists int
	err := DB.QueryRow(`
		SELECT COUNT(*) FROM pragma_table_info('users') 
		WHERE name = 'notification_time'
	`).Scan(&timeColumnExists)

	if err != nil {
		return err
	}

	// If column doesn't exist, add it
	if timeColumnExists == 0 {
		log.Println("Adding notification_time column to users table...")
		_, err = DB.Exec(`ALTER TABLE users ADD COLUMN notification_time TEXT DEFAULT '09:00'`)
		if err != nil {
			return err
		}
		log.Println("notification_time column added successfully")
	}

	// Check if notification_timezone column exists
	var timezoneColumnExists int
	err = DB.QueryRow(`
		SELECT COUNT(*) FROM pragma_table_info('users') 
		WHERE name = 'notification_timezone'
	`).Scan(&timezoneColumnExists)

	if err != nil {
		return err
	}

	// If column doesn't exist, add it
	if timezoneColumnExists == 0 {
		log.Println("Adding notification_timezone column to users table...")
		_, err = DB.Exec(`ALTER TABLE users ADD COLUMN notification_timezone TEXT DEFAULT 'America/New_York'`)
		if err != nil {
			return err
		}
		log.Println("notification_timezone column added successfully")
	}

	return nil
}

// migrateUseDST adds use_dst field to users table if it doesn't exist
func migrateUseDST() error {
	// Check if use_dst column exists
	var exists int
	err := DB.QueryRow(`
		SELECT COUNT(*) FROM pragma_table_info('users') 
		WHERE name = 'use_dst'
	`).Scan(&exists)

	if err != nil {
		return err
	}

	// If column doesn't exist, add it
	if exists == 0 {
		log.Println("Adding use_dst column to users table...")
		_, err = DB.Exec(`ALTER TABLE users ADD COLUMN use_dst BOOLEAN NOT NULL DEFAULT 1`)
		if err != nil {
			return err
		}
		log.Println("use_dst column added successfully")
	}

	return nil
}

// CleanupExpiredSessions removes expired sessions from the database
func CleanupExpiredSessions() {
	result, err := DB.Exec("DELETE FROM sessions WHERE expires_at < ?", time.Now())
	if err != nil {
		log.Printf("Error cleaning up expired sessions: %v", err)
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected > 0 {
		log.Printf("Cleaned up %d expired session(s)", rowsAffected)
	}
}
