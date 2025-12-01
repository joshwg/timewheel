package handlers

import (
	"database/sql"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/josh/timewheel/db"
	"github.com/josh/timewheel/middleware"
	"github.com/josh/timewheel/models"
)

// TimeCardsPageHandler shows the time cards page
func TimeCardsPageHandler(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetCurrentUser(r)

	// Get error or success message from query parameters
	errorMsg := r.URL.Query().Get("error")
	successMsg := r.URL.Query().Get("success")

	// Get all time cards for the user
	rows, err := db.DB.Query(`
		SELECT id, title, description, send_sms, send_email, repeat_type, repeat_every, 
		       day_of_week, day_of_month, next_due, last_sent, reminder_days, reminder_count, last_reminder_sent, is_active, created_at
		FROM time_cards 
		WHERE user_id = ? 
		ORDER BY next_due ASC
	`, user.ID)
	if err != nil {
		log.Printf("Error fetching time cards: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var timeCards []models.TimeCardResponse
	for rows.Next() {
		var tc models.TimeCardResponse
		var lastSent, lastReminderSent sql.NullTime
		if err := rows.Scan(&tc.ID, &tc.Title, &tc.Description, &tc.SendSMS, &tc.SendEmail,
			&tc.RepeatType, &tc.RepeatEvery, &tc.DayOfWeek, &tc.DayOfMonth,
			&tc.NextDue, &lastSent, &tc.ReminderDays, &tc.ReminderCount, &lastReminderSent, &tc.IsActive, &tc.CreatedAt); err != nil {
			log.Printf("Error scanning time card: %v", err)
			continue
		}
		if lastSent.Valid {
			tc.LastSent = &lastSent.Time
		}
		if lastReminderSent.Valid {
			tc.LastReminderSent = &lastReminderSent.Time
		}
		timeCards = append(timeCards, tc)
	}

	data := map[string]interface{}{
		"Title":     "Time Cards - Time Wheel",
		"Year":      time.Now().Year(),
		"User":      user,
		"TimeCards": timeCards,
		"Error":     errorMsg,
		"Success":   successMsg,
	}

	if err := templates.ExecuteTemplate(w, "timecards.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// CreateTimeCardHandler creates a new time card
func CreateTimeCardHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/timecards?error=invalid_method", http.StatusSeeOther)
		return
	}

	user := middleware.GetCurrentUser(r)

	title := strings.TrimSpace(r.FormValue("title"))
	description := strings.TrimSpace(r.FormValue("description"))
	sendSMS := r.FormValue("send_sms") == "on"
	sendEmail := r.FormValue("send_email") == "on"
	repeatType := r.FormValue("repeat_type")
	repeatEveryStr := r.FormValue("repeat_every")
	dayOfWeekStr := r.FormValue("day_of_week")
	dayOfMonthStr := r.FormValue("day_of_month")
	reminderDaysStr := r.FormValue("reminder_days")

	// Validate title
	if title == "" {
		http.Redirect(w, r, "/timecards?error=title_required", http.StatusSeeOther)
		return
	}

	// Validate repeat type
	if repeatType != "weekly" && repeatType != "monthly" && repeatType != "yearly" {
		http.Redirect(w, r, "/timecards?error=invalid_repeat_type", http.StatusSeeOther)
		return
	}

	// Parse repeat_every
	repeatEvery := 1
	if repeatEveryStr != "" {
		var err error
		repeatEvery, err = strconv.Atoi(repeatEveryStr)
		if err != nil || repeatEvery < 1 || repeatEvery > 100 {
			http.Redirect(w, r, "/timecards?error=invalid_repeat_every", http.StatusSeeOther)
			return
		}
	}

	// Parse day_of_week (default 0 = Sunday)
	dayOfWeek := 0
	if dayOfWeekStr != "" {
		var err error
		dayOfWeek, err = strconv.Atoi(dayOfWeekStr)
		if err != nil || dayOfWeek < 0 || dayOfWeek > 6 {
			http.Redirect(w, r, "/timecards?error=invalid_day_of_week", http.StatusSeeOther)
			return
		}
	}

	// Parse day_of_month (default 1)
	dayOfMonth := 1
	if dayOfMonthStr != "" {
		var err error
		dayOfMonth, err = strconv.Atoi(dayOfMonthStr)
		if err != nil || dayOfMonth < 1 || dayOfMonth > 31 {
			http.Redirect(w, r, "/timecards?error=invalid_day_of_month", http.StatusSeeOther)
			return
		}
	}

	// Parse reminder_days
	reminderDays := 0
	if reminderDaysStr != "" {
		var err error
		reminderDays, err = strconv.Atoi(reminderDaysStr)
		if err != nil || reminderDays < 0 || reminderDays > 10 {
			http.Redirect(w, r, "/timecards?error=invalid_reminder_days", http.StatusSeeOther)
			return
		}
	}

	// Calculate next_due date
	nextDue := calculateNextDue(repeatType, repeatEvery, dayOfWeek, dayOfMonth)

	// Insert time card
	_, err := db.DB.Exec(`
	INSERT INTO time_cards (user_id, title, description, send_sms, send_email, 
	                        repeat_type, repeat_every, day_of_week, day_of_month, 
	                        next_due, reminder_days, is_active, created_at, updated_at)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
`, user.ID, title, description, sendSMS, sendEmail, repeatType, repeatEvery,
		dayOfWeek, dayOfMonth, nextDue, reminderDays, time.Now(), time.Now())
	if err != nil {
		log.Printf("Error creating time card: %v", err)
		http.Redirect(w, r, "/timecards?error=server_error", http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, "/timecards?success=timecard_created", http.StatusSeeOther)
}

// UpdateTimeCardHandler updates an existing time card
func UpdateTimeCardHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/timecards?error=invalid_method", http.StatusSeeOther)
		return
	}

	user := middleware.GetCurrentUser(r)
	timeCardIDStr := r.FormValue("timecard_id")
	timeCardID, err := strconv.Atoi(timeCardIDStr)
	if err != nil {
		http.Redirect(w, r, "/timecards?error=invalid_timecard_id", http.StatusSeeOther)
		return
	}

	action := r.FormValue("action")

	// Verify ownership
	var ownerID int
	err = db.DB.QueryRow("SELECT user_id FROM time_cards WHERE id = ?", timeCardID).Scan(&ownerID)
	if err != nil {
		http.Redirect(w, r, "/timecards?error=timecard_not_found", http.StatusSeeOther)
		return
	}
	if ownerID != user.ID {
		http.Redirect(w, r, "/timecards?error=unauthorized", http.StatusSeeOther)
		return
	}

	switch action {
	case "edit":
		title := strings.TrimSpace(r.FormValue("title"))
		description := strings.TrimSpace(r.FormValue("description"))
		sendSMS := r.FormValue("send_sms") == "on"
		sendEmail := r.FormValue("send_email") == "on"
		repeatType := r.FormValue("repeat_type")
		repeatEveryStr := r.FormValue("repeat_every")
		dayOfWeekStr := r.FormValue("day_of_week")
		dayOfMonthStr := r.FormValue("day_of_month")
		reminderDaysStr := r.FormValue("reminder_days")

		if title == "" {
			http.Redirect(w, r, "/timecards?error=title_required", http.StatusSeeOther)
			return
		}

		if repeatType != "weekly" && repeatType != "monthly" && repeatType != "yearly" {
			http.Redirect(w, r, "/timecards?error=invalid_repeat_type", http.StatusSeeOther)
			return
		}

		repeatEvery := 1
		if repeatEveryStr != "" {
			repeatEvery, err = strconv.Atoi(repeatEveryStr)
			if err != nil || repeatEvery < 1 || repeatEvery > 100 {
				http.Redirect(w, r, "/timecards?error=invalid_repeat_every", http.StatusSeeOther)
				return
			}
		}

		dayOfWeek := 0
		if dayOfWeekStr != "" {
			dayOfWeek, err = strconv.Atoi(dayOfWeekStr)
			if err != nil || dayOfWeek < 0 || dayOfWeek > 6 {
				http.Redirect(w, r, "/timecards?error=invalid_day_of_week", http.StatusSeeOther)
				return
			}
		}

		dayOfMonth := 1
		if dayOfMonthStr != "" {
			dayOfMonth, err = strconv.Atoi(dayOfMonthStr)
			if err != nil || dayOfMonth < 1 || dayOfMonth > 31 {
				http.Redirect(w, r, "/timecards?error=invalid_day_of_month", http.StatusSeeOther)
				return
			}
		}

		reminderDays := 0
		if reminderDaysStr != "" {
			reminderDays, err = strconv.Atoi(reminderDaysStr)
			if err != nil || reminderDays < 0 || reminderDays > 10 {
				http.Redirect(w, r, "/timecards?error=invalid_reminder_days", http.StatusSeeOther)
				return
			}
		}

		nextDue := calculateNextDue(repeatType, repeatEvery, dayOfWeek, dayOfMonth)

		_, err = db.DB.Exec(`
			UPDATE time_cards 
			SET title = ?, description = ?, send_sms = ?, send_email = ?, 
			    repeat_type = ?, repeat_every = ?, day_of_week = ?, day_of_month = ?, 
			    next_due = ?, reminder_days = ?, updated_at = ?
			WHERE id = ?
		`, title, description, sendSMS, sendEmail, repeatType, repeatEvery,
			dayOfWeek, dayOfMonth, nextDue, reminderDays, time.Now(), timeCardID)

	case "toggle_active":
		_, err = db.DB.Exec(`
			UPDATE time_cards SET is_active = NOT is_active, updated_at = ? WHERE id = ?
		`, time.Now(), timeCardID)

	case "complete":
		// Mark task as completed and log it
		var repeatType string
		var repeatEvery, dayOfWeek, dayOfMonth int
		err = db.DB.QueryRow(`
			SELECT repeat_type, repeat_every, day_of_week, day_of_month 
			FROM time_cards WHERE id = ?
		`, timeCardID).Scan(&repeatType, &repeatEvery, &dayOfWeek, &dayOfMonth)

		if err != nil {
			http.Redirect(w, r, "/timecards?error=server_error", http.StatusSeeOther)
			return
		}

		// Log the completion
		_, err = db.DB.Exec(`
			INSERT INTO time_card_logs (time_card_id, user_id, log_type, message, created_at)
			VALUES (?, ?, 'completed', 'Task marked as completed', ?)
		`, timeCardID, user.ID, time.Now())

		if err != nil {
			log.Printf("Error logging completion: %v", err)
		}

		// Calculate next due date and reset reminder counters
		nextDue := calculateNextDue(repeatType, repeatEvery, dayOfWeek, dayOfMonth)
		_, err = db.DB.Exec(`
			UPDATE time_cards 
			SET next_due = ?, last_sent = NULL, reminder_count = 0, last_reminder_sent = NULL, updated_at = ?
			WHERE id = ?
		`, nextDue, time.Now(), timeCardID)

	case "delete":
		_, err = db.DB.Exec("DELETE FROM time_cards WHERE id = ?", timeCardID)

	default:
		http.Redirect(w, r, "/timecards?error=invalid_action", http.StatusSeeOther)
		return
	}

	if err != nil {
		log.Printf("Error updating time card: %v", err)
		http.Redirect(w, r, "/timecards?error=server_error", http.StatusSeeOther)
		return
	}

	// Use different success message for completion
	successMsg := "timecard_updated"
	if action == "complete" {
		successMsg = "timecard_completed"
	}
	http.Redirect(w, r, "/timecards?success="+successMsg, http.StatusSeeOther)
}

// calculateNextDue calculates the next due date based on repeat settings
func calculateNextDue(repeatType string, repeatEvery, dayOfWeek, dayOfMonth int) time.Time {
	now := time.Now()

	switch repeatType {
	case "weekly":
		// Find next occurrence of the specified day of week
		daysUntil := (dayOfWeek - int(now.Weekday()) + 7) % 7
		if daysUntil == 0 {
			daysUntil = 7 * repeatEvery
		}
		return now.AddDate(0, 0, daysUntil)

	case "monthly":
		// Find next occurrence of the specified day of month
		nextMonth := now
		if now.Day() >= dayOfMonth {
			nextMonth = now.AddDate(0, repeatEvery, 0)
		}
		return time.Date(nextMonth.Year(), nextMonth.Month(), dayOfMonth, 0, 0, 0, 0, now.Location())

	case "yearly":
		// Next year, same month and day
		nextYear := now.AddDate(1, 0, 0)
		return time.Date(nextYear.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())

	default:
		return now
	}
}
