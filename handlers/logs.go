package handlers

import (
	"database/sql"
	"log"
	"net/http"
	"time"

	"github.com/josh/timewheel/db"
	"github.com/josh/timewheel/middleware"
)

// ActivityLog represents a log entry with timecard info
type ActivityLog struct {
	ID            int
	TimeCardID    int
	TimeCardTitle string
	LogType       string
	Message       string
	CreatedAt     time.Time
}

// GetRecentLogsForTimeCard gets the most recent logs for a specific timecard
func GetRecentLogsForTimeCard(timeCardID int, limit int) ([]ActivityLog, error) {
	query := `
		SELECT l.id, l.time_card_id, tc.title, l.log_type, l.message, l.created_at
		FROM time_card_logs l
		JOIN time_cards tc ON l.time_card_id = tc.id
		WHERE l.time_card_id = ?
		ORDER BY l.created_at DESC
		LIMIT ?
	`

	rows, err := db.DB.Query(query, timeCardID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []ActivityLog
	for rows.Next() {
		var activityLog ActivityLog
		err := rows.Scan(&activityLog.ID, &activityLog.TimeCardID, &activityLog.TimeCardTitle,
			&activityLog.LogType, &activityLog.Message, &activityLog.CreatedAt)
		if err != nil {
			continue
		}
		logs = append(logs, activityLog)
	}
	return logs, nil
}

// GetRecentActivityByTimeCard gets the most recent log for each timecard in the last N days
func GetRecentActivityByTimeCard(userID int, days int) ([]ActivityLog, error) {
	cutoff := time.Now().AddDate(0, 0, -days)

	query := `
		SELECT l.id, l.time_card_id, tc.title, l.log_type, l.message, l.created_at
		FROM time_card_logs l
		JOIN time_cards tc ON l.time_card_id = tc.id
		WHERE l.user_id = ?
		AND l.created_at >= ?
		AND l.id IN (
			SELECT MAX(l2.id)
			FROM time_card_logs l2
			WHERE l2.time_card_id = l.time_card_id
			AND l2.created_at >= ?
			GROUP BY l2.time_card_id
		)
		ORDER BY l.created_at DESC
	`

	rows, err := db.DB.Query(query, userID, cutoff, cutoff)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []ActivityLog
	for rows.Next() {
		var activityLog ActivityLog
		err := rows.Scan(&activityLog.ID, &activityLog.TimeCardID, &activityLog.TimeCardTitle,
			&activityLog.LogType, &activityLog.Message, &activityLog.CreatedAt)
		if err != nil {
			continue
		}
		logs = append(logs, activityLog)
	}
	return logs, nil
}

// LogsPageHandler shows the activity logs page
func LogsPageHandler(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetCurrentUser(r)

	// Get query parameters
	searchTitle := r.URL.Query().Get("search")
	startDate := r.URL.Query().Get("start_date")
	endDate := r.URL.Query().Get("end_date")

	// Default to last 7 days if no dates provided
	now := time.Now()
	var start, end time.Time

	if startDate == "" {
		start = now.AddDate(0, 0, -7)
	} else {
		parsedStart, err := time.Parse("2006-01-02", startDate)
		if err != nil {
			start = now.AddDate(0, 0, -7)
		} else {
			start = parsedStart
		}
	}

	if endDate == "" {
		end = now
	} else {
		parsedEnd, err := time.Parse("2006-01-02", endDate)
		if err != nil {
			end = now
		} else {
			// Set to end of day
			end = parsedEnd.Add(23*time.Hour + 59*time.Minute + 59*time.Second)
		}
	}

	// Build query
	query := `
		SELECT l.id, l.time_card_id, tc.title, l.log_type, l.message, l.created_at
		FROM time_card_logs l
		JOIN time_cards tc ON l.time_card_id = tc.id
		WHERE l.user_id = ?
		AND l.created_at BETWEEN ? AND ?
	`
	args := []interface{}{user.ID, start, end}

	// Add title search filter
	if searchTitle != "" {
		query += " AND LOWER(tc.title) LIKE LOWER(?)"
		args = append(args, "%"+searchTitle+"%")
	}

	query += " ORDER BY l.created_at DESC LIMIT 1000"

	// Execute query
	rows, err := db.DB.Query(query, args...)
	if err != nil {
		log.Printf("Error fetching logs: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var logs []ActivityLog
	for rows.Next() {
		var activityLog ActivityLog
		err := rows.Scan(&activityLog.ID, &activityLog.TimeCardID, &activityLog.TimeCardTitle,
			&activityLog.LogType, &activityLog.Message, &activityLog.CreatedAt)
		if err != nil {
			log.Printf("Error scanning log: %v", err)
			continue
		}
		logs = append(logs, activityLog)
	}

	// Get total counts by type for statistics
	var totalCompleted, totalSent, totalReminders int
	countQuery := `
		SELECT 
			SUM(CASE WHEN log_type = 'completed' THEN 1 ELSE 0 END) as completed,
			SUM(CASE WHEN log_type = 'sent' THEN 1 ELSE 0 END) as sent,
			SUM(CASE WHEN log_type = 'reminder_sent' THEN 1 ELSE 0 END) as reminders
		FROM time_card_logs
		WHERE user_id = ? AND created_at BETWEEN ? AND ?
	`
	err = db.DB.QueryRow(countQuery, user.ID, start, end).Scan(&totalCompleted, &totalSent, &totalReminders)
	if err != nil && err != sql.ErrNoRows {
		log.Printf("Error fetching log counts: %v", err)
	}

	data := map[string]interface{}{
		"Title":          "Activity Logs - Time Wheel",
		"Year":           time.Now().Year(),
		"User":           user,
		"ActivePage":     "logs",
		"Logs":           logs,
		"SearchTitle":    searchTitle,
		"StartDate":      start.Format("2006-01-02"),
		"EndDate":        end.Format("2006-01-02"),
		"TotalCompleted": totalCompleted,
		"TotalSent":      totalSent,
		"TotalReminders": totalReminders,
	}

	if err := templates.ExecuteTemplate(w, "logs.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
