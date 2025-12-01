package models

import "time"

// TimeCard represents a recurring task/reminder
type TimeCard struct {
	ID               int        `json:"id"`
	UserID           int        `json:"user_id"`
	Title            string     `json:"title"`
	Description      string     `json:"description"`
	SendSMS          bool       `json:"send_sms"`
	SendEmail        bool       `json:"send_email"`
	RepeatType       string     `json:"repeat_type"`  // "weekly", "monthly", "yearly"
	RepeatEvery      int        `json:"repeat_every"` // 1-100 for weeks/months
	DayOfWeek        int        `json:"day_of_week"`  // 0=Sunday, 6=Saturday (for weekly)
	DayOfMonth       int        `json:"day_of_month"` // 1-31 (for monthly)
	NextDue          time.Time  `json:"next_due"`
	LastSent         *time.Time `json:"last_sent,omitempty"`
	ReminderDays     int        `json:"reminder_days"`                // Maximum number of daily reminders (0-10)
	ReminderCount    int        `json:"reminder_count"`               // How many reminders have been sent
	LastReminderSent *time.Time `json:"last_reminder_sent,omitempty"` // When the last reminder was sent
	IsActive         bool       `json:"is_active"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
}

// TimeCardResponse is the response format for time card data
type TimeCardResponse struct {
	ID               int        `json:"id"`
	Title            string     `json:"title"`
	Description      string     `json:"description"`
	SendSMS          bool       `json:"send_sms"`
	SendEmail        bool       `json:"send_email"`
	RepeatType       string     `json:"repeat_type"`
	RepeatEvery      int        `json:"repeat_every"`
	DayOfWeek        int        `json:"day_of_week"`
	DayOfMonth       int        `json:"day_of_month"`
	NextDue          time.Time  `json:"next_due"`
	LastSent         *time.Time `json:"last_sent,omitempty"`
	ReminderDays     int        `json:"reminder_days"`
	ReminderCount    int        `json:"reminder_count"`
	LastReminderSent *time.Time `json:"last_reminder_sent,omitempty"`
	IsActive         bool       `json:"is_active"`
	CreatedAt        time.Time  `json:"created_at"`
}

// TimeCardLog represents a log entry for time card events
type TimeCardLog struct {
	ID         int       `json:"id"`
	TimeCardID int       `json:"time_card_id"`
	UserID     int       `json:"user_id"`
	LogType    string    `json:"log_type"` // "sent", "completed", "reminder_sent"
	Message    string    `json:"message"`
	CreatedAt  time.Time `json:"created_at"`
}

// GetDayOfWeekName returns the day name for the day of week
func (tc *TimeCard) GetDayOfWeekName() string {
	days := []string{"Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"}
	if tc.DayOfWeek >= 0 && tc.DayOfWeek < len(days) {
		return days[tc.DayOfWeek]
	}
	return "Sunday"
}

// GetRepeatDescription returns a human-readable description of the repeat pattern
func (tc *TimeCard) GetRepeatDescription() string {
	switch tc.RepeatType {
	case "weekly":
		if tc.RepeatEvery == 1 {
			return "Every " + tc.GetDayOfWeekName()
		}
		return "Every " + string(rune(tc.RepeatEvery)) + " weeks on " + tc.GetDayOfWeekName()
	case "monthly":
		if tc.RepeatEvery == 1 {
			return "Monthly on day " + string(rune(tc.DayOfMonth))
		}
		return "Every " + string(rune(tc.RepeatEvery)) + " months on day " + string(rune(tc.DayOfMonth))
	case "yearly":
		return "Yearly"
	default:
		return "Unknown"
	}
}
