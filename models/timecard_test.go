package models

import (
	"testing"
	"time"
)

func TestGetDayOfWeekName(t *testing.T) {
	tests := []struct {
		name      string
		dayOfWeek int
		expected  string
	}{
		{"Sunday", 0, "Sunday"},
		{"Monday", 1, "Monday"},
		{"Tuesday", 2, "Tuesday"},
		{"Wednesday", 3, "Wednesday"},
		{"Thursday", 4, "Thursday"},
		{"Friday", 5, "Friday"},
		{"Saturday", 6, "Saturday"},
		{"Invalid negative", -1, "Sunday"},
		{"Invalid high", 7, "Sunday"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc := &TimeCard{DayOfWeek: tt.dayOfWeek}
			result := tc.GetDayOfWeekName()
			if result != tt.expected {
				t.Errorf("GetDayOfWeekName() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestGetNextDueWeekday(t *testing.T) {
	tests := []struct {
		name     string
		nextDue  time.Time
		expected int
	}{
		{"Sunday", time.Date(2025, 12, 7, 0, 0, 0, 0, time.UTC), 0},
		{"Monday", time.Date(2025, 12, 1, 0, 0, 0, 0, time.UTC), 1},
		{"Tuesday", time.Date(2025, 12, 2, 0, 0, 0, 0, time.UTC), 2},
		{"Wednesday", time.Date(2025, 12, 3, 0, 0, 0, 0, time.UTC), 3},
		{"Thursday", time.Date(2025, 12, 4, 0, 0, 0, 0, time.UTC), 4},
		{"Friday", time.Date(2025, 12, 5, 0, 0, 0, 0, time.UTC), 5},
		{"Saturday", time.Date(2025, 12, 6, 0, 0, 0, 0, time.UTC), 6},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc := &TimeCard{NextDue: tt.nextDue}
			result := tc.GetNextDueWeekday()
			if result != tt.expected {
				t.Errorf("GetNextDueWeekday() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestGetRepeatDescription(t *testing.T) {
	tests := []struct {
		name        string
		repeatType  string
		repeatEvery int
		dayOfWeek   int
		dayOfMonth  int
		expected    string
	}{
		{"Weekly once", "weekly", 1, 1, 0, "Every Monday"},
		{"Weekly multiple", "weekly", 2, 5, 0, "Every " + string(rune(2)) + " weeks on Friday"},
		{"Monthly once", "monthly", 1, 0, 15, "Monthly on day " + string(rune(15))},
		{"Monthly multiple", "monthly", 3, 0, 1, "Every " + string(rune(3)) + " months on day " + string(rune(1))},
		{"Yearly", "yearly", 1, 0, 0, "Yearly"},
		{"Unknown", "unknown", 1, 0, 0, "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc := &TimeCard{
				RepeatType:  tt.repeatType,
				RepeatEvery: tt.repeatEvery,
				DayOfWeek:   tt.dayOfWeek,
				DayOfMonth:  tt.dayOfMonth,
			}
			result := tc.GetRepeatDescription()
			if result != tt.expected {
				t.Errorf("GetRepeatDescription() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestTimeCardStatusConstants(t *testing.T) {
	tests := []struct {
		name     string
		constant string
		expected string
	}{
		{"StatusReady", StatusReady, "READY"},
		{"StatusTriggered", StatusTriggered, "TRIGGERED"},
		{"StatusDoneSuccess", StatusDoneSuccess, "DONE_SUCCESS"},
		{"StatusDoneIgnored", StatusDoneIgnored, "DONE_IGNORED"},
		{"StatusDoneFailed", StatusDoneFailed, "DONE_FAILED"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.constant != tt.expected {
				t.Errorf("%s = %v, want %v", tt.name, tt.constant, tt.expected)
			}
		})
	}
}
