# Task Completion and Reminder System

## Overview
This document describes the task completion tracking and reminder system implemented in the Time Wheel application.

## Features Implemented

### 1. **Task Completion Logging**
- Every time a task reminder is sent, a log entry is added to the `time_card_logs` table
- When a task is marked as completed, a completion entry is logged
- When a reminder is sent (for uncompleted tasks), a reminder_sent entry is logged

### 2. **Completion Checkbox**
- Time card titles now display as checkboxes instead of plain text
- Checking the box immediately marks the task as completed
- Upon completion:
  - Logs the completion to `time_card_logs` table
  - Calculates the next due date based on the repeat pattern
  - Resets `last_sent` and `reminder_sent` timestamps to NULL
  - Updates `next_due` and `updated_at` timestamps

### 3. **Daily Reminder System**
- Each time card has an optional `reminder_days` field (0-10)
- This specifies the **maximum number of daily reminders** to send
- If set to 0, no reminders are sent
- If set to 1-10, the system will send up to that many daily reminders if the task remains uncompleted
- Example: `reminder_days = 5` means send up to 5 daily reminders after initial notification

### 4. **Database Schema**

#### time_cards table additions:
```sql
reminder_days INTEGER DEFAULT 0 CHECK(reminder_days >= 0 AND reminder_days <= 10)
reminder_count INTEGER DEFAULT 0 CHECK(reminder_count >= 0)
last_reminder_sent DATETIME
```

#### New time_card_logs table:
```sql
CREATE TABLE IF NOT EXISTS time_card_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    time_card_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    log_type TEXT NOT NULL CHECK(log_type IN ('sent', 'completed', 'reminder_sent')),
    message TEXT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (time_card_id) REFERENCES time_cards(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
)
```

#### Indexes:
- `idx_time_card_logs_card` on time_card_id
- `idx_time_card_logs_user` on user_id
- `idx_time_card_logs_type` on log_type

## User Interface
### Creating/Editing Time Cards
- Added "Maximum daily reminders" field in both create and edit modals
- Input range: 0-10
- Hint text explains: "Send up to N daily reminders if task not completed (0 = no reminders)"
- Hint text explains: "If task is not completed, send another reminder after N days (0 = no reminder)"

### Dashboard & Time Cards Page
- Time card titles are now clickable checkboxes
- Clicking the checkbox submits a form that marks the task as completed
- Success message: "Task marked as completed! Next occurrence scheduled."
- Event propagation is managed to prevent checkbox clicks from triggering card expansion

## How It Works

### Task Completion Workflow
1. User clicks the checkbox next to a task title
2. Form submits with `action=complete` and `timecard_id`
3. Handler:
   - Fetches repeat settings (repeat_type, repeat_every, etc.)
   - Logs completion to `time_card_logs` with `log_type='completed'`
   - Calculates next due date using `calculateNextDue()` function
   - Resets `last_sent`, `reminder_count` to 0, and `last_reminder_sent` to NULL
   - Updates `next_due` and `updated_at`
4. Redirects with success message

### Reminder Logic (To Be Implemented)
The background notification service should:

1. **Check for Due Tasks:**
   ```sql
   SELECT * FROM time_cards 
   WHERE next_due <= datetime('now') 
   AND last_sent IS NULL 
   AND is_active = 1
   ```
   - Send SMS/Email based on `send_sms` and `send_email` flags
   - Log to `time_card_logs` with `log_type='sent'`
   - Set `last_sent = NOW()`

2. **Check for Daily Reminder Tasks:**
   ```sql
   SELECT * FROM time_cards 
   WHERE last_sent IS NOT NULL 
   AND reminder_days > 0 
   AND reminder_count < reminder_days
   AND (last_reminder_sent IS NULL OR date(last_reminder_sent) < date('now'))
   AND is_active = 1
   ```
   - Check if task was completed since `last_sent` by querying `time_card_logs`:
     ```sql
     SELECT COUNT(*) FROM time_card_logs 
     WHERE time_card_id = ? 
     AND log_type = 'completed' 
     AND created_at > ?
     ```
   - If NOT completed:
     * Send reminder SMS/Email
     * Increment `reminder_count` by 1
     * Log to `time_card_logs` with `log_type='reminder_sent'`
     * Set `last_reminder_sent = NOW()`
   - Reminders continue daily until either:
     * Task is completed, OR
     * `reminder_count` reaches `reminder_days` limit

## Error Messages

### Create/Edit Errors:
- `invalid_reminder_days`: "Reminder days must be between 0 and 10."

### Success Messages:
- `timecard_completed`: "Task marked as completed! Next occurrence scheduled."

## Code Locations

### Database Schema:
- `db/database.go` - Schema definition and migrations

### Models:
- `models/timecard.go` - TimeCard and TimeCardLog structs

### Handlers:
- `handlers/timecard.go` - CRUD operations and completion logic
- `handlers/auth.go` - Dashboard handler with time card queries

### Templates:
- `templates/timecards.html` - Time card management page with checkboxes and reminder fields
- `templates/dashboard.html` - Dashboard with completion checkboxes on expandable cards

## Pending Implementation

### Background Notification Service
A background service/goroutine needs to be implemented to:
1. Periodically check for due tasks (every minute or configurable interval)
2. Send SMS/Email notifications when tasks are due
3. Check for tasks needing reminders (based on `reminder_days`)
4. Send reminder notifications for uncompleted tasks
5. Log all notification events to `time_card_logs`

### SMS/Email Integration
Actual SMS/Email sending needs to be implemented using:
- SMS: Twilio, AWS SNS, or similar service
- Email: SendGrid, AWS SES, SMTP, or similar service

### Log Viewer
A UI component to display completion history for users:
- Show all log entries for a time card
- Filter by log_type (sent, completed, reminder_sent)
- Display timestamps and messages

## Testing Recommendations

1. **Create a time card with reminder_days = 1**
2. **Mark it as completed** - Verify:
   - Log entry in `time_card_logs` with log_type='completed'
   - `next_due` is calculated correctly
   - `last_sent` and `reminder_sent` are NULL
   - Success message displays

3. **Create a time card with reminder_days = 0** - Verify:
   - No reminders should be sent even if task not completed

4. **Create a time card with reminder_days = 3** - Verify:
### Maximum Reminders Limit
Currently configured as 0-10 daily reminders. To change:
1. Update CHECK constraint in `db/database.go`
2. Update validation in `handlers/timecard.go`
3. Update input `max` attribute in templates

### Daily Reminder Behavior
- Reminders are sent **once per day** (checked by comparing date, not datetime)
- Counter increments with each reminder sent
- Stops automatically when limit reached or task completed
- Setting to 0 disables reminders entirely

### Log Types
Currently supports: 'sent', 'completed', 'reminder_sent'
To add new log types, update CHECK constraint in database schema.
3. Update input `max` attribute in templates

### Log Types
Currently supports: 'sent', 'completed', 'reminder_sent'
To add new log types, update CHECK constraint in database schema.
