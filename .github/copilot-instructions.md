# Copilot Instructions for Time Wheel Project

## Build and Run Commands

Always use WSL (Windows Subsystem for Linux) for running Go commands in this project.

### Why WSL is Required

This project uses `mattn/go-sqlite3`, which requires CGO (C bindings). CGO is not available in native Windows Go toolchain without additional setup. WSL provides a Linux environment where CGO works out of the box.

### Commands

**Build:**
```bash
wsl bash -c "cd /mnt/c/Users/josh/Docs/lab/timewheel && go build"
```

**Run:**
```bash
wsl bash -c "cd /mnt/c/Users/josh/Docs/lab/timewheel && go run main.go"
```

**Test:**
```bash
wsl bash -c "cd /mnt/c/Users/josh/Docs/lab/timewheel && go test ./..."
```

**Install Dependencies:**
```bash
wsl bash -c "cd /mnt/c/Users/josh/Docs/lab/timewheel && go mod download"
wsl bash -c "cd /mnt/c/Users/josh/Docs/lab/timewheel && go mod tidy"
```

### Important Notes

- Do NOT use native Windows `go` commands for this project
- Always run Go commands through `wsl bash -c`
- The WSL path conversion: `C:\Users\josh\Docs\lab\timewheel` → `/mnt/c/Users/josh/Docs/lab/timewheel`
