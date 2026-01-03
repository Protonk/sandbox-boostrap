# Sandbox Tester

A macOS sandbox filter validation tool that tests sandbox rule enforcement using the `sandbox_check()` API.

## Overview

`sb_validator` is a command-line utility that validates whether a running process has permission to perform specific sandbox operations. It checks sandbox rules by invoking the kernel's `sandbox_check()` function with various filter types.

## Building

```bash
make
```

This builds and codesigns both executables:
- `bin/sb_validator` - The main validation tool (signed with `debug.ent`)
- `bin/wait_helper` - A helper process for testing (signed with `gta.ent`)

## Usage

```bash
./bin/sb_validator <pid> <operation> <filter_type> <filter_value>
```

### Examples

```bash
# Check if process can read a file
./bin/sb_validator $(pgrep wait_helper) "file-read*" PATH "/private/etc/passwd"

# Check mach service access
./bin/sb_validator $(pgrep wait_helper) "mach-lookup" GLOBAL_NAME "com.apple.replayd"

# Check NVRAM variable access
./bin/sb_validator $(pgrep wait_helper) "nvram-get" NVRAM_VARIABLE "boot-args"
```

## Testing

Run the test suite with pytest:

```bash
pytest tests/
```

The tests validate sandbox rule enforcement for various filter types including:
- File paths
- Mach services (global and local)
- AppleEvents
- Authorization rights
- Preferences
- System extensions
- System info queries
- Notifications
- XPC services
- NVRAM variables
- POSIX IPC names

## Supported Filter Types

| ID | Type | Operation |
|----|------|-----------|
| 1 | PATH | file-read*, file-write* |
| 2 | GLOBAL_NAME | mach-lookup |
| 3 | LOCAL_NAME | mach-lookup |
| 4 | APPLEEVENT_DESTINATION | appleevent-send |
| 5 | RIGHT_NAME | authorization-right-obtain |
| 6 | PREFERENCE_DOMAIN | user-preference-read/write |
| 7 | KEXT_BUNDLE_ID | system-kext-* |
| 8 | INFO_TYPE | system-info |
| 9 | NOTIFICATION | distributed-notification-post |
| 12 | XPC_SERVICE_NAME | mach-lookup |
| 15 | NVRAM_VARIABLE | nvram-get/set/delete |
| 17 | POSIX_IPC_NAME | ipc-posix-* |