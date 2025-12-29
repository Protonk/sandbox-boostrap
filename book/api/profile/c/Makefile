# Minimal C probe build for libsandbox compilation (Sonoma baseline).
#
# This produces `build/compile_profile`, a reference implementation of
# `sandbox_compile_file` analogous to the Python bindings under:
# `book/api/profile/compile/libsandbox.py`.
#
# Notes:
# - Links against `-lsandbox` (private; dyld resolves this on-host).
# - Intended for debugging and second-implementation cross-checks, not for
#   general “runtime apply” behavior (which lives elsewhere in the repo).

CC := clang
CFLAGS := -Wall -Wextra -Wpedantic -O2
LDFLAGS := -lsandbox

BUILD_DIR := build
BIN := $(BUILD_DIR)/compile_profile

.PHONY: all clean

all: $(BIN)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BIN): compile_profile.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

clean:
	rm -rf $(BUILD_DIR)
