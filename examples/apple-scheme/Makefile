CC := clang
CFLAGS := -Wall -Wextra -Wpedantic -O2
LDFLAGS := -lsandbox

BUILD_DIR := build
BIN := $(BUILD_DIR)/compile_profile

.PHONY: all clean run-demo

all: $(BIN)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BIN): src/compile_profile.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

run-demo: $(BIN)
	./run-demo.sh

clean:
	rm -rf $(BUILD_DIR)
