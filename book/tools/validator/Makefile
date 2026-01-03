CC = gcc
CFLAGS = -Wall -Wextra -O2
SRC_DIR = src
BIN_DIR = bin
SB_VALIDATOR = $(BIN_DIR)/sb_validator
WAIT_HELPER = $(BIN_DIR)/wait_helper

# Source files
SB_VALIDATOR_SOURCES = $(SRC_DIR)/main.c
WAIT_HELPER_SOURCES = $(SRC_DIR)/wait_helper.c

# Object files
SB_VALIDATOR_OBJECTS = $(SB_VALIDATOR_SOURCES:$(SRC_DIR)/%.c=$(BIN_DIR)/%.o)
WAIT_HELPER_OBJECTS = $(WAIT_HELPER_SOURCES:$(SRC_DIR)/%.c=$(BIN_DIR)/%.o)

# Entitlements files
DEBUG_ENT = $(SRC_DIR)/debug.ent
GTA_ENT = $(SRC_DIR)/gta.ent

# Default target
all: $(SB_VALIDATOR) $(WAIT_HELPER)

# Link sb_validator and codesign with debug.ent
$(SB_VALIDATOR): $(SB_VALIDATOR_OBJECTS)
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $^
	chmod +x $@
	codesign -s - -f --entitlements $(DEBUG_ENT) $@

# Link wait_helper and codesign with gta.ent
$(WAIT_HELPER): $(WAIT_HELPER_OBJECTS)
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $^
	chmod +x $@
	codesign -s - -f --entitlements $(GTA_ENT) $@

# Compile source files to object files
$(BIN_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

# Clean build artifacts
clean:
	rm -rf $(BIN_DIR)

# Phony targets
.PHONY: all clean
