# Janus build file.
#
# Usage:
#   make         build the release binary (./janus)
#   make debug   build with debug info and sanitizers (./janus-debug)
#   make test    build, then run tests/run_tests.sh
#   make clean   remove all build output

CC      := gcc
CFLAGS  := -std=c11 -Wall -Wextra -Wpedantic -D_POSIX_C_SOURCE=200809L

# Release build: optimized, no debug info.
RELEASE_FLAGS := -O2

# Debug build: debug symbols, no optimization, and runtime checkers
# for memory errors (address) and undefined behavior (undefined).
DEBUG_FLAGS := -g -O0 -fsanitize=address,undefined -fno-omit-frame-pointer

SRC_DIR   := src
BUILD_DIR := build

# Every .c file in src/ is compiled automatically, so new modules
# (scanner.c, cli.c, ...) do not need Makefile changes.
SOURCES := $(wildcard $(SRC_DIR)/*.c)

RELEASE_OBJS := $(SOURCES:$(SRC_DIR)/%.c=$(BUILD_DIR)/release/%.o)
DEBUG_OBJS   := $(SOURCES:$(SRC_DIR)/%.c=$(BUILD_DIR)/debug/%.o)

TARGET       := janus
DEBUG_TARGET := janus-debug

# These targets are commands, not files, so make must always run them.
.PHONY: all debug clean test

all: $(TARGET)

debug: $(DEBUG_TARGET)

# Link step: combine object files into the final executable.
$(TARGET): $(RELEASE_OBJS)
	$(CC) $(CFLAGS) $(RELEASE_FLAGS) $^ -o $@

$(DEBUG_TARGET): $(DEBUG_OBJS)
	$(CC) $(CFLAGS) $(DEBUG_FLAGS) $^ -o $@

# Compile step: one .c file -> one .o file.
# -MMD -MP write a .d file listing the headers each .c includes,
# so editing a header triggers a rebuild of the files that use it.
$(BUILD_DIR)/release/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)/release
	$(CC) $(CFLAGS) $(RELEASE_FLAGS) -MMD -MP -c $< -o $@

$(BUILD_DIR)/debug/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)/debug
	$(CC) $(CFLAGS) $(DEBUG_FLAGS) -MMD -MP -c $< -o $@

# Create output directories on demand.
$(BUILD_DIR)/release $(BUILD_DIR)/debug:
	mkdir -p $@

# Small C helper that unit-tests the JSON escaping in output.c.
JSON_TEST := $(BUILD_DIR)/test_json_escape
LIB_SOURCES := $(filter-out $(SRC_DIR)/main.c $(SRC_DIR)/output.c,$(SOURCES))

$(JSON_TEST): tests/test_json_escape.c $(SOURCES) | $(BUILD_DIR)/release
	$(CC) $(CFLAGS) -I$(SRC_DIR) tests/test_json_escape.c $(LIB_SOURCES) -o $@

test: $(TARGET) $(JSON_TEST)
	JSON_TEST=$(JSON_TEST) ./tests/run_tests.sh

clean:
	rm -rf $(BUILD_DIR) $(TARGET) $(DEBUG_TARGET)

# Pull in the generated header dependency files (ignored if missing).
-include $(RELEASE_OBJS:.o=.d) $(DEBUG_OBJS:.o=.d)
