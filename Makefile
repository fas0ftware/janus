# Janus build file.
#
# Usage:
#   make         build the release binary (./janus)
#   make debug   build with debug info and sanitizers (./janus-debug)
#   make test    build, then run tests/run_tests.sh
#   make check   run the tests again under ASan/UBSan, valgrind and TSan
#   make clean   remove all build output

CC      := gcc
# -pthread enables POSIX threads for both compiling and linking.
CFLAGS  := -std=c11 -Wall -Wextra -Wpedantic -D_POSIX_C_SOURCE=200809L -pthread

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
.PHONY: all debug clean test check test-debug memcheck tsan

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

# Unit tests for target lists, CIDR expansion and banner sanitizing.
TARGETS_TEST := $(BUILD_DIR)/test_targets
$(TARGETS_TEST): tests/test_targets.c $(SOURCES) | $(BUILD_DIR)/release
	$(CC) $(CFLAGS) -g -fsanitize=address,undefined -I$(SRC_DIR) tests/test_targets.c $(LIB_SOURCES) -o $@

# Unit tests for the UDP probe payloads.
UDP_TEST := $(BUILD_DIR)/test_udp
$(UDP_TEST): tests/test_udp.c $(SOURCES) | $(BUILD_DIR)/release
	$(CC) $(CFLAGS) -g -fsanitize=address,undefined -I$(SRC_DIR) tests/test_udp.c $(LIB_SOURCES) -o $@

# Unit tests for --sv: service fingerprints and the probes Janus sends.
FINGERPRINT_TEST := $(BUILD_DIR)/test_fingerprint
$(FINGERPRINT_TEST): tests/test_fingerprint.c $(SOURCES) | $(BUILD_DIR)/release
	$(CC) $(CFLAGS) -g -fsanitize=address,undefined -I$(SRC_DIR) tests/test_fingerprint.c $(LIB_SOURCES) -o $@

test: $(TARGET) $(JSON_TEST) $(TARGETS_TEST) $(UDP_TEST) $(FINGERPRINT_TEST)
	./$(TARGETS_TEST)
	./$(UDP_TEST)
	./$(FINGERPRINT_TEST)
	JSON_TEST=$(JSON_TEST) ./tests/run_tests.sh

# --- Hardening checks ---------------------------------------------------------

# Whole test suite against the AddressSanitizer/UBSan build.
test-debug: $(DEBUG_TARGET)
	JANUS_BINARY=./$(DEBUG_TARGET) ./tests/run_tests.sh

# Valgrind: any leak or memory error makes the command fail (exit code 99).
VALGRIND := valgrind --leak-check=full --show-leak-kinds=all \
            --errors-for-leak-kinds=all --error-exitcode=99 -q
memcheck: $(TARGET)
	$(VALGRIND) ./$(TARGET) -t 127.0.0.1 -p 1-2000 --threads 16 > /dev/null
	$(VALGRIND) ./$(TARGET) -t localhost -p 22,80,443 --json > /dev/null
	$(VALGRIND) ./$(TARGET) -t 127.0.0.1 -p 0 2> /dev/null; test $$? -eq 2
	$(VALGRIND) ./$(TARGET) -t 127.0.0.0/28,::1 -p 22,80 --banner --json > /dev/null
	$(VALGRIND) ./$(TARGET) -t 10.0.0.0/8 2> /dev/null; test $$? -eq 2
	$(VALGRIND) ./$(TARGET) -t 127.0.0.0/28,::1,no-such-host.invalid -p 22,80 --discover --timeout 200 --json > /dev/null
	$(VALGRIND) ./$(TARGET) -t 127.0.0.0/29 -p 22 --discover-ports 1,2,3 --timeout 200 > /dev/null
	$(VALGRIND) ./$(TARGET) -t 127.0.0.0/29 --udp -p 53,123,161 --timeout 200 --json > /dev/null
	$(VALGRIND) ./$(TARGET) -t 127.0.0.1 --udp --banner 2> /dev/null; test $$? -eq 2
	$(VALGRIND) ./$(TARGET) -t 127.0.0.0/30,::1 -p 22,80,443,631,8000 --sv --banner --timeout 300 --json > /dev/null
	$(VALGRIND) ./$(TARGET) -t 127.0.0.1 --udp --sv --timeout 200 > /dev/null
	@echo "valgrind: no leaks or memory errors"

# ThreadSanitizer finds data races between threads. It cannot be combined
# with AddressSanitizer, so it gets its own binary.
TSAN_TARGET := $(BUILD_DIR)/janus-tsan
$(TSAN_TARGET): $(SOURCES) | $(BUILD_DIR)/release
	$(CC) $(CFLAGS) -g -O1 -fsanitize=thread $(SOURCES) -o $@
tsan: $(TSAN_TARGET)
	./$(TSAN_TARGET) -t 127.0.0.1 -p 1-3000 --threads 64 > /dev/null
	./$(TSAN_TARGET) -t 127.0.0.0/29 --top-ports 100 --banner --threads 32 > /dev/null
	./$(TSAN_TARGET) -t 127.0.0.0/29 --udp --threads 32 --timeout 200 > /dev/null
	./$(TSAN_TARGET) -t 127.0.0.0/29 --top-ports 100 --sv --threads 32 --timeout 300 > /dev/null
	./$(TSAN_TARGET) -t 127.0.0.0/26 -p 22,80 --discover --discover-ports 22,80,443,445 --threads 64 > /dev/null
	@echo "tsan: no data races reported"

check: test-debug memcheck tsan

clean:
	rm -rf $(BUILD_DIR) $(TARGET) $(DEBUG_TARGET)

# Pull in the generated header dependency files (ignored if missing).
-include $(RELEASE_OBJS:.o=.d) $(DEBUG_OBJS:.o=.d)
