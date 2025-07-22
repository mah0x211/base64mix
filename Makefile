# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -Wpedantic -std=c99 \
         -Wformat=2 -Wcast-align -Wconversion -Wdouble-promotion \
         -Wfloat-equal -Wpointer-arith -Wshadow -Wuninitialized \
         -Wunused -Wvla -Wwrite-strings -Wstrict-prototypes \
         -Wmissing-prototypes -Wredundant-decls -Winline \
         -Warray-bounds \
         -fno-common -fstack-protector-strong

# Coverage flags - always enabled for comprehensive testing
COV_FLAGS = --coverage -fprofile-arcs -ftest-coverage

# Address Sanitizer flags
ASAN_FLAGS = -fsanitize=address -fsanitize=undefined -fno-omit-frame-pointer

# Test directory and files
TEST_DIR = test
TEST_SRC = $(TEST_DIR)/test_base64mix.c
TEST_BIN = $(TEST_DIR)/test_base64mix
TEST_OBJ = $(TEST_DIR)/test_base64mix.o

# RFC 4648 compliance proof test
RFC_TEST_SRC = $(TEST_DIR)/test_rfc4648_compliance_proof.c
RFC_TEST_BIN = $(TEST_DIR)/test_rfc4648_compliance_proof

# Benchmark directory and files
BENCH_DIR = bench
BENCH_SRC = $(BENCH_DIR)/benchmark.c
BENCH_BIN = $(BENCH_DIR)/benchmark
BENCH_GO_SRC = $(BENCH_DIR)/benchmark.go
BENCH_RUST_SRC = $(BENCH_DIR)/benchmark.rs

# Coverage output files
COV_FILES = *.gcno *.gcda *.gcov
COV_DIR = coverage
COV_INFO = $(COV_DIR)/coverage.info
COV_HTML = $(COV_DIR)/html

.PHONY: all test test-rfc coverage asan bench bench-c bench-go bench-rust bench-all clean help

# Default target - run tests with coverage
all: test

# Compile and run tests with coverage
test: $(TEST_BIN) test-rfc
	@echo "Running standard tests with coverage..."
	@./$(TEST_BIN)
	@echo "Generating coverage data..."
	@gcov $(TEST_SRC) -o $(TEST_DIR)/
	@echo "Coverage files generated. Run 'make coverage' for HTML report."

# Compile and run RFC 4648 compliance proof test
test-rfc: $(RFC_TEST_BIN)
	@echo "Running RFC 4648 compliance proof test..."
	@./$(RFC_TEST_BIN)

# Compile test binary with coverage flags
$(TEST_BIN): $(TEST_SRC)
	@echo "Compiling tests with coverage support..."
	@$(CC) $(CFLAGS) $(COV_FLAGS) -Wno-sign-conversion -Wno-float-conversion -Wno-implicit-int-conversion -o $(TEST_BIN) $(TEST_SRC)

# Compile RFC 4648 compliance proof test
$(RFC_TEST_BIN): $(RFC_TEST_SRC)
	@echo "Compiling RFC 4648 compliance proof test..."
	@$(CC) $(CFLAGS) $(COV_FLAGS) -Wno-sign-conversion -Wno-float-conversion -Wno-implicit-int-conversion -o $(RFC_TEST_BIN) $(RFC_TEST_SRC)

# Generate HTML coverage report
coverage: test
	@echo "Generating HTML coverage report..."
	@mkdir -p $(COV_DIR)
	@lcov --capture --directory . --output-file $(COV_INFO) 2>/dev/null || echo "lcov not available, using gcov only"
	@if [ -f $(COV_INFO) ]; then \
		lcov --remove $(COV_INFO) '/usr/*' 'test/*' --output-file $(COV_INFO); \
		genhtml $(COV_INFO) --output-directory $(COV_HTML); \
		echo "HTML coverage report generated in $(COV_HTML)/index.html"; \
	else \
		echo "Coverage data available in .gcov files"; \
	fi

# Address Sanitizer build and test
asan: clean
	@echo "Building with Address Sanitizer..."
	@$(CC) $(CFLAGS) $(ASAN_FLAGS) -o $(TEST_BIN)_asan $(TEST_SRC)
	@echo "Running tests with Address Sanitizer..."
	@./$(TEST_BIN)_asan

# Benchmark targets
bench: bench-c
	@echo ""
	@echo "=== Performance Benchmark Summary ==="
	@echo "C benchmark completed. For language comparisons, run:"
	@echo "  make bench-go    # Go standard library comparison"
	@echo "  make bench-rust  # Rust base64 crate comparison"
	@echo "  make bench-all   # Run all benchmarks"

# C benchmark
bench-c: $(BENCH_BIN)
	@echo "Running C base64mix benchmark..."
	@./$(BENCH_BIN)

# Go benchmark
bench-go:
	@echo "Running Go benchmark..."
	@if command -v go >/dev/null 2>&1; then \
		cd $(BENCH_DIR) && go run $(notdir $(BENCH_GO_SRC)); \
	else \
		echo "Go not found. Install Go to run Go benchmarks."; \
		echo "Visit: https://golang.org/dl/"; \
	fi

# Rust benchmark
bench-rust:
	@echo "Running Rust benchmark..."
	@if command -v cargo >/dev/null 2>&1; then \
		cd $(BENCH_DIR) && cargo run --release --bin benchmark 2>&1 || \
		(echo "Rust benchmark failed. This might be due to system configuration issues."; \
		 echo "You can try reinstalling Rust or checking your LLVM configuration."; \
		 echo "Visit: https://rustup.rs/ for Rust installation"; \
		 exit 0); \
	else \
		echo "Rust/Cargo not found. Install Rust to run Rust benchmarks."; \
		echo "Visit: https://rustup.rs/"; \
	fi

# Run all benchmarks
bench-all: bench-c bench-go bench-rust
	@echo ""
	@echo "=== All Benchmarks Completed ==="
	@echo "Compare the results to evaluate base64mix performance"
	@echo "against Go and Rust standard libraries."

# Compile benchmark binary
$(BENCH_BIN): $(BENCH_SRC)
	@echo "Compiling C benchmark..."
	@$(CC) $(CFLAGS) -O3 -DNDEBUG -march=native -mtune=native -funroll-loops -Wno-sign-conversion -Wno-implicit-int-conversion -o $(BENCH_BIN) $(BENCH_SRC)

# Clean all generated files
clean:
	@echo "Cleaning up..."
	@rm -f $(TEST_BIN) $(TEST_BIN)_asan $(TEST_OBJ)
	@rm -f $(RFC_TEST_BIN)
	@rm -f $(BENCH_BIN)
	@rm -f $(COV_FILES)
	@rm -rf $(COV_DIR)
	@find . -name "*.gcno" -delete 2>/dev/null || true
	@find . -name "*.gcda" -delete 2>/dev/null || true
	@find . -name "*.gcov" -delete 2>/dev/null || true
	@cd $(BENCH_DIR) && cargo clean >/dev/null 2>&1 || true

# Help
help:
	@echo "Available targets:"
	@echo "  all        - Compile and run all tests with coverage (default)"
	@echo "  test       - Compile and run all tests with coverage"
	@echo "  test-rfc   - Run RFC 4648 compliance proof test only"
	@echo "  coverage   - Generate HTML coverage report (requires lcov)"
	@echo "  asan       - Build and run tests with Address Sanitizer"
	@echo ""
	@echo "Benchmark targets:"
	@echo "  bench      - Run C base64mix benchmark"
	@echo "  bench-c    - Run C base64mix benchmark only"
	@echo "  bench-go   - Run Go standard library benchmark"
	@echo "  bench-rust - Run Rust base64 crate benchmark"
	@echo "  bench-all  - Run all benchmarks (C, Go, Rust)"
	@echo ""
	@echo "Utility targets:"
	@echo "  clean      - Remove all generated files"
	@echo "  help       - Show this help message"
	@echo ""
	@echo "Coverage is enabled by default for all test builds."
	@echo "Use 'make coverage' to generate HTML reports if lcov is installed."
