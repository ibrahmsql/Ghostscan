# GhostScan Makefile

# Variables
APP_NAME := ghostscan
VERSION := 1.0.0
GO_VERSION := 1.21
BUILD_DIR := build
DIST_DIR := dist

# Go build flags
LDFLAGS := -ldflags "-X main.version=$(VERSION) -s -w"
GOFLAGS := -trimpath

# Default target
.PHONY: all
all: clean build

# Build the application
.PHONY: build
build:
	@echo "Building $(APP_NAME) v$(VERSION)..."
	@mkdir -p $(BUILD_DIR)
	go build $(GOFLAGS) $(LDFLAGS) -o $(BUILD_DIR)/$(APP_NAME) .
	@echo "Build complete: $(BUILD_DIR)/$(APP_NAME)"

# Build for multiple platforms
.PHONY: build-all
build-all: clean
	@echo "Building $(APP_NAME) for multiple platforms..."
	@mkdir -p $(DIST_DIR)
	
	# Linux AMD64
	GOOS=linux GOARCH=amd64 go build $(GOFLAGS) $(LDFLAGS) -o $(DIST_DIR)/$(APP_NAME)-linux-amd64 .
	
	# Linux ARM64
	GOOS=linux GOARCH=arm64 go build $(GOFLAGS) $(LDFLAGS) -o $(DIST_DIR)/$(APP_NAME)-linux-arm64 .
	
	# macOS AMD64
	GOOS=darwin GOARCH=amd64 go build $(GOFLAGS) $(LDFLAGS) -o $(DIST_DIR)/$(APP_NAME)-darwin-amd64 .
	
	# macOS ARM64 (Apple Silicon)
	GOOS=darwin GOARCH=arm64 go build $(GOFLAGS) $(LDFLAGS) -o $(DIST_DIR)/$(APP_NAME)-darwin-arm64 .
	
	# Windows AMD64
	GOOS=windows GOARCH=amd64 go build $(GOFLAGS) $(LDFLAGS) -o $(DIST_DIR)/$(APP_NAME)-windows-amd64.exe .
	
	@echo "Multi-platform build complete in $(DIST_DIR)/"

# Install the application
.PHONY: install
install: build
	@echo "Installing $(APP_NAME)..."
	go install $(GOFLAGS) $(LDFLAGS) .
	@echo "Installation complete"

# Run tests
.PHONY: test
test:
	@echo "Running tests..."
	go test -v ./...

# Run tests with coverage
.PHONY: test-coverage
test-coverage:
	@echo "Running tests with coverage..."
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

# Run linter
.PHONY: lint
lint:
	@echo "Running linter..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		echo "golangci-lint not installed. Install with: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; \
	fi

# Format code
.PHONY: fmt
fmt:
	@echo "Formatting code..."
	go fmt ./...
	goimports -w .

# Tidy dependencies
.PHONY: tidy
tidy:
	@echo "Tidying dependencies..."
	go mod tidy
	go mod verify

# Clean build artifacts
.PHONY: clean
clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(BUILD_DIR) $(DIST_DIR)
	rm -f coverage.out coverage.html

# Development setup
.PHONY: dev-setup
dev-setup:
	@echo "Setting up development environment..."
	go mod download
	@echo "Installing development tools..."
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install golang.org/x/tools/cmd/goimports@latest
	@echo "Development setup complete"

# Run the application with sample arguments
.PHONY: run
run: build
	@echo "Running $(APP_NAME) with sample arguments..."
	./$(BUILD_DIR)/$(APP_NAME) --help

# Create release archives
.PHONY: release
release: build-all
	@echo "Creating release archives..."
	@mkdir -p $(DIST_DIR)/archives
	
	# Create tar.gz for Unix systems
	tar -czf $(DIST_DIR)/archives/$(APP_NAME)-$(VERSION)-linux-amd64.tar.gz -C $(DIST_DIR) $(APP_NAME)-linux-amd64
	tar -czf $(DIST_DIR)/archives/$(APP_NAME)-$(VERSION)-linux-arm64.tar.gz -C $(DIST_DIR) $(APP_NAME)-linux-arm64
	tar -czf $(DIST_DIR)/archives/$(APP_NAME)-$(VERSION)-darwin-amd64.tar.gz -C $(DIST_DIR) $(APP_NAME)-darwin-amd64
	tar -czf $(DIST_DIR)/archives/$(APP_NAME)-$(VERSION)-darwin-arm64.tar.gz -C $(DIST_DIR) $(APP_NAME)-darwin-arm64
	
	# Create zip for Windows
	zip -j $(DIST_DIR)/archives/$(APP_NAME)-$(VERSION)-windows-amd64.zip $(DIST_DIR)/$(APP_NAME)-windows-amd64.exe
	
	@echo "Release archives created in $(DIST_DIR)/archives/"

# Generate checksums
.PHONY: checksums
checksums: release
	@echo "Generating checksums..."
	cd $(DIST_DIR)/archives && sha256sum * > checksums.txt
	@echo "Checksums generated: $(DIST_DIR)/archives/checksums.txt"

# Docker build
.PHONY: docker-build
docker-build:
	@echo "Building Docker image..."
	docker build -t $(APP_NAME):$(VERSION) .
	docker tag $(APP_NAME):$(VERSION) $(APP_NAME):latest

# Show help
.PHONY: help
help:
	@echo "GhostScan Build System"
	@echo ""
	@echo "Available targets:"
	@echo "  build        - Build the application for current platform"
	@echo "  build-all    - Build for multiple platforms"
	@echo "  install      - Install the application"
	@echo "  test         - Run tests"
	@echo "  test-coverage- Run tests with coverage report"
	@echo "  lint         - Run linter"
	@echo "  fmt          - Format code"
	@echo "  tidy         - Tidy dependencies"
	@echo "  clean        - Clean build artifacts"
	@echo "  dev-setup    - Setup development environment"
	@echo "  run          - Build and run with sample arguments"
	@echo "  release      - Create release archives"
	@echo "  checksums    - Generate checksums for releases"
	@echo "  docker-build - Build Docker image"
	@echo "  help         - Show this help message"
	@echo ""
	@echo "Variables:"
	@echo "  APP_NAME     = $(APP_NAME)"
	@echo "  VERSION      = $(VERSION)"
	@echo "  GO_VERSION   = $(GO_VERSION)"

# Check Go version
.PHONY: check-go-version
check-go-version:
	@echo "Checking Go version..."
	@go version | grep -q "go$(GO_VERSION)" || (echo "Go $(GO_VERSION) required" && exit 1)

# Verify build works
.PHONY: verify
verify: clean build test lint
	@echo "Verification complete - build, test, and lint passed"

# Quick development cycle
.PHONY: dev
dev: fmt build test
	@echo "Development cycle complete"