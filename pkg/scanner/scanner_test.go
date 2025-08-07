package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestNewScanner tests scanner creation
func TestNewScanner(t *testing.T) {
	tests := []struct {
		name      string
		targetURL string
		verbose   bool
		threads   int
		timeout   int
		userAgent string
		wantErr   bool
	}{
		{
			name:      "valid URL",
			targetURL: "https://example.com",
			verbose:   true,
			threads:   5,
			timeout:   30,
			userAgent: "GhostScan/1.0",
			wantErr:   false,
		},
		{
			name:      "invalid URL",
			targetURL: "not-a-url",
			verbose:   false,
			threads:   1,
			timeout:   10,
			userAgent: "Test",
			wantErr:   true,
		},
		{
			name:      "empty URL",
			targetURL: "",
			verbose:   false,
			threads:   1,
			timeout:   10,
			userAgent: "Test",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner, err := NewScanner(tt.targetURL, tt.verbose, tt.threads, tt.timeout, tt.userAgent)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewScanner() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if scanner == nil {
					t.Error("NewScanner() returned nil scanner")
				}
				if scanner.targetURL != tt.targetURL {
					t.Errorf("NewScanner() targetURL = %v, want %v", scanner.targetURL, tt.targetURL)
				}
				if scanner.verbose != tt.verbose {
					t.Errorf("NewScanner() verbose = %v, want %v", scanner.verbose, tt.verbose)
				}
			}
		})
	}
}

// TestDetectGhost tests Ghost CMS detection
func TestDetectGhost(t *testing.T) {
	tests := []struct {
		name           string
		responseBody   string
		responseHeader map[string]string
		statusCode     int
		expectedGhost  bool
	}{
		{
			name:         "Ghost meta tag detection",
			responseBody: `<html><head><meta name="generator" content="Ghost 4.48.2"></head></html>`,
			statusCode:   200,
			expectedGhost: true,
		},
		{
			name:           "Ghost header detection",
			responseBody:   `<html><body>Test</body></html>`,
			responseHeader: map[string]string{"X-Ghost-Cache": "miss"},
			statusCode:     200,
			expectedGhost:  true,
		},
		{
			name:         "No Ghost detection",
			responseBody: `<html><head><meta name="generator" content="WordPress 5.8"></head></html>`,
			statusCode:   200,
			expectedGhost: false,
		},
		{
			name:         "Ghost API endpoint",
			responseBody: `{"version":"4.48.2","environment":"production"}`,
			statusCode:   200,
			expectedGhost: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Set headers
				for key, value := range tt.responseHeader {
					w.Header().Set(key, value)
				}
				w.WriteHeader(tt.statusCode)
				w.Write([]byte(tt.responseBody))
			}))
			defer server.Close()

			// Create scanner
			scanner, err := NewScanner(server.URL, false, 1, 10, "Test")
			if err != nil {
				t.Fatalf("Failed to create scanner: %v", err)
			}

			// Test detection
			result := &ScanResult{}
			ctx := context.Background()
			isGhost, err := scanner.detectGhost(ctx, result)
			if err != nil {
				t.Fatalf("detectGhost() error = %v", err)
			}

			if isGhost != tt.expectedGhost {
				t.Errorf("detectGhost() = %v, want %v", isGhost, tt.expectedGhost)
			}
		})
	}
}

// TestDetectVersion tests version detection
func TestDetectVersion(t *testing.T) {
	tests := []struct {
		name            string
		responseBody    string
		expectedVersion string
		expectError     bool
	}{
		{
			name:            "Version from meta tag",
			responseBody:    `<html><head><meta name="generator" content="Ghost 4.48.2"></head></html>`,
			expectedVersion: "4.48.2",
			expectError:     false,
		},
		{
			name:            "Version from API",
			responseBody:    `{"version":"5.0.0","environment":"production"}`,
			expectedVersion: "5.0.0",
			expectError:     false,
		},
		{
			name:         "No version found",
			responseBody: `<html><body>No version info</body></html>`,
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(200)
				w.Write([]byte(tt.responseBody))
			}))
			defer server.Close()

			// Create scanner
			scanner, err := NewScanner(server.URL, false, 1, 10, "Test")
			if err != nil {
				t.Fatalf("Failed to create scanner: %v", err)
			}

			// Test version detection
			ctx := context.Background()
			version, err := scanner.detectVersion(ctx)
			if tt.expectError {
				if err == nil {
					t.Error("detectVersion() expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("detectVersion() error = %v", err)
				}
				if version != tt.expectedVersion {
					t.Errorf("detectVersion() = %v, want %v", version, tt.expectedVersion)
				}
			}
		})
	}
}

// TestScannerOptions tests scanner options
func TestScannerOptions(t *testing.T) {
	options := DefaultScannerOptions()
	if options.Threads <= 0 {
		t.Error("Default threads should be > 0")
	}
	if options.Timeout <= 0 {
		t.Error("Default timeout should be > 0")
	}
	if options.UserAgent == "" {
		t.Error("Default user agent should not be empty")
	}
}

// TestScannerMethods tests scanner getter/setter methods
func TestScannerMethods(t *testing.T) {
	scanner, err := NewScanner("https://example.com", false, 5, 30, "Test")
	if err != nil {
		t.Fatalf("Failed to create scanner: %v", err)
	}

	// Test verbose
	scanner.SetVerbose(true)
	if !scanner.IsVerbose() {
		t.Error("SetVerbose(true) failed")
	}

	// Test delay
	delay := 2 * time.Second
	scanner.SetDelay(delay)
	if scanner.GetDelay() != delay {
		t.Errorf("SetDelay() = %v, want %v", scanner.GetDelay(), delay)
	}

	// Test random delay
	scanner.SetRandomDelay(true)
	if !scanner.IsRandomDelayEnabled() {
		t.Error("SetRandomDelay(true) failed")
	}

	// Test target
	if scanner.GetTarget() != "https://example.com" {
		t.Errorf("GetTarget() = %v, want %v", scanner.GetTarget(), "https://example.com")
	}

	// Test threads
	if scanner.GetThreads() != 5 {
		t.Errorf("GetThreads() = %v, want %v", scanner.GetThreads(), 5)
	}
}

// TestVersionComparison tests version comparison logic
func TestVersionComparison(t *testing.T) {
	scanner, err := NewScanner("https://example.com", false, 1, 10, "Test")
	if err != nil {
		t.Fatalf("Failed to create scanner: %v", err)
	}

	tests := []struct {
		v1       string
		v2       string
		expected int
	}{
		{"4.48.2", "4.48.1", 1},
		{"4.48.1", "4.48.2", -1},
		{"4.48.2", "4.48.2", 0},
		{"5.0.0", "4.48.2", 1},
		{"4.48.2", "5.0.0", -1},
	}

	for _, tt := range tests {
		t.Run(tt.v1+" vs "+tt.v2, func(t *testing.T) {
			result := scanner.compareVersions(tt.v1, tt.v2)
			if result != tt.expected {
				t.Errorf("compareVersions(%s, %s) = %d, want %d", tt.v1, tt.v2, result, tt.expected)
			}
		})
	}
}

// TestIsVersionAffected tests vulnerability version checking
func TestIsVersionAffected(t *testing.T) {
	scanner, err := NewScanner("https://example.com", false, 1, 10, "Test")
	if err != nil {
		t.Fatalf("Failed to create scanner: %v", err)
	}

	tests := []struct {
		version  string
		affected string
		expected bool
	}{
		{"4.48.2", "<= 4.48.2", true},
		{"4.48.3", "<= 4.48.2", false},
		{"4.48.1", "<= 4.48.2", true},
		{"5.0.0", "< 5.0.0", false},
		{"4.59.9", "< 5.0.0", true},
	}

	for _, tt := range tests {
		t.Run(tt.version+" in "+tt.affected, func(t *testing.T) {
			result := scanner.isVersionAffected(tt.version, tt.affected)
			if result != tt.expected {
				t.Errorf("isVersionAffected(%s, %s) = %t, want %t", tt.version, tt.affected, result, tt.expected)
			}
		})
	}
}

// BenchmarkDetectGhost benchmarks Ghost detection
func BenchmarkDetectGhost(b *testing.B) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Ghost-Cache", "miss")
		w.WriteHeader(200)
		w.Write([]byte(`<html><head><meta name="generator" content="Ghost 4.48.2"></head></html>`))
	}))
	defer server.Close()

	// Create scanner
	scanner, err := NewScanner(server.URL, false, 1, 10, "Test")
	if err != nil {
		b.Fatalf("Failed to create scanner: %v", err)
	}

	ctx := context.Background()
	result := &ScanResult{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := scanner.detectGhost(ctx, result)
		if err != nil {
			b.Fatalf("detectGhost() error = %v", err)
		}
	}
}

// BenchmarkVersionDetection benchmarks version detection
func BenchmarkVersionDetection(b *testing.B) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "api") {
			w.Write([]byte(`{"version":"4.48.2","environment":"production"}`))
		} else {
			w.Write([]byte(`<html><head><meta name="generator" content="Ghost 4.48.2"></head></html>`))
		}
	}))
	defer server.Close()

	// Create scanner
	scanner, err := NewScanner(server.URL, false, 1, 10, "Test")
	if err != nil {
		b.Fatalf("Failed to create scanner: %v", err)
	}

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := scanner.detectVersion(ctx)
		if err != nil {
			b.Fatalf("detectVersion() error = %v", err)
		}
	}
}

// TestScanIntegration tests full scan integration
func TestScanIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Create comprehensive test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("X-Ghost-Cache", "miss")
			w.Write([]byte(`<html><head><meta name="generator" content="Ghost 4.48.2"></head><body>Ghost Blog</body></html>`))
		case "/ghost/api/v4/admin/site/":
			w.Write([]byte(`{"version":"4.48.2","environment":"production"}`))
		case "/rss/":
			w.Write([]byte(`<?xml version="1.0"?><rss><channel><item><author>admin@example.com</author></item></channel></rss>`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer server.Close()

	// Create scanner
	scanner, err := NewScanner(server.URL, true, 2, 10, "GhostScan/Test")
	if err != nil {
		t.Fatalf("Failed to create scanner: %v", err)
	}

	// Run scan
	ctx := context.Background()
	result, err := scanner.Scan(ctx)
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}

	// Verify results
	if !result.IsGhost {
		t.Error("Expected Ghost to be detected")
	}
	if result.Version != "4.48.2" {
		t.Errorf("Expected version 4.48.2, got %s", result.Version)
	}
	if result.Target != server.URL {
		t.Errorf("Expected target %s, got %s", server.URL, result.Target)
	}
}