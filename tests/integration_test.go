package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ibrahmsql/ghostscan/pkg/scanner"
)

// MockGhostServer represents a mock Ghost CMS server for testing
type MockGhostServer struct {
	server   *httptest.Server
	version  string
	themes   []string
	users    []string
	plugins  []string
	endpoints map[string]interface{}
}

// NewMockGhostServer creates a new mock Ghost server
func NewMockGhostServer(version string) *MockGhostServer {
	mock := &MockGhostServer{
		version: version,
		themes:  []string{"casper", "dawn", "custom-theme"},
		users:   []string{"admin", "editor", "author"},
		plugins: []string{"ghost-storage-adapter", "ghost-newsletter"},
		endpoints: map[string]interface{}{
			"/ghost/api/v4/admin/site/": map[string]interface{}{
				"version":     version,
				"environment": "production",
				"database":    "mysql",
				"mail":        "SMTP",
			},
			"/ghost/api/v4/content/posts/": map[string]interface{}{
				"posts": []map[string]interface{}{
					{"id": "1", "title": "Test Post", "slug": "test-post"},
				},
			},
			"/ghost/api/v4/content/tags/": map[string]interface{}{
				"tags": []map[string]interface{}{
					{"id": "1", "name": "Technology", "slug": "technology"},
				},
			},
		},
	}

	mock.server = httptest.NewServer(http.HandlerFunc(mock.handleRequest))
	return mock
}

// Close closes the mock server
func (m *MockGhostServer) Close() {
	m.server.Close()
}

// URL returns the server URL
func (m *MockGhostServer) URL() string {
	return m.server.URL
}

// handleRequest handles HTTP requests to the mock server
func (m *MockGhostServer) handleRequest(w http.ResponseWriter, r *http.Request) {
	// Set Ghost-specific headers
	w.Header().Set("X-Ghost-Cache", "miss")
	w.Header().Set("X-Powered-By", "Ghost")
	w.Header().Set("Server", "nginx")

	switch {
	case r.URL.Path == "/":
		m.handleHomePage(w, r)
	case strings.HasPrefix(r.URL.Path, "/ghost/api/"):
		m.handleAPIRequest(w, r)
	case r.URL.Path == "/rss/" || r.URL.Path == "/feed/":
		m.handleRSSFeed(w, r)
	case strings.HasPrefix(r.URL.Path, "/content/themes/"):
		m.handleThemeRequest(w, r)
	case r.URL.Path == "/robots.txt":
		m.handleRobotsTxt(w, r)
	case r.URL.Path == "/sitemap.xml":
		m.handleSitemap(w, r)
	case strings.HasPrefix(r.URL.Path, "/ghost/"):
		m.handleAdminRequest(w, r)
	default:
		w.WriteHeader(404)
		w.Write([]byte("Not Found"))
	}
}

// handleHomePage handles the main page request
func (m *MockGhostServer) handleHomePage(w http.ResponseWriter, r *http.Request) {
	htmlContent := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="generator" content="Ghost %s">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Test Ghost Blog</title>
    <link rel="stylesheet" type="text/css" href="/content/themes/casper/assets/css/screen.css">
</head>
<body class="home-template">
    <div class="site-wrapper">
        <header class="site-header">
            <h1>Test Ghost Blog</h1>
        </header>
        <main class="site-main">
            <article class="post">
                <h2>Welcome to Ghost</h2>
                <p>This is a test Ghost blog for integration testing.</p>
            </article>
        </main>
    </div>
    <script src="/content/themes/casper/assets/js/index.js"></script>
</body>
</html>`, m.version)

	// Add security headers for testing
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Frame-Options", "SAMEORIGIN")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-XSS-Protection", "1; mode=block")
	w.Header().Set("Server", "nginx/1.18.0")
	w.Write([]byte(htmlContent))
}

// handleAPIRequest handles Ghost API requests
func (m *MockGhostServer) handleAPIRequest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if response, exists := m.endpoints[r.URL.Path]; exists {
		jsonData, _ := json.Marshal(response)
		w.Write(jsonData)
	} else {
		w.WriteHeader(404)
		w.Write([]byte(`{"error":"Not Found"}`))
	}
}

// handleRSSFeed handles RSS feed requests
func (m *MockGhostServer) handleRSSFeed(w http.ResponseWriter, r *http.Request) {
	rssContent := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
<channel>
    <title>Test Ghost Blog</title>
    <description>A test blog</description>
    <generator>Ghost %s</generator>
    <item>
        <title>Test Post</title>
        <description>Test content</description>
        <author>admin@example.com (Admin User)</author>
        <pubDate>Mon, 01 Jan 2024 00:00:00 GMT</pubDate>
    </item>
</channel>
</rss>`, m.version)

	w.Header().Set("Content-Type", "application/rss+xml")
	w.Write([]byte(rssContent))
}

// handleThemeRequest handles theme file requests
func (m *MockGhostServer) handleThemeRequest(w http.ResponseWriter, r *http.Request) {
	if strings.Contains(r.URL.Path, "casper") {
		w.Header().Set("Content-Type", "text/css")
		w.Write([]byte("/* Casper theme CSS */"))
	} else {
		w.WriteHeader(404)
	}
}

// handleRobotsTxt handles robots.txt requests
func (m *MockGhostServer) handleRobotsTxt(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte("User-agent: *\nDisallow: /ghost/\nSitemap: /sitemap.xml"))
}

// handleSitemap handles sitemap.xml requests
func (m *MockGhostServer) handleSitemap(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/xml")
	w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
<url><loc>/</loc></url>
</urlset>`))
}

// handleAdminRequest handles Ghost admin requests
func (m *MockGhostServer) handleAdminRequest(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/ghost/" {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><head><title>Ghost Admin</title></head><body><div id="ember-app"></div></body></html>`))
	} else {
		w.WriteHeader(404)
	}
}

// TestFullScanIntegration tests complete scan functionality
func TestFullScanIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tests := []struct {
		name    string
		version string
	}{
		{"Ghost 4.48.2", "4.48.2"},
		{"Ghost 5.0.0", "5.0.0"},
		{"Ghost 3.42.0", "3.42.0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock server
			mockServer := NewMockGhostServer(tt.version)
			defer mockServer.Close()

			// Create scanner
			scanner, err := scanner.NewScanner(mockServer.URL(), true, 5, 30, "GhostScan/Test")
			if err != nil {
				t.Fatalf("Failed to create scanner: %v", err)
			}

			// Enable verbose mode
			scanner.SetVerbose(true)

			// Run full scan
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()

			result, err := scanner.Scan(ctx)
			if err != nil {
				t.Fatalf("Scan failed: %v", err)
			}

			// Verify basic detection
			if !result.IsGhost {
				t.Error("Ghost CMS not detected")
			}

			if result.Version != tt.version {
				t.Errorf("Expected version %s, got %s", tt.version, result.Version)
			}

			if result.Confidence < 50 {
				t.Errorf("Low confidence score: %d", result.Confidence)
			}

			// Verify scan completeness
			if len(result.Endpoints) == 0 {
				t.Error("No endpoints discovered")
			}

			if len(result.SecurityHeaders) == 0 {
				t.Error("No security headers analyzed")
			}

			// Verify timing
			if result.ScanDuration <= 0 {
				t.Error("Invalid scan duration")
			}

			// Log results for debugging
			t.Logf("Scan completed in %v", result.ScanDuration)
			t.Logf("Found %d endpoints", len(result.Endpoints))
			t.Logf("Found %d security headers", len(result.SecurityHeaders))
			t.Logf("Confidence: %d", result.Confidence)
		})
	}
}

// TestVulnerabilityScanning tests vulnerability detection
func TestVulnerabilityScanning(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Test with vulnerable version
	mockServer := NewMockGhostServer("4.0.0") // Older version with known vulnerabilities
	defer mockServer.Close()

	scanner, err := scanner.NewScanner(mockServer.URL(), true, 3, 20, "GhostScan/VulnTest")
	if err != nil {
		t.Fatalf("Failed to create scanner: %v", err)
	}

	ctx := context.Background()
	result, err := scanner.Scan(ctx)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// Should detect some vulnerabilities for older version
	if len(result.Vulns) == 0 {
		t.Log("No vulnerabilities detected (this might be expected if CVE database is empty)")
	}

	for _, vuln := range result.Vulns {
		if vuln.CVE == "" {
			t.Error("Vulnerability missing CVE identifier")
		}
		if vuln.Severity == "" {
			t.Error("Vulnerability missing severity")
		}
		t.Logf("Found vulnerability: %s (%s)", vuln.CVE, vuln.Severity)
	}
}

// TestUserEnumeration tests user enumeration functionality
func TestUserEnumeration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	mockServer := NewMockGhostServer("4.48.2")
	defer mockServer.Close()

	scanner, err := scanner.NewScanner(mockServer.URL(), false, 2, 15, "GhostScan/UserTest")
	if err != nil {
		t.Fatalf("Failed to create scanner: %v", err)
	}

	ctx := context.Background()
	result, err := scanner.Scan(ctx)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// Check if users were enumerated
	if len(result.Users) == 0 {
		t.Log("No users enumerated (might be expected depending on configuration)")
	} else {
		for _, user := range result.Users {
			if user.Username == "" {
				t.Error("User missing username")
			}
			t.Logf("Found user: %s", user.Username)
		}
	}
}

// TestThemeDetection tests theme detection functionality
func TestThemeDetection(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	mockServer := NewMockGhostServer("4.48.2")
	defer mockServer.Close()

	scanner, err := scanner.NewScanner(mockServer.URL(), false, 1, 10, "GhostScan/ThemeTest")
	if err != nil {
		t.Fatalf("Failed to create scanner: %v", err)
	}

	ctx := context.Background()
	result, err := scanner.Scan(ctx)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// Should detect at least the default theme
	if result.Theme == "" {
		t.Error("No theme detected")
	} else {
		t.Logf("Detected theme: %s", result.Theme)
	}
}

// TestPerformanceMetrics tests performance monitoring
func TestPerformanceMetrics(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	mockServer := NewMockGhostServer("4.48.2")
	defer mockServer.Close()

	scanner, err := scanner.NewScanner(mockServer.URL(), false, 3, 20, "GhostScan/PerfTest")
	if err != nil {
		t.Fatalf("Failed to create scanner: %v", err)
	}

	start := time.Now()
	ctx := context.Background()
	result, err := scanner.Scan(ctx)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	elapsed := time.Since(start)

	// Verify performance metrics
	if result.ScanDuration <= 0 {
		t.Error("Invalid scan duration in result")
	}

	if elapsed < result.ScanDuration {
		t.Error("Measured time less than reported scan duration")
	}

	t.Logf("Scan completed in %v (reported: %v)", elapsed, result.ScanDuration)
}

// TestConcurrentScans tests multiple concurrent scans
func TestConcurrentScans(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	mockServer := NewMockGhostServer("4.48.2")
	defer mockServer.Close()

	const numScans = 3
	results := make(chan error, numScans)

	for i := 0; i < numScans; i++ {
		go func(scanID int) {
			scanner, err := scanner.NewScanner(mockServer.URL(), false, 2, 15, fmt.Sprintf("GhostScan/Concurrent-%d", scanID))
			if err != nil {
				results <- fmt.Errorf("scan %d: failed to create scanner: %v", scanID, err)
				return
			}

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			_, err = scanner.Scan(ctx)
			if err != nil {
				results <- fmt.Errorf("scan %d: scan failed: %v", scanID, err)
				return
			}

			results <- nil
		}(i)
	}

	// Wait for all scans to complete
	for i := 0; i < numScans; i++ {
		if err := <-results; err != nil {
			t.Error(err)
		}
	}
}

// TestConfigFileIntegration tests configuration file loading
func TestConfigFileIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Create temporary config file
	tempDir := t.TempDir()
	configFile := filepath.Join(tempDir, "test-config.yaml")

	configContent := `
scanner:
  threads: 10
  timeout: 60
  user_agent: "GhostScan/Test"
  delay: 1000
  random_delay: true

enumeration:
  users: true
  themes: true
  plugins: true
  endpoints: true

vulnerabilities:
  enabled: true
  passive_only: false

output:
  format: "json"
  verbose: true
`

	err := os.WriteFile(configFile, []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create config file: %v", err)
	}

	// Test would involve loading config and verifying scanner behavior
	// This is a placeholder for actual config integration testing
	t.Logf("Config file created at: %s", configFile)
}

// TestErrorHandling tests error handling in various scenarios
func TestErrorHandling(t *testing.T) {
	tests := []struct {
		name      string
		targetURL string
		expectErr bool
	}{
		{
			name:      "Invalid URL",
			targetURL: "://invalid-url",
			expectErr: true,
		},
		{
			name:      "Valid URL - should not error",
			targetURL: "https://example.com",
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner, err := scanner.NewScanner(tt.targetURL, false, 1, 5, "Test")
			if tt.expectErr {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			// Test scan with timeout for network errors
			if tt.targetURL == "https://example.com" {
				ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
				defer cancel()

				_, err = scanner.Scan(ctx)
				if err == nil {
					t.Error("Expected timeout/network error but got none")
				}
			}
		})
	}
}