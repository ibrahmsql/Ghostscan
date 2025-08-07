package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/tidwall/gjson"
)

// Scanner represents the main Ghost CMS scanner
type Scanner struct {
	client       *resty.Client
	targetURL    string
	verbose      bool
	threads      int
	proxy        string
	maxRedirects int
	deepScan     bool
	userAgent    string
	timeout      time.Duration
	delay        time.Duration
	randomDelay  bool
}

// ScanResult holds the results of a Ghost CMS scan
type ScanResult struct {
	Target          string              `json:"target"`
	Timestamp       time.Time           `json:"timestamp"`
	ScanDuration    time.Duration       `json:"scan_duration"`
	IsGhost         bool                `json:"is_ghost"`
	Confidence      int                 `json:"confidence"`
	Version         string              `json:"version"`
	VersionSource   string              `json:"version_source,omitempty"`
	Theme           string              `json:"theme"`
	ThemeVersion    string              `json:"theme_version,omitempty"`
	Users           []User              `json:"users"`
	Plugins         []Plugin            `json:"plugins"`
	Endpoints       []Endpoint          `json:"endpoints"`
	Vulns           []Vulnerability     `json:"vulnerabilities"`
	Misconfigs      []Misconfiguration  `json:"misconfigurations"`
	Interesting     []string            `json:"interesting_files"`
	Headers         map[string]string   `json:"headers"`
	SecurityHeaders []SecurityHeader    `json:"security_headers"`
	Technologies    []Technology        `json:"technologies"`
	DatabaseInfo    *DatabaseInfo       `json:"database_info,omitempty"`
	ServerInfo      *ServerInfo         `json:"server_info,omitempty"`
	Performance     *PerformanceMetrics `json:"performance,omitempty"`
}

// Vulnerability represents a detected vulnerability
type Vulnerability struct {
	CVE         string `json:"cve"`
	Title       string `json:"title"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	Affected    string `json:"affected_versions"`
	Fixed       string `json:"fixed_in"`
}

// Misconfiguration represents a security misconfiguration
type Misconfiguration struct {
	Type        string `json:"type"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	URL         string `json:"url"`
}

// User represents a discovered user
type User struct {
	ID       string `json:"id,omitempty"`
	Username string `json:"username"`
	Email    string `json:"email,omitempty"`
	Name     string `json:"name,omitempty"`
	Role     string `json:"role,omitempty"`
	Active   bool   `json:"active"`
	URL      string `json:"url,omitempty"`
}

// Plugin represents a discovered plugin
type Plugin struct {
	Name        string `json:"name"`
	Version     string `json:"version,omitempty"`
	Active      bool   `json:"active"`
	Path        string `json:"path,omitempty"`
	Description string `json:"description,omitempty"`
	Author      string `json:"author,omitempty"`
}

// Endpoint represents a discovered endpoint
type Endpoint struct {
	URL        string `json:"url"`
	Method     string `json:"method"`
	StatusCode int    `json:"status_code"`
	Size       int64  `json:"size"`
	Type       string `json:"type,omitempty"`
	Title      string `json:"title,omitempty"`
}

// SecurityHeader represents security header information
type SecurityHeader struct {
	Name     string `json:"name"`
	Value    string `json:"value,omitempty"`
	Present  bool   `json:"present"`
	Secure   bool   `json:"secure"`
	Severity string `json:"severity"`
	Advice   string `json:"advice"`
}

// Technology represents detected technologies
type Technology struct {
	Name        string `json:"name"`
	Version     string `json:"version,omitempty"`
	Category    string `json:"category"`
	Confidence  int    `json:"confidence"`
	Description string `json:"description"`
}

// DatabaseInfo represents database information
type DatabaseInfo struct {
	Type    string `json:"type"`
	Version string `json:"version,omitempty"`
	Size    string `json:"size,omitempty"`
	Tables  int    `json:"tables,omitempty"`
	Exposed bool   `json:"exposed"`
	Path    string `json:"path,omitempty"`
}

// ServerInfo represents server information
type ServerInfo struct {
	Software  string            `json:"software"`
	Version   string            `json:"version,omitempty"`
	OS        string            `json:"os,omitempty"`
	PoweredBy string            `json:"powered_by,omitempty"`
	Headers   map[string]string `json:"headers,omitempty"`
	SSL       *SSLInfo          `json:"ssl,omitempty"`
}

// SSLInfo represents SSL/TLS information
type SSLInfo struct {
	Enabled     bool      `json:"enabled"`
	Version     string    `json:"version,omitempty"`
	Cipher      string    `json:"cipher,omitempty"`
	Certificate string    `json:"certificate,omitempty"`
	Expiry      time.Time `json:"expiry,omitempty"`
	Issuer      string    `json:"issuer,omitempty"`
}

// PerformanceMetrics represents performance metrics
type PerformanceMetrics struct {
	ResponseTime     time.Duration `json:"response_time"`
	TTFB             time.Duration `json:"ttfb"`
	PageSize         int64         `json:"page_size"`
	Requests         int           `json:"requests"`
	CompressionRatio float64       `json:"compression_ratio,omitempty"`
	LoadTime         time.Duration `json:"load_time"`
}

// NewScanner creates a new Ghost CMS scanner instance
func NewScanner(targetURL string, verbose bool, threads int, timeout int, userAgent string) (*Scanner, error) {
	// Validate URL
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %v", err)
	}

	if parsedURL.Scheme == "" {
		targetURL = "https://" + targetURL
	}

	// Create HTTP client
	client := resty.New()
	client.SetTimeout(time.Duration(timeout) * time.Second)
	client.SetHeader("User-Agent", userAgent)
	client.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})
	client.SetRedirectPolicy(resty.FlexibleRedirectPolicy(5))

	return &Scanner{
		client:    client,
		targetURL: targetURL,
		verbose:   verbose,
		threads:   threads,
	}, nil
}

// Scan performs a comprehensive Ghost CMS security scan
func (s *Scanner) Scan(ctx context.Context) (*ScanResult, error) {
	start := time.Now()
	result := &ScanResult{
		Target:          s.targetURL,
		Timestamp:       start,
		Headers:         make(map[string]string),
		Users:           []User{},
		Plugins:         []Plugin{},
		Endpoints:       []Endpoint{},
		Vulns:           []Vulnerability{},
		Misconfigs:      []Misconfiguration{},
		Interesting:     []string{},
		SecurityHeaders: []SecurityHeader{},
		Technologies:    []Technology{},
	}

	// Step 1: Detect Ghost CMS
	if s.verbose {
		fmt.Println("[*] Detecting Ghost CMS...")
	}
	isGhost, err := s.detectGhost(ctx, result)
	if err != nil {
		return nil, fmt.Errorf("ghost detection failed: %v", err)
	}

	result.IsGhost = isGhost
	if !isGhost {
		return result, nil
	}

	// Step 2: Version detection
	if s.verbose {
		fmt.Println("[*] Detecting Ghost version...")
	}
	version, err := s.detectVersion(ctx)
	if err == nil {
		result.Version = version
	}

	// Step 3: Theme detection
	if s.verbose {
		fmt.Println("[*] Detecting active theme...")
	}
	theme, err := s.detectTheme(ctx)
	if err == nil {
		result.Theme = theme
	}

	// Step 4: User enumeration
	if s.verbose {
		fmt.Println("[*] Enumerating users...")
	}
	users, err := s.enumerateUsers(ctx)
	if err == nil {
		result.Users = users
	}

	// Step 5: Plugin detection
	if s.verbose {
		fmt.Println("[*] Detecting plugins...")
	}
	plugins := s.detectPlugins(ctx)
	result.Plugins = plugins

	// Step 6: Endpoint discovery
	if s.verbose {
		fmt.Println("[*] Discovering endpoints...")
	}
	endpoints := s.discoverEndpoints(ctx)
	result.Endpoints = endpoints

	// Step 7: Vulnerability assessment
	if s.verbose {
		fmt.Println("[*] Checking for vulnerabilities...")
	}
	vulns := s.checkVulnerabilities(ctx, result.Version)
	result.Vulns = vulns

	// Step 8: Security misconfiguration checks
	if s.verbose {
		fmt.Println("[*] Checking for misconfigurations...")
	}
	misconfigs := s.checkMisconfigurations(ctx)
	result.Misconfigs = misconfigs

	// Step 9: Interesting files discovery
	if s.verbose {
		fmt.Println("[*] Discovering interesting files...")
	}
	interesting := s.discoverInterestingFiles(ctx)
	result.Interesting = interesting

	// Step 10: Security headers analysis
	if s.verbose {
		fmt.Println("[*] Analyzing security headers...")
	}
	securityHeaders := s.analyzeSecurityHeaders(result.Headers)
	result.SecurityHeaders = securityHeaders

	// Calculate confidence score
	result.Confidence = s.calculateConfidence(result)

	// Calculate scan duration
	result.ScanDuration = time.Since(start)

	return result, nil
}

// NewScannerWithOptions creates a new scanner with advanced options
func NewScannerWithOptions(targetURL string, options ScannerOptions) (*Scanner, error) {
	if targetURL == "" {
		return nil, fmt.Errorf("target URL cannot be empty")
	}

	// Parse and validate URL
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %v", err)
	}

	if parsedURL.Scheme == "" {
		targetURL = "https://" + targetURL
	}

	// Create HTTP client
	client := resty.New()
	client.SetTimeout(options.Timeout)
	client.SetHeader("User-Agent", options.UserAgent)
	client.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})

	if options.Proxy != "" {
		client.SetProxy(options.Proxy)
	}

	if options.MaxRedirects > 0 {
		client.SetRedirectPolicy(resty.FlexibleRedirectPolicy(options.MaxRedirects))
	}

	return &Scanner{
		client:       client,
		targetURL:    targetURL,
		verbose:      options.Verbose,
		threads:      options.Threads,
		proxy:        options.Proxy,
		maxRedirects: options.MaxRedirects,
		deepScan:     options.DeepScan,
		userAgent:    options.UserAgent,
		timeout:      options.Timeout,
		delay:        options.Delay,
		randomDelay:  options.RandomDelay,
	}, nil
}

// ScannerOptions represents scanner configuration options
type ScannerOptions struct {
	Verbose      bool          `json:"verbose"`
	Threads      int           `json:"threads"`
	Proxy        string        `json:"proxy,omitempty"`
	MaxRedirects int           `json:"max_redirects"`
	DeepScan     bool          `json:"deep_scan"`
	UserAgent    string        `json:"user_agent"`
	Timeout      time.Duration `json:"timeout"`
	Delay        time.Duration `json:"delay"`
	RandomDelay  bool          `json:"random_delay"`
}

// DefaultScannerOptions returns default scanner options
func DefaultScannerOptions() ScannerOptions {
	return ScannerOptions{
		Verbose:      false,
		Threads:      10,
		MaxRedirects: 5,
		DeepScan:     false,
		UserAgent:    "GhostScan/1.0",
		Timeout:      30 * time.Second,
		Delay:        100 * time.Millisecond,
		RandomDelay:  false,
	}
}

// SetVerbose enables or disables verbose output
func (s *Scanner) SetVerbose(verbose bool) {
	s.verbose = verbose
}

// SetDelay sets the delay between requests
func (s *Scanner) SetDelay(delay time.Duration) {
	s.delay = delay
}

// SetRandomDelay enables or disables random delay
func (s *Scanner) SetRandomDelay(enabled bool) {
	s.randomDelay = enabled
}

// GetTarget returns the target URL
func (s *Scanner) GetTarget() string {
	return s.targetURL
}

// IsVerbose returns whether verbose mode is enabled
func (s *Scanner) IsVerbose() bool {
	return s.verbose
}

// GetThreads returns the number of threads
func (s *Scanner) GetThreads() int {
	return s.threads
}

// GetDelay returns the delay between requests
func (s *Scanner) GetDelay() time.Duration {
	return s.delay
}

// IsRandomDelayEnabled returns whether random delay is enabled
func (s *Scanner) IsRandomDelayEnabled() bool {
	return s.randomDelay
}

// IsDeepScanEnabled returns whether deep scan is enabled
func (s *Scanner) IsDeepScanEnabled() bool {
	return s.deepScan
}

// checkVulnerabilities checks for known Ghost CMS vulnerabilities
func (s *Scanner) checkVulnerabilities(ctx context.Context, version string) []Vulnerability {
	vulns := []Vulnerability{}

	// Define known Ghost vulnerabilities
	knownVulns := []Vulnerability{
		{
			CVE:         "CVE-2023-32235",
			Title:       "Path Traversal in Theme Preview",
			Severity:    "High",
			Description: "Path traversal vulnerability in Ghost theme preview functionality",
			Affected:    "≤ 5.52.1",
			Fixed:       "5.52.2",
		},
		{
			CVE:         "CVE-2023-40028",
			Title:       "Arbitrary File Read via Theme Upload",
			Severity:    "High",
			Description: "Arbitrary file read vulnerability via malicious theme upload",
			Affected:    "≤ 5.58.0",
			Fixed:       "5.58.1",
		},
		{
			CVE:         "CVE-2024-23724",
			Title:       "Stored XSS via Profile Image",
			Severity:    "Medium",
			Description: "Stored XSS vulnerability via SVG profile image upload",
			Affected:    "Multiple versions",
			Fixed:       "Latest",
		},
	}

	// Check if current version is affected
	for _, vuln := range knownVulns {
		if s.isVersionAffected(version, vuln.Affected) {
			vulns = append(vulns, vuln)
		}
	}

	// Test for path traversal vulnerability
	if s.testPathTraversal(ctx) {
		vulns = append(vulns, Vulnerability{
			CVE:         "CVE-2023-32235",
			Title:       "Path Traversal Confirmed",
			Severity:    "Critical",
			Description: "Active path traversal vulnerability detected",
			Affected:    "Current version",
			Fixed:       "Update required",
		})
	}

	return vulns
}

// checkMisconfigurations checks for security misconfigurations
func (s *Scanner) checkMisconfigurations(ctx context.Context) []Misconfiguration {
	misconfigs := []Misconfiguration{}

	// Check if admin interface is accessible over HTTP
	if strings.HasPrefix(s.targetURL, "http://") {
		adminResp, err := s.client.R().SetContext(ctx).Get(s.targetURL + "/ghost/")
		if err == nil && adminResp.StatusCode() == 200 {
			misconfigs = append(misconfigs, Misconfiguration{
				Type:        "Insecure Admin Access",
				Description: "Ghost admin interface accessible over HTTP",
				Severity:    "High",
				URL:         s.targetURL + "/ghost/",
			})
		}
	}

	// Check for directory browsing
	directories := []string{"/content/", "/content/images/", "/content/themes/", "/content/logs/"}
	for _, dir := range directories {
		dirResp, err := s.client.R().SetContext(ctx).Get(s.targetURL + dir)
		if err == nil && dirResp.StatusCode() == 200 {
			body := dirResp.String()
			if strings.Contains(body, "Index of") || strings.Contains(body, "Directory listing") {
				misconfigs = append(misconfigs, Misconfiguration{
					Type:        "Directory Browsing",
					Description: fmt.Sprintf("Directory browsing enabled for %s", dir),
					Severity:    "Medium",
					URL:         s.targetURL + dir,
				})
			}
		}
	}

	// Check for exposed configuration files
	configFiles := []string{"/.env", "/config.production.json", "/config.development.json"}
	for _, file := range configFiles {
		fileResp, err := s.client.R().SetContext(ctx).Get(s.targetURL + file)
		if err == nil && fileResp.StatusCode() == 200 {
			misconfigs = append(misconfigs, Misconfiguration{
				Type:        "Exposed Configuration",
				Description: fmt.Sprintf("Configuration file exposed: %s", file),
				Severity:    "Critical",
				URL:         s.targetURL + file,
			})
		}
	}

	// Check for debug mode
	debugResp, err := s.client.R().SetContext(ctx).Get(s.targetURL + "/ghost/api/v4/admin/site/")
	if err == nil && debugResp.StatusCode() == 200 {
		body := debugResp.String()
		if strings.Contains(body, "\"debug\":true") {
			misconfigs = append(misconfigs, Misconfiguration{
				Type:        "Debug Mode Enabled",
				Description: "Ghost is running in debug mode",
				Severity:    "Medium",
				URL:         s.targetURL + "/ghost/api/v4/admin/site/",
			})
		}
	}

	return misconfigs
}

// discoverInterestingFiles discovers interesting files and endpoints
func (s *Scanner) discoverInterestingFiles(ctx context.Context) []string {
	interesting := []string{}

	// Common Ghost files and endpoints to check
	files := []string{
		"/robots.txt",
		"/sitemap.xml",
		"/rss/",
		"/ghost/",
		"/ghost/api/v4/admin/",
		"/ghost/api/v4/content/",
		"/content/themes/",
		"/content/images/",
		"/assets/built/",
		"/.well-known/ghost/",
		"/ghost/assets/",
		"/content/logs/",
		"/content/data/",
	}

	for _, file := range files {
		resp, err := s.client.R().SetContext(ctx).Get(s.targetURL + file)
		if err == nil && resp.StatusCode() == 200 {
			interesting = append(interesting, file)
		}
	}

	return interesting
}

// isVersionAffected checks if a version is affected by a vulnerability
func (s *Scanner) isVersionAffected(version, affected string) bool {
	if version == "" || affected == "" {
		return false
	}

	// Simple version comparison (can be enhanced)
	if strings.Contains(affected, "≤") {
		// Extract version from "≤ 5.52.1" format
		parts := strings.Split(affected, " ")
		if len(parts) >= 2 {
			maxVersion := parts[1]
			return s.compareVersions(version, maxVersion) <= 0
		}
	}

	return false
}

// compareVersions compares two version strings
func (s *Scanner) compareVersions(v1, v2 string) int {
	// Simple version comparison (can be enhanced with proper semver)
	if v1 == v2 {
		return 0
	}
	if v1 < v2 {
		return -1
	}
	return 1
}

// testPathTraversal tests for path traversal vulnerability
func (s *Scanner) testPathTraversal(ctx context.Context) bool {
	// Test CVE-2023-32235: Path Traversal in Theme Preview
	payloads := []string{
		"../../../etc/passwd",
		"..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
		"....//....//....//etc/passwd",
	}

	for _, payload := range payloads {
		testURL := s.targetURL + "/ghost/api/v4/admin/themes/preview/" + payload
		resp, err := s.client.R().SetContext(ctx).Get(testURL)
		if err == nil && resp.StatusCode() == 200 {
			body := resp.String()
			// Check for signs of successful file read
			if strings.Contains(body, "root:") || strings.Contains(body, "localhost") {
				return true
			}
		}
	}

	return false
}

// detectGhost checks if the target is running Ghost CMS
func (s *Scanner) detectGhost(ctx context.Context, result *ScanResult) (bool, error) {
	resp, err := s.client.R().SetContext(ctx).Get(s.targetURL)
	if err != nil {
		return false, err
	}

	// Store response headers
	for key, values := range resp.Header() {
		if len(values) > 0 {
			result.Headers[key] = values[0]
		}
	}

	body := resp.String()

	// Method 1: Check for Ghost-specific headers
	if ghostCache := resp.Header().Get("X-Ghost-Cache"); ghostCache != "" {
		return true, nil
	}

	if ghostVersion := resp.Header().Get("X-Ghost-Version"); ghostVersion != "" {
		return true, nil
	}

	// Method 2: Check for Ghost meta generator tag
	generatorRegex := regexp.MustCompile(`<meta\s+name=["']generator["']\s+content=["']Ghost\s+([0-9.]+)["']`)
	if generatorRegex.MatchString(body) {
		return true, nil
	}

	// Method 3: Check for Ghost-specific paths and assets
	ghostPaths := []string{
		"/ghost/",
		"/assets/built/",
		"/content/themes/",
		"/ghost/api/v4/",
	}

	for _, path := range ghostPaths {
		if strings.Contains(body, path) {
			return true, nil
		}
	}

	// Method 4: Check Ghost API endpoints
	apiEndpoints := []string{
		"/ghost/api/v4/content/settings/",
		"/ghost/api/v4/admin/site/",
		"/.well-known/ghost/",
	}

	for _, endpoint := range apiEndpoints {
		apiResp, err := s.client.R().SetContext(ctx).Get(s.targetURL + endpoint)
		if err == nil && apiResp.StatusCode() == 200 {
			apiBody := apiResp.String()
			if strings.Contains(apiBody, "ghost") || strings.Contains(apiBody, "version") {
				return true, nil
			}
		}
	}

	return false, nil
}

// detectVersion attempts to determine the Ghost version
func (s *Scanner) detectVersion(ctx context.Context) (string, error) {
	// Method 1: Check meta generator tag
	resp, err := s.client.R().SetContext(ctx).Get(s.targetURL)
	if err != nil {
		return "", err
	}

	body := resp.String()
	generatorRegex := regexp.MustCompile(`<meta\s+name=["']generator["']\s+content=["']Ghost\s+([0-9.]+)["']`)
	matches := generatorRegex.FindStringSubmatch(body)
	if len(matches) > 1 {
		return matches[1], nil
	}

	// Method 2: Check X-Ghost-Version header
	if ghostVersion := resp.Header().Get("X-Ghost-Version"); ghostVersion != "" {
		return ghostVersion, nil
	}

	// Method 3: Check admin API
	apiResp, err := s.client.R().SetContext(ctx).Get(s.targetURL + "/ghost/api/v4/admin/site/")
	if err == nil && apiResp.StatusCode() == 200 {
		version := gjson.Get(apiResp.String(), "site.version")
		if version.Exists() {
			return version.String(), nil
		}
	}

	// Method 4: Check content API settings
	contentResp, err := s.client.R().SetContext(ctx).Get(s.targetURL + "/ghost/api/v4/content/settings/")
	if err == nil && contentResp.StatusCode() == 200 {
		version := gjson.Get(contentResp.String(), "settings.ghost_head")
		if version.Exists() {
			versionRegex := regexp.MustCompile(`Ghost\s+([0-9.]+)`)
			matches := versionRegex.FindStringSubmatch(version.String())
			if len(matches) > 1 {
				return matches[1], nil
			}
		}
	}

	return "", fmt.Errorf("version not detected")
}

// detectTheme attempts to identify the active Ghost theme
func (s *Scanner) detectTheme(ctx context.Context) (string, error) {
	resp, err := s.client.R().SetContext(ctx).Get(s.targetURL)
	if err != nil {
		return "", err
	}

	body := resp.String()

	// Look for theme assets in the HTML
	themeRegex := regexp.MustCompile(`/content/themes/([^/]+)/`)
	matches := themeRegex.FindStringSubmatch(body)
	if len(matches) > 1 {
		return matches[1], nil
	}

	// Check for theme CSS/JS files
	assetRegex := regexp.MustCompile(`/assets/built/([^/]+)\.`)
	assetMatches := assetRegex.FindStringSubmatch(body)
	if len(assetMatches) > 1 {
		return assetMatches[1], nil
	}

	return "", fmt.Errorf("theme not detected")
}

// enumerateUsers attempts to discover Ghost users
func (s *Scanner) enumerateUsers(ctx context.Context) ([]User, error) {
	users := []User{}

	// Method 1: Check authors API
	authorsResp, err := s.client.R().SetContext(ctx).Get(s.targetURL + "/ghost/api/v4/content/authors/")
	if err == nil && authorsResp.StatusCode() == 200 {
		authorsData := gjson.Get(authorsResp.String(), "authors")
		if authorsData.Exists() {
			authorsData.ForEach(func(key, value gjson.Result) bool {
				user := User{
					ID:       value.Get("id").String(),
					Username: value.Get("slug").String(),
					Name:     value.Get("name").String(),
					URL:      value.Get("url").String(),
					Active:   true,
				}
				if user.Username != "" {
					users = append(users, user)
				}
				return true
			})
		}
	}

	// Method 2: Check RSS feed for authors
	rssResp, err := s.client.R().SetContext(ctx).Get(s.targetURL + "/rss/")
	if err == nil && rssResp.StatusCode() == 200 {
		rssBody := rssResp.String()
		authorRegex := regexp.MustCompile(`<dc:creator><!\[CDATA\[([^\]]+)\]\]></dc:creator>`)
		matches := authorRegex.FindAllStringSubmatch(rssBody, -1)
		for _, match := range matches {
			if len(match) > 1 {
				user := User{
					Username: match[1],
					Name:     match[1],
					Active:   true,
				}
				users = append(users, user)
			}
		}
	}

	// Remove duplicates
	uniqueUsers := make(map[string]bool)
	result := []User{}
	for _, user := range users {
		if !uniqueUsers[user.Username] {
			uniqueUsers[user.Username] = true
			result = append(result, user)
		}
	}

	return result, nil
}

// detectPlugins attempts to discover Ghost plugins
func (s *Scanner) detectPlugins(ctx context.Context) []Plugin {
	plugins := []Plugin{}

	// Check for common plugin paths
	commonPlugins := []string{
		"ghost-storage-adapter-s3",
		"ghost-storage-cloudinary",
		"ghost-mailgun",
		"ghost-newsletter",
		"ghost-comments",
		"ghost-search",
	}

	for _, pluginName := range commonPlugins {
		resp, err := s.client.R().SetContext(ctx).Get(s.targetURL + "/content/adapters/" + pluginName)
		if err == nil && resp.StatusCode() == 200 {
			plugin := Plugin{
				Name:   pluginName,
				Active: true,
				Path:   "/content/adapters/" + pluginName,
			}
			plugins = append(plugins, plugin)
		}
	}

	return plugins
}

// discoverEndpoints discovers available Ghost endpoints
func (s *Scanner) discoverEndpoints(ctx context.Context) []Endpoint {
	endpoints := []Endpoint{}

	// Common Ghost endpoints
	commonEndpoints := []string{
		"/ghost/api/v4/content/posts/",
		"/ghost/api/v4/content/authors/",
		"/ghost/api/v4/content/tags/",
		"/ghost/api/v4/content/pages/",
		"/ghost/api/v4/content/settings/",
		"/ghost/api/admin/",
		"/ghost/",
		"/rss/",
		"/sitemap.xml",
		"/robots.txt",
	}

	for _, path := range commonEndpoints {
		resp, err := s.client.R().SetContext(ctx).Get(s.targetURL + path)
		if err == nil {
			endpoint := Endpoint{
				URL:        s.targetURL + path,
				Method:     "GET",
				StatusCode: resp.StatusCode(),
				Size:       int64(len(resp.Body())),
			}

			if resp.StatusCode() == 200 {
				if strings.Contains(path, "api") {
					endpoint.Type = "API"
				} else {
					endpoint.Type = "Static"
				}
			}

			endpoints = append(endpoints, endpoint)
		}
	}

	return endpoints
}

// analyzeSecurityHeaders analyzes HTTP security headers
func (s *Scanner) analyzeSecurityHeaders(headers map[string]string) []SecurityHeader {
	securityHeaders := []SecurityHeader{}

	// Define expected security headers
	expectedHeaders := map[string]string{
		"X-Frame-Options":        "Protects against clickjacking attacks",
		"X-Content-Type-Options": "Prevents MIME type sniffing",
		"X-XSS-Protection":       "Enables XSS filtering",
		"Strict-Transport-Security": "Enforces HTTPS connections",
		"Content-Security-Policy": "Prevents XSS and data injection attacks",
		"Referrer-Policy":        "Controls referrer information",
	}

	for headerName, description := range expectedHeaders {
		header := SecurityHeader{
			Name:     headerName,
			Present:  false,
			Secure:   false,
			Severity: "Medium",
			Advice:   "Consider adding " + headerName + " header. " + description,
		}

		if value, exists := headers[headerName]; exists {
			header.Present = true
			header.Value = value
			header.Secure = true
			header.Severity = "Info"
			header.Advice = headerName + " header is properly configured"
		}

		securityHeaders = append(securityHeaders, header)
	}

	return securityHeaders
}

// calculateConfidence calculates the confidence score based on scan results
func (s *Scanner) calculateConfidence(result *ScanResult) int {
	confidence := 0

	// Base confidence for Ghost detection
	if result.IsGhost {
		confidence += 30
	}

	// Version detection adds confidence
	if result.Version != "" {
		confidence += 25
	}

	// Theme detection adds confidence
	if result.Theme != "" {
		confidence += 15
	}

	// Endpoints discovery adds confidence
	if len(result.Endpoints) > 0 {
		confidence += 10
	}

	// Users enumeration adds confidence
	if len(result.Users) > 0 {
		confidence += 10
	}

	// Plugins detection adds confidence
	if len(result.Plugins) > 0 {
		confidence += 5
	}

	// Security headers analysis adds confidence
	if len(result.SecurityHeaders) > 0 {
		confidence += 5
	}

	// Cap confidence at 100
	if confidence > 100 {
		confidence = 100
	}

	return confidence
}
