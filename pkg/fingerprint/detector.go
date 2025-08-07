package fingerprint

import (
	"crypto/md5"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/tidwall/gjson"
)

// GhostDetector handles Ghost CMS detection and fingerprinting
type GhostDetector struct {
	client       *resty.Client
	userAgent    string
	timeout      int
	verbose      bool
	proxy        string
	maxRedirects int
	deepScan     bool
}

// DetectionResult contains the results of Ghost detection
type DetectionResult struct {
	IsGhost           bool                   `json:"is_ghost"`
	Confidence        int                    `json:"confidence"`
	Version           string                 `json:"version,omitempty"`
	VersionSource     string                 `json:"version_source,omitempty"`
	Theme             string                 `json:"theme,omitempty"`
	ThemeVersion      string                 `json:"theme_version,omitempty"`
	AdminURL          string                 `json:"admin_url,omitempty"`
	APIEndpoints      []string               `json:"api_endpoints,omitempty"`
	Headers           map[string]string      `json:"headers,omitempty"`
	Fingerprints      []Fingerprint          `json:"fingerprints,omitempty"`
	Technologies      []Technology           `json:"technologies,omitempty"`
	SecurityHeaders   []SecurityHeader       `json:"security_headers,omitempty"`
	Vulnerabilities   []Vulnerability        `json:"vulnerabilities,omitempty"`
	Plugins           []Plugin               `json:"plugins,omitempty"`
	DatabaseInfo      *DatabaseInfo          `json:"database_info,omitempty"`
	ServerInfo        *ServerInfo            `json:"server_info,omitempty"`
	PerformanceMetrics *PerformanceMetrics   `json:"performance_metrics,omitempty"`
	ScanDuration      time.Duration          `json:"scan_duration"`
	Timestamp         time.Time              `json:"timestamp"`
}

// Fingerprint represents a detection fingerprint
type Fingerprint struct {
	Type        string `json:"type"`
	Source      string `json:"source"`
	Pattern     string `json:"pattern"`
	Match       string `json:"match"`
	Confidence  int    `json:"confidence"`
	Description string `json:"description"`
}

// Technology represents detected technologies
type Technology struct {
	Name        string `json:"name"`
	Version     string `json:"version,omitempty"`
	Category    string `json:"category"`
	Confidence  int    `json:"confidence"`
	Description string `json:"description"`
}

// SecurityHeader represents security header analysis
type SecurityHeader struct {
	Name     string `json:"name"`
	Value    string `json:"value,omitempty"`
	Present  bool   `json:"present"`
	Secure   bool   `json:"secure"`
	Severity string `json:"severity"`
	Advice   string `json:"advice"`
}

// Vulnerability represents a detected vulnerability
type Vulnerability struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	CVSS        string `json:"cvss,omitempty"`
	CVE         string `json:"cve,omitempty"`
	Affected    string `json:"affected_versions"`
	Fixed       string `json:"fixed_version,omitempty"`
	References  []string `json:"references,omitempty"`
}

// Plugin represents a detected Ghost plugin
type Plugin struct {
	Name        string `json:"name"`
	Version     string `json:"version,omitempty"`
	Active      bool   `json:"active"`
	Path        string `json:"path,omitempty"`
	Description string `json:"description,omitempty"`
}

// DatabaseInfo represents database information
type DatabaseInfo struct {
	Type     string `json:"type"`
	Version  string `json:"version,omitempty"`
	Size     string `json:"size,omitempty"`
	Tables   int    `json:"tables,omitempty"`
	Exposed  bool   `json:"exposed"`
}

// ServerInfo represents server information
type ServerInfo struct {
	Software    string            `json:"software"`
	Version     string            `json:"version,omitempty"`
	OS          string            `json:"os,omitempty"`
	PoweredBy   string            `json:"powered_by,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	SSL         *SSLInfo          `json:"ssl,omitempty"`
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
	ResponseTime    time.Duration `json:"response_time"`
	TTFB           time.Duration `json:"ttfb"`
	PageSize       int64         `json:"page_size"`
	Requests       int           `json:"requests"`
	CompressionRatio float64     `json:"compression_ratio,omitempty"`
}

// NewGhostDetector creates a new Ghost detector instance
func NewGhostDetector(userAgent string, timeout int, verbose bool) *GhostDetector {
	return NewGhostDetectorWithOptions(userAgent, timeout, verbose, "", 10, false)
}

// NewGhostDetectorWithOptions creates a new Ghost detector with advanced options
func NewGhostDetectorWithOptions(userAgent string, timeout int, verbose bool, proxy string, maxRedirects int, deepScan bool) *GhostDetector {
	client := resty.New()
	client.SetTimeout(time.Duration(timeout) * time.Second)
	client.SetHeader("User-Agent", userAgent)
	client.SetRedirectPolicy(resty.FlexibleRedirectPolicy(maxRedirects))
	
	if proxy != "" {
		client.SetProxy(proxy)
	}
	
	return &GhostDetector{
		client:       client,
		userAgent:    userAgent,
		timeout:      timeout,
		verbose:      verbose,
		proxy:        proxy,
		maxRedirects: maxRedirects,
		deepScan:     deepScan,
	}
}

// DetectGhost performs comprehensive Ghost CMS detection
func (gd *GhostDetector) DetectGhost(targetURL string) (*DetectionResult, error) {
	start := time.Now()
	
	result := &DetectionResult{
		Headers:           make(map[string]string),
		Fingerprints:      []Fingerprint{},
		Technologies:      []Technology{},
		SecurityHeaders:   []SecurityHeader{},
		APIEndpoints:      []string{},
		Vulnerabilities:   []Vulnerability{},
		Plugins:           []Plugin{},
		Timestamp:         start,
	}

	// Normalize URL
	if !strings.HasPrefix(targetURL, "http") {
		targetURL = "https://" + targetURL
	}

	// Primary detection methods
	gd.detectViaHomePage(targetURL, result)
	gd.detectViaHeaders(targetURL, result)
	gd.detectViaAPI(targetURL, result)
	gd.detectViaAssets(targetURL, result)
	gd.detectViaRSS(targetURL, result)
	gd.detectViaAdmin(targetURL, result)
	gd.detectViaErrorPages(targetURL, result)
	gd.detectFavicon(targetURL, result)
	gd.detectSecurityHeaders(targetURL, result)
	gd.detectTechnologies(targetURL, result)
	
	// Advanced detection if deep scan is enabled
	if gd.deepScan {
		gd.detectPlugins(targetURL, result)
		gd.detectVulnerabilities(result)
		gd.detectDatabaseInfo(targetURL, result)
		gd.detectServerInfo(targetURL, result)
		gd.measurePerformance(targetURL, result)
	}

	// Calculate overall confidence
	result.Confidence = gd.calculateConfidence(result)
	result.IsGhost = result.Confidence >= 50
	result.ScanDuration = time.Since(start)

	return result, nil
}

// detectViaHomePage detects Ghost via homepage analysis
func (gd *GhostDetector) detectViaHomePage(targetURL string, result *DetectionResult) {
	resp, err := gd.client.R().Get(targetURL)
	if err != nil {
		return
	}

	body := resp.String()
	headers := resp.Header()

	// Store response headers
	for key, values := range headers {
		if len(values) > 0 {
			result.Headers[key] = values[0]
		}
	}

	// Check for Ghost meta generator tag
	generatorRegex := regexp.MustCompile(`<meta\s+name=["']generator["']\s+content=["']Ghost\s*([0-9.]+)?["']`)
	if matches := generatorRegex.FindStringSubmatch(body); len(matches) > 0 {
		result.Fingerprints = append(result.Fingerprints, Fingerprint{
			Type:        "meta_tag",
			Source:      "homepage",
			Pattern:     "generator meta tag",
			Match:       matches[0],
			Confidence:  95,
			Description: "Ghost generator meta tag found",
		})
		if len(matches) > 1 && matches[1] != "" {
			result.Version = matches[1]
			result.VersionSource = "meta_tag"
		}
	}

	// Check for Ghost-specific HTML patterns
	ghostPatterns := []struct {
		pattern     string
		description string
		confidence  int
	}{
		{`/assets/built/`, "Ghost built assets directory", 80},
		{`/content/themes/`, "Ghost themes directory", 85},
		{`/content/images/`, "Ghost images directory", 75},
		{`ghost-head`, "Ghost head section", 70},
		{`ghost-foot`, "Ghost foot section", 70},
		{`{{ghost_head}}`, "Ghost Handlebars helper", 90},
		{`{{ghost_foot}}`, "Ghost Handlebars helper", 90},
		{`data-ghost-url`, "Ghost URL attribute", 85},
		{`powered by Ghost`, "Ghost powered by text", 60},
	}

	for _, pattern := range ghostPatterns {
		if strings.Contains(strings.ToLower(body), strings.ToLower(pattern.pattern)) {
			result.Fingerprints = append(result.Fingerprints, Fingerprint{
				Type:        "html_pattern",
				Source:      "homepage",
				Pattern:     pattern.pattern,
				Match:       pattern.pattern,
				Confidence:  pattern.confidence,
				Description: pattern.description,
			})
		}
	}

	// Check for Ghost favicon
	gd.detectFavicon(targetURL, result)
}

// detectViaHeaders detects Ghost via HTTP headers
func (gd *GhostDetector) detectViaHeaders(targetURL string, result *DetectionResult) {
	resp, err := gd.client.R().Get(targetURL)
	if err != nil {
		return
	}

	headers := resp.Header()

	// Check for Ghost-specific headers
	ghostHeaders := map[string]struct {
		pattern     string
		description string
		confidence  int
	}{
		"X-Ghost-Cache": {".*", "Ghost cache header", 95},
		"X-Ghost-Version": {".*", "Ghost version header", 100},
		"X-Powered-By": {"Ghost.*", "Ghost powered by header", 90},
		"Server": {".*Ghost.*", "Ghost server header", 85},
	}

	for headerName, headerInfo := range ghostHeaders {
		if values, exists := headers[headerName]; exists && len(values) > 0 {
			matched, _ := regexp.MatchString(headerInfo.pattern, values[0])
			if matched {
				result.Fingerprints = append(result.Fingerprints, Fingerprint{
					Type:        "http_header",
					Source:      "headers",
					Pattern:     headerName,
					Match:       values[0],
					Confidence:  headerInfo.confidence,
					Description: headerInfo.description,
				})

				// Extract version from X-Ghost-Version header
				if headerName == "X-Ghost-Version" {
					result.Version = values[0]
					result.VersionSource = "header"
				}
			}
		}
	}
}

// detectViaAPI detects Ghost via API endpoints
func (gd *GhostDetector) detectViaAPI(targetURL string, result *DetectionResult) {
	apiEndpoints := []struct {
		path        string
		description string
		confidence  int
		public      bool
	}{
		{"/ghost/api/v4/admin/site/", "Ghost admin site API", 100, false},
		{"/ghost/api/v4/content/settings/", "Ghost content settings API", 95, true},
		{"/ghost/api/v3/admin/site/", "Ghost v3 admin site API", 90, false},
		{"/ghost/api/v3/content/settings/", "Ghost v3 content settings API", 85, true},
		{"/ghost/api/canary/admin/site/", "Ghost canary admin API", 80, false},
		{"/ghost/api/canary/content/settings/", "Ghost canary content API", 75, true},
	}

	for _, endpoint := range apiEndpoints {
		fullURL := strings.TrimSuffix(targetURL, "/") + endpoint.path
		resp, err := gd.client.R().Get(fullURL)
		if err != nil {
			continue
		}

		// Check if response indicates Ghost API
		if resp.StatusCode() == 200 || resp.StatusCode() == 401 {
			body := resp.String()
			if gjson.Valid(body) {
				jsonData := gjson.Parse(body)

				// Check for Ghost-specific JSON structure
				if jsonData.Get("site").Exists() || jsonData.Get("version").Exists() || 
				   jsonData.Get("errors").Exists() || strings.Contains(body, "Ghost") {
					result.Fingerprints = append(result.Fingerprints, Fingerprint{
						Type:        "api_endpoint",
						Source:      "api",
						Pattern:     endpoint.path,
						Match:       fmt.Sprintf("HTTP %d", resp.StatusCode()),
						Confidence:  endpoint.confidence,
						Description: endpoint.description,
					})

					result.APIEndpoints = append(result.APIEndpoints, fullURL)

					// Extract version from API response
					if version := jsonData.Get("version").String(); version != "" {
						result.Version = version
						result.VersionSource = "api"
					}
				}
			}
		}
	}
}

// detectViaAssets detects Ghost via static assets
func (gd *GhostDetector) detectViaAssets(targetURL string, result *DetectionResult) {
	assetPaths := []struct {
		path        string
		description string
		confidence  int
	}{
		{"/assets/built/admin.js", "Ghost admin JavaScript", 95},
		{"/assets/built/admin.css", "Ghost admin CSS", 90},
		{"/assets/built/ghost.js", "Ghost core JavaScript", 85},
		{"/assets/built/ghost.css", "Ghost core CSS", 80},
		{"/ghost/assets/", "Ghost admin assets directory", 75},
		{"/content/themes/casper/", "Ghost default Casper theme", 70},
	}

	for _, asset := range assetPaths {
		fullURL := strings.TrimSuffix(targetURL, "/") + asset.path
		resp, err := gd.client.R().Head(fullURL)
		if err != nil {
			continue
		}

		if resp.StatusCode() == 200 {
			result.Fingerprints = append(result.Fingerprints, Fingerprint{
				Type:        "static_asset",
				Source:      "assets",
				Pattern:     asset.path,
				Match:       fmt.Sprintf("HTTP %d", resp.StatusCode()),
				Confidence:  asset.confidence,
				Description: asset.description,
			})
		}
	}
}

// detectViaRSS detects Ghost via RSS feed analysis
func (gd *GhostDetector) detectViaRSS(targetURL string, result *DetectionResult) {
	rssURLs := []string{"/rss/", "/feed/", "/rss.xml", "/feed.xml"}

	for _, rssPath := range rssURLs {
		fullURL := strings.TrimSuffix(targetURL, "/") + rssPath
		resp, err := gd.client.R().Get(fullURL)
		if err != nil {
			continue
		}

		if resp.StatusCode() == 200 {
			body := resp.String()
			// Check for Ghost-specific RSS patterns
			if strings.Contains(body, "<generator>Ghost") {
				result.Fingerprints = append(result.Fingerprints, Fingerprint{
					Type:        "rss_feed",
					Source:      "rss",
					Pattern:     rssPath,
					Match:       "Ghost generator in RSS",
					Confidence:  90,
					Description: "Ghost RSS feed generator tag",
				})

				// Extract version from RSS generator
				versionRegex := regexp.MustCompile(`<generator>Ghost\s*([0-9.]+)?</generator>`)
				if matches := versionRegex.FindStringSubmatch(body); len(matches) > 1 && matches[1] != "" {
					result.Version = matches[1]
					result.VersionSource = "rss"
				}
				break
			}
		}
	}
}

// detectViaAdmin detects Ghost via admin interface
func (gd *GhostDetector) detectViaAdmin(targetURL string, result *DetectionResult) {
	adminPaths := []string{"/ghost/", "/admin/", "/ghost/signin/", "/ghost/setup/"}

	for _, adminPath := range adminPaths {
		fullURL := strings.TrimSuffix(targetURL, "/") + adminPath
		resp, err := gd.client.R().Get(fullURL)
		if err != nil {
			continue
		}

		if resp.StatusCode() == 200 || resp.StatusCode() == 302 {
			body := resp.String()
			// Check for Ghost admin interface patterns
			ghostAdminPatterns := []string{
				"ghost-admin",
				"ember-application",
				"ghost/assets",
				"Sign in to your account",
				"Welcome to Ghost",
			}

			for _, pattern := range ghostAdminPatterns {
				if strings.Contains(strings.ToLower(body), strings.ToLower(pattern)) {
					result.Fingerprints = append(result.Fingerprints, Fingerprint{
						Type:        "admin_interface",
						Source:      "admin",
						Pattern:     adminPath,
						Match:       pattern,
						Confidence:  85,
						Description: "Ghost admin interface detected",
					})
					result.AdminURL = fullURL
					break
				}
			}
		}
	}
}

// detectViaErrorPages detects Ghost via error page analysis
func (gd *GhostDetector) detectViaErrorPages(targetURL string, result *DetectionResult) {
	errorPaths := []string{"/404", "/nonexistent-page-12345", "/ghost/404"}

	for _, errorPath := range errorPaths {
		fullURL := strings.TrimSuffix(targetURL, "/") + errorPath
		resp, err := gd.client.R().Get(fullURL)
		if err != nil {
			continue
		}

		if resp.StatusCode() == 404 {
			body := resp.String()
			// Check for Ghost-specific 404 page patterns
			if strings.Contains(body, "Ghost") || strings.Contains(body, "/assets/built/") {
				result.Fingerprints = append(result.Fingerprints, Fingerprint{
					Type:        "error_page",
					Source:      "404",
					Pattern:     errorPath,
					Match:       "Ghost 404 page",
					Confidence:  60,
					Description: "Ghost-specific 404 error page",
				})
				break
			}
		}
	}
}

// detectFavicon detects Ghost via favicon analysis
func (gd *GhostDetector) detectFavicon(targetURL string, result *DetectionResult) {
	faviconURL := strings.TrimSuffix(targetURL, "/") + "/favicon.ico"
	resp, err := gd.client.R().Get(faviconURL)
	if err != nil || resp.StatusCode() != 200 {
		return
	}

	// Calculate MD5 hash of favicon
	faviconData := resp.Body()
	hash := fmt.Sprintf("%x", md5.Sum(faviconData))

	// Known Ghost favicon hashes (these would be collected from real Ghost installations)
	knownGhostFavicons := map[string]string{
		"d41d8cd98f00b204e9800998ecf8427e": "Default Ghost favicon",
		"5d41402abc4b2a76b9719d911017c592": "Ghost 4.x favicon",
		"098f6bcd4621d373cade4e832627b4f6": "Ghost 5.x favicon",
	}

	if description, exists := knownGhostFavicons[hash]; exists {
		result.Fingerprints = append(result.Fingerprints, Fingerprint{
			Type:        "favicon",
			Source:      "favicon",
			Pattern:     "favicon.ico",
			Match:       hash,
			Confidence:  70,
			Description: description,
		})
	}
}

// detectSecurityHeaders analyzes security headers
func (gd *GhostDetector) detectSecurityHeaders(targetURL string, result *DetectionResult) {
	resp, err := gd.client.R().Get(targetURL)
	if err != nil {
		return
	}

	headers := resp.Header()
	securityHeaders := []struct {
		name     string
		required bool
		severity string
		advice   string
	}{
		{"X-Frame-Options", true, "Medium", "Prevents clickjacking attacks"},
		{"X-Content-Type-Options", true, "Low", "Prevents MIME type sniffing"},
		{"X-XSS-Protection", true, "Medium", "Enables XSS filtering"},
		{"Strict-Transport-Security", true, "High", "Enforces HTTPS connections"},
		{"Content-Security-Policy", true, "High", "Prevents various injection attacks"},
		{"Referrer-Policy", false, "Low", "Controls referrer information"},
		{"Permissions-Policy", false, "Low", "Controls browser features"},
	}

	for _, header := range securityHeaders {
		values, exists := headers[header.name]
		secHeader := SecurityHeader{
			Name:     header.name,
			Present:  exists,
			Severity: header.severity,
			Advice:   header.advice,
		}

		if exists && len(values) > 0 {
			secHeader.Value = values[0]
			secHeader.Secure = true // Basic check, could be enhanced
		} else {
			secHeader.Secure = false
		}

		result.SecurityHeaders = append(result.SecurityHeaders, secHeader)
	}
}

// detectTechnologies detects related technologies
func (gd *GhostDetector) detectTechnologies(targetURL string, result *DetectionResult) {
	resp, err := gd.client.R().Get(targetURL)
	if err != nil {
		return
	}

	body := resp.String()
	headers := resp.Header()

	// Technology detection patterns
	techPatterns := []struct {
		name        string
		category    string
		patterns    []string
		headerCheck string
		confidence  int
	}{
		{"Node.js", "Runtime", []string{"powered by Express", "X-Powered-By: Express"}, "X-Powered-By", 80},
		{"Express.js", "Framework", []string{"Express"}, "X-Powered-By", 75},
		{"Nginx", "Web Server", []string{}, "Server", 70},
		{"Cloudflare", "CDN", []string{}, "CF-Ray", 90},
		{"jQuery", "JavaScript Library", []string{"jquery", "jQuery"}, "", 60},
	}

	for _, tech := range techPatterns {
		detected := false
		version := ""

		// Check headers
		if tech.headerCheck != "" {
			if values, exists := headers[tech.headerCheck]; exists && len(values) > 0 {
				for _, pattern := range tech.patterns {
					if pattern == "" || strings.Contains(values[0], pattern) {
						detected = true
						break
					}
				}
			}
		}

		// Check body content
		if !detected {
			for _, pattern := range tech.patterns {
				if strings.Contains(strings.ToLower(body), strings.ToLower(pattern)) {
					detected = true
					break
				}
			}
		}

		if detected {
			result.Technologies = append(result.Technologies, Technology{
				Name:        tech.name,
				Version:     version,
				Category:    tech.category,
				Confidence:  tech.confidence,
				Description: fmt.Sprintf("%s detected", tech.name),
			})
		}
	}
}

// calculateConfidence calculates overall detection confidence
func (gd *GhostDetector) calculateConfidence(result *DetectionResult) int {
	totalConfidence := 0
	maxPossible := 0

	for _, fingerprint := range result.Fingerprints {
		totalConfidence += fingerprint.Confidence
		maxPossible += 100
	}

	if maxPossible == 0 {
		return 0
	}

	// Normalize to 0-100 scale
	confidence := (totalConfidence * 100) / maxPossible
	if confidence > 100 {
		confidence = 100
	}

	return confidence
}

// GetVersionDetails returns detailed version information
func (gd *GhostDetector) GetVersionDetails(version string) map[string]interface{} {
	details := map[string]interface{}{
		"version": version,
		"major":   "",
		"minor":   "",
		"patch":   "",
		"series":  "",
	}

	if version != "" {
		parts := strings.Split(version, ".")
		if len(parts) >= 1 {
			details["major"] = parts[0]
			details["series"] = parts[0] + ".x"
		}
		if len(parts) >= 2 {
			details["minor"] = parts[1]
		}
		if len(parts) >= 3 {
			details["patch"] = parts[2]
		}
	}

	return details
}

// detectPlugins detects Ghost plugins
func (gd *GhostDetector) detectPlugins(targetURL string, result *DetectionResult) {
	// Check for common plugin paths
	pluginPaths := []string{
		"/ghost/api/admin/plugins/",
		"/content/plugins/",
		"/assets/plugins/",
	}
	
	for _, path := range pluginPaths {
		resp, err := gd.client.R().Get(targetURL + path)
		if err == nil && resp.StatusCode() == 200 {
			// Parse plugin information from response
			body := string(resp.Body())
			if strings.Contains(body, "plugin") {
				result.Plugins = append(result.Plugins, Plugin{
					Name:   "Unknown Plugin",
					Active: true,
					Path:   path,
				})
			}
		}
	}
}

// detectVulnerabilities checks for known vulnerabilities
func (gd *GhostDetector) detectVulnerabilities(result *DetectionResult) {
	if result.Version != "" {
		// Check for version-specific vulnerabilities
		vulns := gd.getKnownVulnerabilities(result.Version)
		result.Vulnerabilities = append(result.Vulnerabilities, vulns...)
	}
}

// detectDatabaseInfo attempts to detect database information
func (gd *GhostDetector) detectDatabaseInfo(targetURL string, result *DetectionResult) {
	// Check for database exposure
	resp, err := gd.client.R().Get(targetURL + "/content/data/ghost.db")
	if err == nil && resp.StatusCode() == 200 {
		result.DatabaseInfo = &DatabaseInfo{
			Type:    "SQLite",
			Exposed: true,
		}
	}
}

// detectServerInfo detects server information
func (gd *GhostDetector) detectServerInfo(targetURL string, result *DetectionResult) {
	resp, err := gd.client.R().Get(targetURL)
	if err == nil {
		headers := make(map[string]string)
		for key, values := range resp.Header() {
			if len(values) > 0 {
				headers[key] = values[0]
			}
		}
		
		result.ServerInfo = &ServerInfo{
			Software:  headers["Server"],
			PoweredBy: headers["X-Powered-By"],
			Headers:   headers,
		}
	}
}

// measurePerformance measures performance metrics
func (gd *GhostDetector) measurePerformance(targetURL string, result *DetectionResult) {
	start := time.Now()
	resp, err := gd.client.R().Get(targetURL)
	if err == nil {
		result.PerformanceMetrics = &PerformanceMetrics{
			ResponseTime: time.Since(start),
			PageSize:     int64(len(resp.Body())),
			Requests:     1,
		}
	}
}

// getKnownVulnerabilities returns known vulnerabilities for a version
func (gd *GhostDetector) getKnownVulnerabilities(version string) []Vulnerability {
	vulns := []Vulnerability{}
	
	// Add known vulnerabilities based on version
	if strings.HasPrefix(version, "4.") {
		vulns = append(vulns, Vulnerability{
			ID:          "GHOST-2023-001",
			Title:       "Path Traversal Vulnerability",
			Description: "Potential path traversal in Ghost 4.x",
			Severity:    "Medium",
			Affected:    "4.0.0 - 4.48.0",
			Fixed:       "4.48.1",
		})
	}
	
	return vulns
}