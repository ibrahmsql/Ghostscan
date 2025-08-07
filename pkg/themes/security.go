package themes

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/go-resty/resty/v2"
)

// ThemeSecurity represents the theme security scanner
type ThemeSecurity struct {
	client  *resty.Client
	target  string
	timeout time.Duration
}

// ThemeInfo represents information about a Ghost theme
type ThemeInfo struct {
	Name        string            `json:"name"`
	Version     string            `json:"version"`
	Description string            `json:"description"`
	Author      string            `json:"author"`
	Keywords    []string          `json:"keywords"`
	Repository  map[string]string `json:"repository"`
	Engines     map[string]string `json:"engines"`
	Config      map[string]interface{} `json:"config"`
	Active      bool              `json:"active"`
	Path        string            `json:"path"`
	Files       []string          `json:"files"`
}

// ThemeVulnerability represents a security vulnerability in a theme
type ThemeVulnerability struct {
	Type        string   `json:"type"`
	Severity    string   `json:"severity"`
	Description string   `json:"description"`
	File        string   `json:"file"`
	Line        int      `json:"line"`
	Code        string   `json:"code"`
	Remediation string   `json:"remediation"`
	References  []string `json:"references"`
}

// ThemeSecurityReport represents the complete theme security assessment
type ThemeSecurityReport struct {
	Themes          []ThemeInfo           `json:"themes"`
	Vulnerabilities []ThemeVulnerability  `json:"vulnerabilities"`
	RiskScore       int                   `json:"risk_score"`
	Recommendations []string              `json:"recommendations"`
	ScanTime        time.Time             `json:"scan_time"`
	Errors          []string              `json:"errors"`
}

// SecurityPattern represents a security pattern to check for
type SecurityPattern struct {
	Name        string
	Pattern     *regexp.Regexp
	Severity    string
	Description string
	Remediation string
	FileTypes   []string
}

// NewThemeSecurity creates a new theme security scanner
func NewThemeSecurity(target string, timeout time.Duration) *ThemeSecurity {
	client := resty.New()
	client.SetTimeout(timeout)
	client.SetHeader("User-Agent", "GhostScan/1.0")
	client.SetHeader("Accept", "application/json")

	return &ThemeSecurity{
		client:  client,
		target:  strings.TrimSuffix(target, "/"),
		timeout: timeout,
	}
}

// ScanThemes performs a comprehensive security scan of Ghost themes
func (ts *ThemeSecurity) ScanThemes() (*ThemeSecurityReport, error) {
	report := &ThemeSecurityReport{
		ScanTime: time.Now(),
		Themes:   []ThemeInfo{},
		Vulnerabilities: []ThemeVulnerability{},
		Errors:   []string{},
	}

	// Discover themes
	themes, err := ts.discoverThemes()
	if err != nil {
		report.Errors = append(report.Errors, fmt.Sprintf("Theme discovery failed: %v", err))
	}
	report.Themes = themes

	// Scan each theme for vulnerabilities
	for _, theme := range themes {
		vulns, err := ts.scanThemeVulnerabilities(theme)
		if err != nil {
			report.Errors = append(report.Errors, fmt.Sprintf("Theme scan failed for %s: %v", theme.Name, err))
			continue
		}
		report.Vulnerabilities = append(report.Vulnerabilities, vulns...)
	}

	// Calculate risk score
	report.RiskScore = ts.calculateRiskScore(report.Vulnerabilities)

	// Generate recommendations
	report.Recommendations = ts.generateRecommendations(report.Vulnerabilities)

	return report, nil
}

// discoverThemes discovers available themes
func (ts *ThemeSecurity) discoverThemes() ([]ThemeInfo, error) {
	var themes []ThemeInfo

	// Try to get themes via API
	apiThemes, err := ts.getThemesViaAPI()
	if err == nil {
		themes = append(themes, apiThemes...)
	}

	// Try to discover themes via directory traversal
	dirThemes, err := ts.discoverThemesViaDirectory()
	if err == nil {
		themes = append(themes, dirThemes...)
	}

	// Try to discover themes via common paths
	pathThemes, err := ts.discoverThemesViaCommonPaths()
	if err == nil {
		themes = append(themes, pathThemes...)
	}

	return ts.deduplicateThemes(themes), nil
}

// getThemesViaAPI attempts to get themes via Ghost Admin API
func (ts *ThemeSecurity) getThemesViaAPI() ([]ThemeInfo, error) {
	var themes []ThemeInfo

	// Try different API endpoints
	endpoints := []string{
		"/ghost/api/v4/admin/themes/",
		"/ghost/api/v3/admin/themes/",
		"/ghost/api/v2/admin/themes/",
		"/ghost/api/canary/admin/themes/",
	}

	for _, endpoint := range endpoints {
		resp, err := ts.client.R().Get(fmt.Sprintf("%s%s", ts.target, endpoint))
		if err != nil {
			continue
		}

		if resp.StatusCode() == 200 {
			var apiResponse map[string]interface{}
			if err := json.Unmarshal(resp.Body(), &apiResponse); err == nil {
				if themesData, ok := apiResponse["themes"]; ok {
					if themesArray, ok := themesData.([]interface{}); ok {
						for _, themeData := range themesArray {
							if themeMap, ok := themeData.(map[string]interface{}); ok {
								theme := ts.parseThemeFromAPI(themeMap)
								themes = append(themes, theme)
							}
						}
					}
				}
			}
			break
		}
	}

	return themes, nil
}

// discoverThemesViaDirectory discovers themes via directory listing
func (ts *ThemeSecurity) discoverThemesViaDirectory() ([]ThemeInfo, error) {
	var themes []ThemeInfo

	// Common theme directory paths
	themePaths := []string{
		"/content/themes/",
		"/themes/",
		"/assets/themes/",
		"/ghost/content/themes/",
	}

	for _, path := range themePaths {
		resp, err := ts.client.R().Get(fmt.Sprintf("%s%s", ts.target, path))
		if err != nil {
			continue
		}

		if resp.StatusCode() == 200 {
			// Parse directory listing
			themeNames := ts.parseDirectoryListing(resp.String())
			for _, themeName := range themeNames {
				theme := ThemeInfo{
					Name: themeName,
					Path: fmt.Sprintf("%s%s", path, themeName),
				}
				// Try to get theme details
				ts.enrichThemeInfo(&theme)
				themes = append(themes, theme)
			}
		}
	}

	return themes, nil
}

// discoverThemesViaCommonPaths discovers themes by testing common theme names
func (ts *ThemeSecurity) discoverThemesViaCommonPaths() ([]ThemeInfo, error) {
	var themes []ThemeInfo

	// Common Ghost theme names
	commonThemes := []string{
		"casper", "dawn", "edition", "london", "massively", "editorial",
		"ghost", "default", "custom", "theme", "blog", "news",
		"magazine", "portfolio", "business", "minimal", "clean",
		"modern", "dark", "light", "responsive", "bootstrap",
	}

	basePaths := []string{
		"/content/themes/",
		"/themes/",
		"/assets/themes/",
	}

	for _, basePath := range basePaths {
		for _, themeName := range commonThemes {
			themePath := fmt.Sprintf("%s%s/", basePath, themeName)
			resp, err := ts.client.R().Get(fmt.Sprintf("%s%s", ts.target, themePath))
			if err != nil {
				continue
			}

			if resp.StatusCode() == 200 || resp.StatusCode() == 403 {
				theme := ThemeInfo{
					Name: themeName,
					Path: themePath,
				}
				ts.enrichThemeInfo(&theme)
				themes = append(themes, theme)
			}
		}
	}

	return themes, nil
}

// parseThemeFromAPI parses theme information from API response
func (ts *ThemeSecurity) parseThemeFromAPI(themeData map[string]interface{}) ThemeInfo {
	theme := ThemeInfo{}

	if name, ok := themeData["name"].(string); ok {
		theme.Name = name
	}
	if version, ok := themeData["version"].(string); ok {
		theme.Version = version
	}
	if description, ok := themeData["description"].(string); ok {
		theme.Description = description
	}
	if author, ok := themeData["author"].(string); ok {
		theme.Author = author
	}
	if active, ok := themeData["active"].(bool); ok {
		theme.Active = active
	}

	return theme
}

// parseDirectoryListing parses directory listing HTML to extract theme names
func (ts *ThemeSecurity) parseDirectoryListing(html string) []string {
	var themes []string

	// Common patterns for directory listings
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`<a href="([^"]+)/"[^>]*>([^<]+)</a>`),
		regexp.MustCompile(`href="([^"]+)/"`),
		regexp.MustCompile(`>([a-zA-Z0-9_-]+)/<`),
	}

	for _, pattern := range patterns {
		matches := pattern.FindAllStringSubmatch(html, -1)
		for _, match := range matches {
			if len(match) > 1 {
				themeName := match[1]
				if ts.isValidThemeName(themeName) {
					themes = append(themes, themeName)
				}
			}
		}
	}

	return ts.deduplicateStrings(themes)
}

// isValidThemeName checks if a string is a valid theme name
func (ts *ThemeSecurity) isValidThemeName(name string) bool {
	// Skip common non-theme directories
	skipDirs := []string{".", "..", "index", "assets", "css", "js", "images", "fonts"}
	for _, skip := range skipDirs {
		if name == skip {
			return false
		}
	}

	// Valid theme names are typically alphanumeric with hyphens/underscores
	validName := regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
	return validName.MatchString(name) && len(name) > 1
}

// enrichThemeInfo attempts to gather more information about a theme
func (ts *ThemeSecurity) enrichThemeInfo(theme *ThemeInfo) {
	// Try to get package.json
	packageURL := fmt.Sprintf("%s%spackage.json", ts.target, theme.Path)
	resp, err := ts.client.R().Get(packageURL)
	if err == nil && resp.StatusCode() == 200 {
		var packageData map[string]interface{}
		if err := json.Unmarshal(resp.Body(), &packageData); err == nil {
			if name, ok := packageData["name"].(string); ok {
				theme.Name = name
			}
			if version, ok := packageData["version"].(string); ok {
				theme.Version = version
			}
			if description, ok := packageData["description"].(string); ok {
				theme.Description = description
			}
			if author, ok := packageData["author"].(string); ok {
				theme.Author = author
			}
			if config, ok := packageData["config"].(map[string]interface{}); ok {
				theme.Config = config
			}
		}
	}

	// Try to discover theme files
	theme.Files = ts.discoverThemeFiles(theme.Path)
}

// discoverThemeFiles discovers files in a theme directory
func (ts *ThemeSecurity) discoverThemeFiles(themePath string) []string {
	var files []string

	// Common theme files
	commonFiles := []string{
		"index.hbs", "post.hbs", "page.hbs", "tag.hbs", "author.hbs",
		"default.hbs", "partials/header.hbs", "partials/footer.hbs",
		"assets/css/style.css", "assets/js/script.js",
		"package.json", "README.md", "LICENSE",
	}

	for _, file := range commonFiles {
		fileURL := fmt.Sprintf("%s%s%s", ts.target, themePath, file)
		resp, err := ts.client.R().Head(fileURL)
		if err == nil && resp.StatusCode() == 200 {
			files = append(files, file)
		}
	}

	return files
}

// scanThemeVulnerabilities scans a theme for security vulnerabilities
func (ts *ThemeSecurity) scanThemeVulnerabilities(theme ThemeInfo) ([]ThemeVulnerability, error) {
	var vulnerabilities []ThemeVulnerability

	// Get security patterns
	patterns := ts.getSecurityPatterns()

	// Scan each file in the theme
	for _, file := range theme.Files {
		fileURL := fmt.Sprintf("%s%s%s", ts.target, theme.Path, file)
		resp, err := ts.client.R().Get(fileURL)
		if err != nil {
			continue
		}

		if resp.StatusCode() == 200 {
			content := resp.String()
			fileVulns := ts.scanFileContent(file, content, patterns)
			vulnerabilities = append(vulnerabilities, fileVulns...)
		}
	}

	// Scan theme configuration
	configVulns := ts.scanThemeConfiguration(theme)
	vulnerabilities = append(vulnerabilities, configVulns...)

	return vulnerabilities, nil
}

// getSecurityPatterns returns security patterns to check for
func (ts *ThemeSecurity) getSecurityPatterns() []SecurityPattern {
	return []SecurityPattern{
		{
			Name:        "XSS_UNESCAPED_OUTPUT",
			Pattern:     regexp.MustCompile(`\{\{\{[^}]+\}\}\}`),
			Severity:    "High",
			Description: "Unescaped Handlebars output can lead to XSS vulnerabilities",
			Remediation: "Use {{}} instead of {{{}}} for user-controlled content",
			FileTypes:   []string{".hbs", ".html"},
		},
		{
			Name:        "JAVASCRIPT_EVAL",
			Pattern:     regexp.MustCompile(`eval\s*\(`),
			Severity:    "Critical",
			Description: "Use of eval() can lead to code injection vulnerabilities",
			Remediation: "Avoid using eval() and use safer alternatives",
			FileTypes:   []string{".js"},
		},
		{
			Name:        "JAVASCRIPT_INNERHTML",
			Pattern:     regexp.MustCompile(`\.innerHTML\s*=`),
			Severity:    "Medium",
			Description: "Direct innerHTML assignment can lead to XSS vulnerabilities",
			Remediation: "Use textContent or properly sanitize HTML content",
			FileTypes:   []string{".js"},
		},
		{
			Name:        "EXTERNAL_SCRIPT_INCLUSION",
			Pattern:     regexp.MustCompile(`<script[^>]+src=["']https?://[^"']+["'][^>]*>`),
			Severity:    "Medium",
			Description: "External script inclusion can pose security risks",
			Remediation: "Verify the integrity of external scripts and use SRI",
			FileTypes:   []string{".hbs", ".html"},
		},
		{
			Name:        "INLINE_JAVASCRIPT",
			Pattern:     regexp.MustCompile(`on\w+\s*=\s*["'][^"']*["']`),
			Severity:    "Low",
			Description: "Inline JavaScript event handlers can be security risks",
			Remediation: "Use external event listeners instead of inline handlers",
			FileTypes:   []string{".hbs", ".html"},
		},
		{
			Name:        "TEMPLATE_INJECTION",
			Pattern:     regexp.MustCompile(`\{\{[^}]*constructor[^}]*\}\}`),
			Severity:    "Critical",
			Description: "Potential template injection vulnerability",
			Remediation: "Avoid using constructor or other dangerous objects in templates",
			FileTypes:   []string{".hbs"},
		},
		{
			Name:        "HARDCODED_CREDENTIALS",
			Pattern:     regexp.MustCompile(`(?i)(password|secret|key|token)\s*[:=]\s*["'][^"']{8,}["']`),
			Severity:    "High",
			Description: "Hardcoded credentials found in theme files",
			Remediation: "Remove hardcoded credentials and use environment variables",
			FileTypes:   []string{".js", ".json", ".hbs"},
		},
		{
			Name:        "UNSAFE_URL_REDIRECT",
			Pattern:     regexp.MustCompile(`window\.location\s*=\s*[^;]+`),
			Severity:    "Medium",
			Description: "Unsafe URL redirection can lead to phishing attacks",
			Remediation: "Validate and sanitize redirect URLs",
			FileTypes:   []string{".js"},
		},
	}
}

// scanFileContent scans file content for security vulnerabilities
func (ts *ThemeSecurity) scanFileContent(filename, content string, patterns []SecurityPattern) []ThemeVulnerability {
	var vulnerabilities []ThemeVulnerability

	lines := strings.Split(content, "\n")
	fileExt := filepath.Ext(filename)

	for _, pattern := range patterns {
		// Check if pattern applies to this file type
		applies := false
		for _, ext := range pattern.FileTypes {
			if ext == fileExt {
				applies = true
				break
			}
		}
		if !applies {
			continue
		}

		// Scan each line
		for lineNum, line := range lines {
			if pattern.Pattern.MatchString(line) {
				vuln := ThemeVulnerability{
					Type:        pattern.Name,
					Severity:    pattern.Severity,
					Description: pattern.Description,
					File:        filename,
					Line:        lineNum + 1,
					Code:        strings.TrimSpace(line),
					Remediation: pattern.Remediation,
				}
				vulnerabilities = append(vulnerabilities, vuln)
			}
		}
	}

	return vulnerabilities
}

// scanThemeConfiguration scans theme configuration for security issues
func (ts *ThemeSecurity) scanThemeConfiguration(theme ThemeInfo) []ThemeVulnerability {
	var vulnerabilities []ThemeVulnerability

	// Check for dangerous configuration options
	if theme.Config != nil {
		if customSettings, ok := theme.Config["custom"].(map[string]interface{}); ok {
			for key, value := range customSettings {
				if strings.Contains(strings.ToLower(key), "script") {
					vuln := ThemeVulnerability{
						Type:        "DANGEROUS_CONFIG",
						Severity:    "Medium",
						Description: "Theme configuration allows custom script injection",
						File:        "package.json",
						Code:        fmt.Sprintf("%s: %v", key, value),
						Remediation: "Review and sanitize custom configuration options",
					}
					vulnerabilities = append(vulnerabilities, vuln)
				}
			}
		}
	}

	return vulnerabilities
}

// calculateRiskScore calculates overall risk score based on vulnerabilities
func (ts *ThemeSecurity) calculateRiskScore(vulnerabilities []ThemeVulnerability) int {
	score := 0
	for _, vuln := range vulnerabilities {
		switch vuln.Severity {
		case "Critical":
			score += 10
		case "High":
			score += 7
		case "Medium":
			score += 4
		case "Low":
			score += 1
		}
	}
	return score
}

// generateRecommendations generates security recommendations
func (ts *ThemeSecurity) generateRecommendations(vulnerabilities []ThemeVulnerability) []string {
	recommendations := []string{}
	vulnTypes := make(map[string]bool)

	for _, vuln := range vulnerabilities {
		vulnTypes[vuln.Type] = true
	}

	if vulnTypes["XSS_UNESCAPED_OUTPUT"] {
		recommendations = append(recommendations, "Review all Handlebars templates and ensure proper output escaping")
	}
	if vulnTypes["JAVASCRIPT_EVAL"] {
		recommendations = append(recommendations, "Remove all uses of eval() and replace with safer alternatives")
	}
	if vulnTypes["TEMPLATE_INJECTION"] {
		recommendations = append(recommendations, "Audit templates for potential injection vulnerabilities")
	}
	if vulnTypes["HARDCODED_CREDENTIALS"] {
		recommendations = append(recommendations, "Remove hardcoded credentials and use environment variables")
	}
	if vulnTypes["EXTERNAL_SCRIPT_INCLUSION"] {
		recommendations = append(recommendations, "Implement Subresource Integrity (SRI) for external scripts")
	}

	// General recommendations
	recommendations = append(recommendations, "Regularly update themes to latest versions")
	recommendations = append(recommendations, "Implement Content Security Policy (CSP) headers")
	recommendations = append(recommendations, "Conduct regular security audits of custom themes")

	return recommendations
}

// deduplicateThemes removes duplicate themes
func (ts *ThemeSecurity) deduplicateThemes(themes []ThemeInfo) []ThemeInfo {
	seen := make(map[string]bool)
	var result []ThemeInfo

	for _, theme := range themes {
		key := fmt.Sprintf("%s:%s", theme.Name, theme.Path)
		if !seen[key] {
			seen[key] = true
			result = append(result, theme)
		}
	}

	return result
}

// deduplicateStrings removes duplicate strings
func (ts *ThemeSecurity) deduplicateStrings(strings []string) []string {
	seen := make(map[string]bool)
	var result []string

	for _, str := range strings {
		if !seen[str] {
			seen[str] = true
			result = append(result, str)
		}
	}

	return result
}

// DownloadAndAnalyzeTheme downloads and analyzes a theme package
func (ts *ThemeSecurity) DownloadAndAnalyzeTheme(themeURL string) (*ThemeSecurityReport, error) {
	// Download theme package
	resp, err := ts.client.R().Get(themeURL)
	if err != nil {
		return nil, fmt.Errorf("failed to download theme: %w", err)
	}

	if resp.StatusCode() != 200 {
		return nil, fmt.Errorf("failed to download theme: HTTP %d", resp.StatusCode())
	}

	// Analyze theme package
	return ts.analyzeThemePackage(resp.Body())
}

// analyzeThemePackage analyzes a theme package (ZIP file)
func (ts *ThemeSecurity) analyzeThemePackage(data []byte) (*ThemeSecurityReport, error) {
	report := &ThemeSecurityReport{
		ScanTime: time.Now(),
		Vulnerabilities: []ThemeVulnerability{},
		Errors: []string{},
	}

	// Read ZIP file
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("failed to read theme package: %w", err)
	}

	// Get security patterns
	patterns := ts.getSecurityPatterns()

	// Analyze each file in the package
	for _, file := range reader.File {
		if file.FileInfo().IsDir() {
			continue
		}

		// Read file content
		rc, err := file.Open()
		if err != nil {
			report.Errors = append(report.Errors, fmt.Sprintf("Failed to open %s: %v", file.Name, err))
			continue
		}

		content, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			report.Errors = append(report.Errors, fmt.Sprintf("Failed to read %s: %v", file.Name, err))
			continue
		}

		// Scan file content
		vulns := ts.scanFileContent(file.Name, string(content), patterns)
		report.Vulnerabilities = append(report.Vulnerabilities, vulns...)
	}

	// Calculate risk score and generate recommendations
	report.RiskScore = ts.calculateRiskScore(report.Vulnerabilities)
	report.Recommendations = ts.generateRecommendations(report.Vulnerabilities)

	return report, nil
}