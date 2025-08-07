package enumeration

import (
	"crypto/md5"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/go-resty/resty/v2"
)

// ThemeEnumerator handles Ghost CMS theme enumeration
type ThemeEnumerator struct {
	client  *resty.Client
	baseURL string
	verbose bool
	config  *ThemeEnumConfig
}

// ThemeEnumConfig contains theme enumeration configuration
type ThemeEnumConfig struct {
	Timeout         time.Duration
	UserAgent       string
	FollowRedirects bool
	SkipSSL         bool
	Proxy           string
	Headers         map[string]string
	Delay           time.Duration
	RandomDelay     bool
	PassiveOnly     bool
	AggressiveMode  bool
	ThemeList       []string
	CheckVulns      bool
}

// GhostTheme represents a discovered Ghost theme
type GhostTheme struct {
	Name         string            `json:"name"`
	Version      string            `json:"version"`
	Author       string            `json:"author"`
	Description  string            `json:"description"`
	Active       bool              `json:"active"`
	Custom       bool              `json:"custom"`
	Path         string            `json:"path"`
	URL          string            `json:"url"`
	PackageJSON  string            `json:"package_json,omitempty"`
	Stylesheet   string            `json:"stylesheet,omitempty"`
	Screenshot   string            `json:"screenshot,omitempty"`
	Files        []string          `json:"files,omitempty"`
	Vulnerable   bool              `json:"vulnerable"`
	Vulns        []ThemeVuln       `json:"vulnerabilities,omitempty"`
	RiskScore    int               `json:"risk_score"`
	FoundBy      []string          `json:"found_by"`
	Confidence   int               `json:"confidence"`
	Metadata     map[string]string `json:"metadata,omitempty"`
	Fingerprint  string            `json:"fingerprint,omitempty"`
}

// ThemeVuln represents a theme vulnerability
type ThemeVuln struct {
	CVE         string `json:"cve,omitempty"`
	Title       string `json:"title"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	Fixed       string `json:"fixed_in,omitempty"`
	Reference   string `json:"reference,omitempty"`
}

// ThemeEnumResult contains enumeration results
type ThemeEnumResult struct {
	Themes      []*GhostTheme `json:"themes"`
	ActiveTheme *GhostTheme   `json:"active_theme,omitempty"`
	TotalFound  int           `json:"total_found"`
	Methods     []string      `json:"methods_used"`
	Duration    time.Duration `json:"duration"`
	Errors      []string      `json:"errors,omitempty"`
}

// KnownTheme represents a known Ghost theme with fingerprints
type KnownTheme struct {
	Name         string            `json:"name"`
	Versions     map[string]string `json:"versions"`
	Fingerprints map[string]string `json:"fingerprints"`
	Vulns        []ThemeVuln       `json:"vulnerabilities"`
	Popular      bool              `json:"popular"`
}

// NewThemeEnumerator creates a new theme enumerator
func NewThemeEnumerator(baseURL string, config *ThemeEnumConfig) *ThemeEnumerator {
	if config == nil {
		config = &ThemeEnumConfig{
			Timeout:         30 * time.Second,
			UserAgent:       "GhostScan/1.0 (Theme Enumerator)",
			FollowRedirects: true,
			Delay:           100 * time.Millisecond,
			CheckVulns:      true,
		}
	}

	client := resty.New()
	client.SetTimeout(config.Timeout)
	client.SetHeader("User-Agent", config.UserAgent)
	client.SetRedirectPolicy(resty.FlexibleRedirectPolicy(10))

	if config.SkipSSL {
		client.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})
	}

	if config.Proxy != "" {
		client.SetProxy(config.Proxy)
	}

	return &ThemeEnumerator{
		client:  client,
		baseURL: strings.TrimSuffix(baseURL, "/"),
		config:  config,
	}
}

// EnumerateThemes performs comprehensive theme enumeration
func (te *ThemeEnumerator) EnumerateThemes(verbose bool) (*ThemeEnumResult, error) {
	te.verbose = verbose
	start := time.Now()

	if verbose {
		color.Blue("[*] Starting Ghost CMS theme enumeration...")
	}

	result := &ThemeEnumResult{
		Themes:  make([]*GhostTheme, 0),
		Methods: make([]string, 0),
		Errors:  make([]string, 0),
	}

	themeMap := make(map[string]*GhostTheme)

	// Method 1: Active Theme Detection via HTML Analysis
	if verbose {
		color.Yellow("[*] Detecting active theme via HTML analysis...")
	}
	activeTheme, err := te.detectActiveTheme()
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Active theme detection failed: %v", err))
	} else if activeTheme != nil {
		result.Methods = append(result.Methods, "HTML Analysis")
		activeTheme.Active = true
		activeTheme.FoundBy = []string{"HTML Analysis"}
		activeTheme.Confidence = 95
		themeMap[activeTheme.Name] = activeTheme
		result.ActiveTheme = activeTheme
		if verbose {
			color.Green("[+] Active theme detected: %s", activeTheme.Name)
		}
	}
	te.applyDelay()

	// Method 2: Theme Directory Enumeration
	if !te.config.PassiveOnly {
		if verbose {
			color.Yellow("[*] Enumerating theme directories...")
		}
		themes, err := te.enumerateThemeDirectories()
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("Theme directory enumeration failed: %v", err))
		} else {
			result.Methods = append(result.Methods, "Directory Enumeration")
			for _, theme := range themes {
				if existing, exists := themeMap[theme.Name]; exists {
					existing.FoundBy = append(existing.FoundBy, "Directory Enumeration")
					existing.Confidence += 20
					// Merge additional information
					if theme.Version != "" && existing.Version == "" {
						existing.Version = theme.Version
					}
					if len(theme.Files) > 0 {
						existing.Files = append(existing.Files, theme.Files...)
					}
				} else {
					theme.FoundBy = []string{"Directory Enumeration"}
					theme.Confidence = 80
					themeMap[theme.Name] = theme
				}
			}
			if verbose {
				color.Green("[+] Found %d themes via directory enumeration", len(themes))
			}
		}
		te.applyDelay()
	}

	// Method 3: Package.json Analysis
	if !te.config.PassiveOnly {
		if verbose {
			color.Yellow("[*] Analyzing theme package.json files...")
		}
		themes, err := te.analyzePackageJSON()
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("Package.json analysis failed: %v", err))
		} else {
			result.Methods = append(result.Methods, "Package.json Analysis")
			for _, theme := range themes {
				if existing, exists := themeMap[theme.Name]; exists {
					existing.FoundBy = append(existing.FoundBy, "Package.json")
					existing.Confidence += 25
					if theme.Version != "" {
						existing.Version = theme.Version
					}
					if theme.Author != "" {
						existing.Author = theme.Author
					}
					if theme.Description != "" {
						existing.Description = theme.Description
					}
				} else {
					theme.FoundBy = []string{"Package.json"}
					theme.Confidence = 90
					themeMap[theme.Name] = theme
				}
			}
			if verbose {
				color.Green("[+] Found %d themes via package.json analysis", len(themes))
			}
		}
		te.applyDelay()
	}

	// Method 4: Popular Theme Detection
	if verbose {
		color.Yellow("[*] Checking for popular Ghost themes...")
	}
	themes, err := te.detectPopularThemes()
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Popular theme detection failed: %v", err))
	} else {
		result.Methods = append(result.Methods, "Popular Theme Detection")
		for _, theme := range themes {
			if existing, exists := themeMap[theme.Name]; exists {
				existing.FoundBy = append(existing.FoundBy, "Fingerprinting")
				existing.Confidence += 30
				if theme.Version != "" {
					existing.Version = theme.Version
				}
			} else {
				theme.FoundBy = []string{"Fingerprinting"}
				theme.Confidence = 85
				themeMap[theme.Name] = theme
			}
		}
		if verbose {
			color.Green("[+] Found %d popular themes", len(themes))
		}
	}
	te.applyDelay()

	// Method 5: Vulnerability Assessment
	if te.config.CheckVulns {
		if verbose {
			color.Yellow("[*] Checking themes for known vulnerabilities...")
		}
		for _, theme := range themeMap {
			vulns := te.checkThemeVulnerabilities(theme)
			if len(vulns) > 0 {
				theme.Vulnerable = true
				theme.Vulns = vulns
				theme.RiskScore = te.calculateRiskScore(vulns)
				if verbose {
					color.Red("[!] Theme %s has %d known vulnerabilities", theme.Name, len(vulns))
				}
			}
		}
	}

	// Convert map to slice
	for _, theme := range themeMap {
		result.Themes = append(result.Themes, theme)
	}

	result.TotalFound = len(result.Themes)
	result.Duration = time.Since(start)

	if verbose {
		color.Green("[+] Theme enumeration completed in %v", result.Duration)
		color.Green("[+] Total themes found: %d", result.TotalFound)
	}

	return result, nil
}

// detectActiveTheme detects the currently active theme
func (te *ThemeEnumerator) detectActiveTheme() (*GhostTheme, error) {
	resp, err := te.client.R().Get(te.baseURL)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode() != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode())
	}

	body := string(resp.Body())
	theme := &GhostTheme{}

	// Method 1: CSS link analysis
	cssRegex := regexp.MustCompile(`<link[^>]+href="[^"]*\/content\/themes\/([^\/"]+)\/[^"]*\.css[^"]*"`)
	if match := cssRegex.FindStringSubmatch(body); len(match) > 1 {
		theme.Name = match[1]
		theme.Path = fmt.Sprintf("/content/themes/%s/", theme.Name)
		theme.URL = te.baseURL + theme.Path
		theme.Stylesheet = match[0]
	}

	// Method 2: Asset URL analysis
	if theme.Name == "" {
		assetRegex := regexp.MustCompile(`\/content\/themes\/([^\/"]+)\/`)
		if match := assetRegex.FindStringSubmatch(body); len(match) > 1 {
			theme.Name = match[1]
			theme.Path = fmt.Sprintf("/content/themes/%s/", theme.Name)
			theme.URL = te.baseURL + theme.Path
		}
	}

	// Method 3: Built assets analysis
	if theme.Name == "" {
		builtRegex := regexp.MustCompile(`\/assets\/built\/([^\/.]+)`)
		if match := builtRegex.FindStringSubmatch(body); len(match) > 1 {
			// Built assets might indicate theme name
			theme.Name = match[1]
			theme.Custom = true
		}
	}

	if theme.Name == "" {
		return nil, fmt.Errorf("could not detect active theme")
	}

	// Try to get additional theme information
	te.enrichThemeInfo(theme)

	return theme, nil
}

// enumerateThemeDirectories enumerates themes by checking common directories
func (te *ThemeEnumerator) enumerateThemeDirectories() ([]*GhostTheme, error) {
	var themes []*GhostTheme

	// Common Ghost theme names
	commonThemes := []string{
		"casper", "dawn", "edition", "london", "massively", "simply",
		"attila", "ghostium", "vapor", "uno", "boo", "crisp",
		"journal", "saga", "liebling", "alto", "wave", "ruby",
		"mapache", "dope", "ease", "digest", "bulletin", "source",
		"headline", "editorial", "galerie", "portfolio", "minimal",
	}

	// Add custom theme list if provided
	if len(te.config.ThemeList) > 0 {
		commonThemes = append(commonThemes, te.config.ThemeList...)
	}

	for _, themeName := range commonThemes {
		themeURL := fmt.Sprintf("%s/content/themes/%s/", te.baseURL, themeName)
		resp, err := te.client.R().Get(themeURL)
		if err != nil {
			continue
		}

		if resp.StatusCode() == 200 || resp.StatusCode() == 403 {
			// Theme directory exists
			theme := &GhostTheme{
				Name: themeName,
				Path: fmt.Sprintf("/content/themes/%s/", themeName),
				URL:  themeURL,
			}

			// Try to detect if it's a custom theme
			theme.Custom = !te.isDefaultTheme(themeName)

			// Try to get theme files
			files := te.getThemeFiles(themeName)
			theme.Files = files

			themes = append(themes, theme)
		}

		te.applyDelay()
	}

	return themes, nil
}

// analyzePackageJSON analyzes theme package.json files for detailed information
func (te *ThemeEnumerator) analyzePackageJSON() ([]*GhostTheme, error) {
	var themes []*GhostTheme

	// Get list of potential themes from previous enumeration or common names
	themeNames := []string{"casper", "dawn", "edition", "london"}
	if len(te.config.ThemeList) > 0 {
		themeNames = append(themeNames, te.config.ThemeList...)
	}

	for _, themeName := range themeNames {
		packageURL := fmt.Sprintf("%s/content/themes/%s/package.json", te.baseURL, themeName)
		resp, err := te.client.R().Get(packageURL)
		if err != nil || resp.StatusCode() != 200 {
			continue
		}

		var packageData struct {
			Name        string `json:"name"`
			Version     string `json:"version"`
			Description string `json:"description"`
			Author      struct {
				Name  string `json:"name"`
				Email string `json:"email"`
			} `json:"author"`
			Keywords []string `json:"keywords"`
			Config   struct {
				Posts_per_page int `json:"posts_per_page"`
			} `json:"config"`
		}

		err = json.Unmarshal(resp.Body(), &packageData)
		if err != nil {
			continue
		}

		theme := &GhostTheme{
			Name:        packageData.Name,
			Version:     packageData.Version,
			Description: packageData.Description,
			Author:      packageData.Author.Name,
			Path:        fmt.Sprintf("/content/themes/%s/", themeName),
			URL:         fmt.Sprintf("%s/content/themes/%s/", te.baseURL, themeName),
			PackageJSON: string(resp.Body()),
			Custom:      !te.isDefaultTheme(packageData.Name),
		}

		// Generate fingerprint
		theme.Fingerprint = te.generateThemeFingerprint(theme)

		themes = append(themes, theme)
		te.applyDelay()
	}

	return themes, nil
}

// detectPopularThemes detects popular Ghost themes using fingerprinting
func (te *ThemeEnumerator) detectPopularThemes() ([]*GhostTheme, error) {
	var themes []*GhostTheme

	// Get known theme database
	knownThemes := te.getKnownThemes()

	for _, knownTheme := range knownThemes {
		if te.isThemePresent(knownTheme) {
			theme := &GhostTheme{
				Name:   knownTheme.Name,
				Custom: !te.isDefaultTheme(knownTheme.Name),
				Path:   fmt.Sprintf("/content/themes/%s/", knownTheme.Name),
				URL:    fmt.Sprintf("%s/content/themes/%s/", te.baseURL, knownTheme.Name),
			}

			// Try to detect version
			version := te.detectThemeVersion(knownTheme)
			if version != "" {
				theme.Version = version
			}

			// Check for vulnerabilities
			if len(knownTheme.Vulns) > 0 {
				theme.Vulns = knownTheme.Vulns
				theme.Vulnerable = true
				theme.RiskScore = te.calculateRiskScore(knownTheme.Vulns)
			}

			themes = append(themes, theme)
		}
		te.applyDelay()
	}

	return themes, nil
}

// enrichThemeInfo enriches theme information with additional details
func (te *ThemeEnumerator) enrichThemeInfo(theme *GhostTheme) {
	if theme.Name == "" {
		return
	}

	// Try to get package.json
	packageURL := fmt.Sprintf("%s/content/themes/%s/package.json", te.baseURL, theme.Name)
	resp, err := te.client.R().Get(packageURL)
	if err == nil && resp.StatusCode() == 200 {
		var packageData struct {
			Version     string `json:"version"`
			Description string `json:"description"`
			Author      struct {
				Name string `json:"name"`
			} `json:"author"`
		}

		if json.Unmarshal(resp.Body(), &packageData) == nil {
			if theme.Version == "" {
				theme.Version = packageData.Version
			}
			if theme.Description == "" {
				theme.Description = packageData.Description
			}
			if theme.Author == "" {
				theme.Author = packageData.Author.Name
			}
			theme.PackageJSON = string(resp.Body())
		}
	}

	// Try to get screenshot
	screenshotURL := fmt.Sprintf("%s/content/themes/%s/screenshot.png", te.baseURL, theme.Name)
	resp, err = te.client.R().Head(screenshotURL)
	if err == nil && resp.StatusCode() == 200 {
		theme.Screenshot = screenshotURL
	}

	// Check if it's a default theme
	theme.Custom = !te.isDefaultTheme(theme.Name)

	// Generate fingerprint
	theme.Fingerprint = te.generateThemeFingerprint(theme)
}

// getThemeFiles attempts to discover theme files
func (te *ThemeEnumerator) getThemeFiles(themeName string) []string {
	var files []string

	// Common theme files to check
	commonFiles := []string{
		"index.hbs", "post.hbs", "page.hbs", "tag.hbs", "author.hbs",
		"default.hbs", "partials/navigation.hbs", "assets/css/screen.css",
		"assets/js/index.js", "package.json", "screenshot.png",
	}

	for _, file := range commonFiles {
		fileURL := fmt.Sprintf("%s/content/themes/%s/%s", te.baseURL, themeName, file)
		resp, err := te.client.R().Head(fileURL)
		if err == nil && resp.StatusCode() == 200 {
			files = append(files, file)
		}
	}

	return files
}

// isDefaultTheme checks if a theme is a default Ghost theme
func (te *ThemeEnumerator) isDefaultTheme(themeName string) bool {
	defaultThemes := []string{"casper", "dawn", "edition", "london", "massively", "simply"}
	for _, defaultTheme := range defaultThemes {
		if strings.EqualFold(themeName, defaultTheme) {
			return true
		}
	}
	return false
}

// generateThemeFingerprint generates a unique fingerprint for the theme
func (te *ThemeEnumerator) generateThemeFingerprint(theme *GhostTheme) string {
	data := fmt.Sprintf("%s:%s:%s:%s", theme.Name, theme.Version, theme.Author, theme.Description)
	hash := md5.Sum([]byte(data))
	return fmt.Sprintf("%x", hash)
}

// getKnownThemes returns a database of known Ghost themes
func (te *ThemeEnumerator) getKnownThemes() []KnownTheme {
	return []KnownTheme{
		{
			Name:    "casper",
			Popular: true,
			Versions: map[string]string{
				"4.8.0": "Ghost 4.x default theme",
				"5.0.0": "Ghost 5.x default theme",
			},
			Fingerprints: map[string]string{
				"css_hash": "a1b2c3d4e5f6",
				"js_hash":  "f6e5d4c3b2a1",
			},
		},
		{
			Name:    "dawn",
			Popular: true,
			Versions: map[string]string{
				"1.0.0": "Newsletter-focused theme",
			},
		},
		{
			Name:    "edition",
			Popular: true,
			Versions: map[string]string{
				"1.0.0": "Publication theme",
			},
		},
		{
			Name:    "london",
			Popular: true,
			Versions: map[string]string{
				"1.0.0": "Magazine-style theme",
			},
		},
		{
			Name:    "attila",
			Popular: true,
			Versions: map[string]string{
				"1.8.0": "Popular community theme",
			},
			Vulns: []ThemeVuln{
				{
					Title:       "XSS in Comment Section",
					Severity:    "Medium",
					Description: "Cross-site scripting vulnerability in comment handling",
					Fixed:       "1.8.1",
				},
			},
		},
	}
}

// isThemePresent checks if a known theme is present on the target
func (te *ThemeEnumerator) isThemePresent(knownTheme KnownTheme) bool {
	// Check if theme directory exists
	themeURL := fmt.Sprintf("%s/content/themes/%s/", te.baseURL, knownTheme.Name)
	resp, err := te.client.R().Head(themeURL)
	if err != nil || (resp.StatusCode() != 200 && resp.StatusCode() != 403) {
		return false
	}

	// Additional fingerprinting checks could be added here
	return true
}

// detectThemeVersion attempts to detect the version of a known theme
func (te *ThemeEnumerator) detectThemeVersion(knownTheme KnownTheme) string {
	// Try package.json first
	packageURL := fmt.Sprintf("%s/content/themes/%s/package.json", te.baseURL, knownTheme.Name)
	resp, err := te.client.R().Get(packageURL)
	if err == nil && resp.StatusCode() == 200 {
		var packageData struct {
			Version string `json:"version"`
		}
		if json.Unmarshal(resp.Body(), &packageData) == nil {
			return packageData.Version
		}
	}

	// Fallback to fingerprinting
	for version := range knownTheme.Versions {
		if te.matchesVersionFingerprint(knownTheme.Name, version, knownTheme.Fingerprints) {
			return version
		}
	}

	return ""
}

// matchesVersionFingerprint checks if theme matches version-specific fingerprints
func (te *ThemeEnumerator) matchesVersionFingerprint(themeName, version string, fingerprints map[string]string) bool {
	// This would implement actual fingerprinting logic
	// For now, return false as placeholder
	return false
}

// checkThemeVulnerabilities checks a theme for known vulnerabilities
func (te *ThemeEnumerator) checkThemeVulnerabilities(theme *GhostTheme) []ThemeVuln {
	var vulns []ThemeVuln

	// Get known themes database
	knownThemes := te.getKnownThemes()

	for _, knownTheme := range knownThemes {
		if strings.EqualFold(theme.Name, knownTheme.Name) {
			// Check if current version is vulnerable
			for _, vuln := range knownTheme.Vulns {
				if te.isVersionVulnerable(theme.Version, vuln.Fixed) {
					vulns = append(vulns, vuln)
				}
			}
			break
		}
	}

	return vulns
}

// isVersionVulnerable checks if a version is vulnerable
func (te *ThemeEnumerator) isVersionVulnerable(currentVersion, fixedVersion string) bool {
	if currentVersion == "" || fixedVersion == "" {
		return true // Assume vulnerable if version unknown
	}

	// Simple version comparison (would need more sophisticated logic for real use)
	return te.compareVersions(currentVersion, fixedVersion) < 0
}

// compareVersions compares two version strings
func (te *ThemeEnumerator) compareVersions(v1, v2 string) int {
	// Simple version comparison implementation
	parts1 := strings.Split(v1, ".")
	parts2 := strings.Split(v2, ".")

	maxLen := len(parts1)
	if len(parts2) > maxLen {
		maxLen = len(parts2)
	}

	for i := 0; i < maxLen; i++ {
		var p1, p2 int
		if i < len(parts1) {
			p1, _ = strconv.Atoi(parts1[i])
		}
		if i < len(parts2) {
			p2, _ = strconv.Atoi(parts2[i])
		}

		if p1 < p2 {
			return -1
		} else if p1 > p2 {
			return 1
		}
	}

	return 0
}

// calculateRiskScore calculates a risk score based on vulnerabilities
func (te *ThemeEnumerator) calculateRiskScore(vulns []ThemeVuln) int {
	score := 0
	for _, vuln := range vulns {
		switch strings.ToLower(vuln.Severity) {
		case "critical":
			score += 10
		case "high":
			score += 7
		case "medium":
			score += 4
		case "low":
			score += 1
		}
	}
	return score
}

// applyDelay applies configured delay between requests
func (te *ThemeEnumerator) applyDelay() {
	if te.config.Delay > 0 {
		if te.config.RandomDelay {
			// Add random variation (50-150% of base delay)
			variation := time.Duration(float64(te.config.Delay) * (0.5 + (float64(time.Now().UnixNano()%100) / 100.0)))
			time.Sleep(variation)
		} else {
			time.Sleep(te.config.Delay)
		}
	}
}

// SetVerbose sets verbose output mode
func (te *ThemeEnumerator) SetVerbose(verbose bool) {
	te.verbose = verbose
}