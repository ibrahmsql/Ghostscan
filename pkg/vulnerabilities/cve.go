package vulnerabilities

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// CVE represents a Common Vulnerabilities and Exposures entry
type CVE struct {
	ID          string    `json:"id"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"`
	CVSS        float64   `json:"cvss"`
	Published   time.Time `json:"published"`
	Modified    time.Time `json:"modified"`
	References  []string  `json:"references"`
	Affected    []string  `json:"affected_versions"`
	Fixed       []string  `json:"fixed_versions"`
	Exploit     *Exploit  `json:"exploit,omitempty"`
}

// Exploit represents an exploit for a vulnerability
type Exploit struct {
	Type        string            `json:"type"`
	Method      string            `json:"method"`
	Endpoint    string            `json:"endpoint"`
	Payload     string            `json:"payload"`
	Headers     map[string]string `json:"headers,omitempty"`
	Parameters  map[string]string `json:"parameters,omitempty"`
	Description string            `json:"description"`
	Reliable    bool              `json:"reliable"`
}

// VulnerabilityDatabase holds all known Ghost CMS vulnerabilities
type VulnerabilityDatabase struct {
	CVEs        []CVE             `json:"cves"`
	Signatures  []Signature       `json:"signatures"`
	LastUpdated time.Time         `json:"last_updated"`
	Version     string            `json:"version"`
}

// Signature represents a detection signature for vulnerabilities
type Signature struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Type        string            `json:"type"`
	Pattern     string            `json:"pattern"`
	Endpoint    string            `json:"endpoint"`
	Method      string            `json:"method"`
	Headers     map[string]string `json:"headers,omitempty"`
	Body        string            `json:"body,omitempty"`
	Expected    ExpectedResponse  `json:"expected"`
	Severity    string            `json:"severity"`
	Description string            `json:"description"`
}

// ExpectedResponse defines what to expect from a vulnerability test
type ExpectedResponse struct {
	StatusCode   int      `json:"status_code,omitempty"`
	StatusCodes  []int    `json:"status_codes,omitempty"`
	BodyContains []string `json:"body_contains,omitempty"`
	BodyRegex    string   `json:"body_regex,omitempty"`
	Headers      map[string]string `json:"headers,omitempty"`
	Timeout      bool     `json:"timeout,omitempty"`
}

// GetGhostCVEDatabase returns the built-in Ghost CMS vulnerability database
func GetGhostCVEDatabase() *VulnerabilityDatabase {
	return &VulnerabilityDatabase{
		CVEs: []CVE{
			{
				ID:          "CVE-2023-32235",
				Title:       "Path Traversal in Theme Preview",
				Description: "Ghost CMS allows path traversal via theme preview functionality, enabling arbitrary file read",
				Severity:    "High",
				CVSS:        7.5,
				Published:   time.Date(2023, 5, 15, 0, 0, 0, 0, time.UTC),
				Modified:    time.Date(2023, 5, 20, 0, 0, 0, 0, time.UTC),
				References: []string{
					"https://nvd.nist.gov/vuln/detail/CVE-2023-32235",
					"https://github.com/TryGhost/Ghost/security/advisories",
				},
				Affected: []string{"<= 5.52.1"},
				Fixed:    []string{">= 5.52.2"},
				Exploit: &Exploit{
					Type:        "path_traversal",
					Method:      "GET",
					Endpoint:    "/ghost/api/v4/admin/themes/preview/",
					Payload:     "../../../etc/passwd",
					Description: "Attempts to read /etc/passwd via path traversal",
					Reliable:    true,
				},
			},
			{
				ID:          "CVE-2023-40028",
				Title:       "Arbitrary File Read via Theme Upload",
				Description: "Ghost CMS theme upload functionality allows arbitrary file read through malicious zip files",
				Severity:    "Critical",
				CVSS:        9.1,
				Published:   time.Date(2023, 8, 10, 0, 0, 0, 0, time.UTC),
				Modified:    time.Date(2023, 8, 15, 0, 0, 0, 0, time.UTC),
				References: []string{
					"https://nvd.nist.gov/vuln/detail/CVE-2023-40028",
					"https://github.com/TryGhost/Ghost/security/advisories",
				},
				Affected: []string{"<= 5.58.0"},
				Fixed:    []string{">= 5.58.1"},
				Exploit: &Exploit{
					Type:        "file_upload",
					Method:      "POST",
					Endpoint:    "/ghost/api/v4/admin/themes/upload/",
					Description: "Uploads malicious theme with symlinks to read arbitrary files",
					Reliable:    false,
				},
			},
			{
				ID:          "CVE-2024-23724",
				Title:       "Stored XSS via Profile Image",
				Description: "Ghost CMS allows stored XSS through SVG profile image uploads",
				Severity:    "Medium",
				CVSS:        6.1,
				Published:   time.Date(2024, 1, 20, 0, 0, 0, 0, time.UTC),
				Modified:    time.Date(2024, 1, 25, 0, 0, 0, 0, time.UTC),
				References: []string{
					"https://nvd.nist.gov/vuln/detail/CVE-2024-23724",
					"https://github.com/TryGhost/Ghost/security/advisories",
				},
				Affected: []string{"4.0.0 - 5.75.0"},
				Fixed:    []string{">= 5.75.1"},
				Exploit: &Exploit{
					Type:        "xss",
					Method:      "POST",
					Endpoint:    "/ghost/api/v4/admin/images/upload/",
					Payload:     "<svg onload=alert('XSS')></svg>",
					Description: "Uploads SVG with XSS payload as profile image",
					Reliable:    true,
				},
			},
			{
				ID:          "CVE-2023-31133",
				Title:       "Authentication Bypass via JWT",
				Description: "Ghost CMS JWT token validation vulnerability allows authentication bypass",
				Severity:    "Critical",
				CVSS:        9.8,
				Published:   time.Date(2023, 6, 5, 0, 0, 0, 0, time.UTC),
				Modified:    time.Date(2023, 6, 10, 0, 0, 0, 0, time.UTC),
				References: []string{
					"https://nvd.nist.gov/vuln/detail/CVE-2023-31133",
					"https://github.com/TryGhost/Ghost/security/advisories",
				},
				Affected: []string{"4.0.0 - 5.50.0"},
				Fixed:    []string{">= 5.50.1"},
				Exploit: &Exploit{
					Type:        "auth_bypass",
					Method:      "POST",
					Endpoint:    "/ghost/api/v4/admin/session/",
					Description: "Exploits JWT validation flaw to bypass authentication",
					Reliable:    false,
				},
			},
			{
				ID:          "CVE-2024-27913",
				Title:       "Template Injection in Handlebars",
				Description: "Ghost CMS Handlebars template engine allows server-side template injection",
				Severity:    "High",
				CVSS:        8.1,
				Published:   time.Date(2024, 3, 12, 0, 0, 0, 0, time.UTC),
				Modified:    time.Date(2024, 3, 18, 0, 0, 0, 0, time.UTC),
				References: []string{
					"https://nvd.nist.gov/vuln/detail/CVE-2024-27913",
					"https://github.com/TryGhost/Ghost/security/advisories",
				},
				Affected: []string{"5.0.0 - 5.80.0"},
				Fixed:    []string{">= 5.80.1"},
				Exploit: &Exploit{
					Type:        "template_injection",
					Method:      "POST",
					Endpoint:    "/ghost/api/v4/admin/posts/",
					Payload:     "{{#each (lookup (lookup this 'constructor') 'constructor') }}{{this}}{{/each}}",
					Description: "Injects malicious Handlebars template code",
					Reliable:    true,
				},
			},
		},
		Signatures: []Signature{
			{
				ID:       "GHOST-SIG-001",
				Name:     "Ghost Admin Interface Detection",
				Type:     "detection",
				Endpoint: "/ghost/",
				Method:   "GET",
				Expected: ExpectedResponse{
					StatusCodes:  []int{200, 302},
					BodyContains: []string{"Ghost", "admin"},
				},
				Severity:    "Info",
				Description: "Detects Ghost admin interface accessibility",
			},
			{
				ID:       "GHOST-SIG-002",
				Name:     "Ghost API Endpoint Exposure",
				Type:     "misconfiguration",
				Endpoint: "/ghost/api/v4/admin/site/",
				Method:   "GET",
				Expected: ExpectedResponse{
					StatusCode:   200,
					BodyContains: []string{"version", "title"},
				},
				Severity:    "Medium",
				Description: "Ghost admin API accessible without authentication",
			},
			{
				ID:       "GHOST-SIG-003",
				Name:     "Content Directory Browsing",
				Type:     "misconfiguration",
				Endpoint: "/content/",
				Method:   "GET",
				Expected: ExpectedResponse{
					StatusCode:   200,
					BodyContains: []string{"Index of", "Parent Directory"},
				},
				Severity:    "High",
				Description: "Ghost content directory allows directory browsing",
			},
			{
				ID:       "GHOST-SIG-004",
				Name:     "Debug Mode Detection",
				Type:     "misconfiguration",
				Endpoint: "/ghost/api/v4/admin/site/",
				Method:   "GET",
				Expected: ExpectedResponse{
					BodyContains: []string{"development", "debug"},
				},
				Severity:    "Medium",
				Description: "Ghost running in debug/development mode",
			},
			{
				ID:       "GHOST-SIG-005",
				Name:     "Exposed Configuration Files",
				Type:     "misconfiguration",
				Endpoint: "/.env",
				Method:   "GET",
				Expected: ExpectedResponse{
					StatusCode:   200,
					BodyContains: []string{"database", "password", "secret"},
				},
				Severity:    "Critical",
				Description: "Ghost .env configuration file exposed",
			},
		},
		LastUpdated: time.Now(),
		Version:     "1.0.0",
	}
}

// IsVersionAffected checks if a given version is affected by a CVE
func (cve *CVE) IsVersionAffected(version string) bool {
	for _, affected := range cve.Affected {
		if matchesVersionRange(version, affected) {
			return true
		}
	}
	return false
}

// IsVersionFixed checks if a given version has the CVE fixed
func (cve *CVE) IsVersionFixed(version string) bool {
	for _, fixed := range cve.Fixed {
		if matchesVersionRange(version, fixed) {
			return true
		}
	}
	return false
}

// matchesVersionRange checks if a version matches a version range pattern
func matchesVersionRange(version, pattern string) bool {
	// Simple version matching - can be enhanced with proper semver
	if strings.HasPrefix(pattern, "<=") {
		threshold := strings.TrimSpace(pattern[2:])
		return compareVersions(version, threshold) <= 0
	}
	if strings.HasPrefix(pattern, ">=") {
		threshold := strings.TrimSpace(pattern[2:])
		return compareVersions(version, threshold) >= 0
	}
	if strings.HasPrefix(pattern, "<") {
		threshold := strings.TrimSpace(pattern[1:])
		return compareVersions(version, threshold) < 0
	}
	if strings.HasPrefix(pattern, ">") {
		threshold := strings.TrimSpace(pattern[1:])
		return compareVersions(version, threshold) > 0
	}
	if strings.Contains(pattern, " - ") {
		parts := strings.Split(pattern, " - ")
		if len(parts) == 2 {
			min := strings.TrimSpace(parts[0])
			max := strings.TrimSpace(parts[1])
			return compareVersions(version, min) >= 0 && compareVersions(version, max) <= 0
		}
	}
	return version == pattern
}

// compareVersions compares two version strings
// Returns: -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2
func compareVersions(v1, v2 string) int {
	// Simple string comparison - should be replaced with proper semver
	return strings.Compare(v1, v2)
}

// GetCVEsBySeverity returns CVEs filtered by severity
func (db *VulnerabilityDatabase) GetCVEsBySeverity(severity string) []CVE {
	var result []CVE
	for _, cve := range db.CVEs {
		if strings.EqualFold(cve.Severity, severity) {
			result = append(result, cve)
		}
	}
	return result
}

// GetCVEsForVersion returns CVEs that affect a specific Ghost version
func (db *VulnerabilityDatabase) GetCVEsForVersion(version string) []CVE {
	var result []CVE
	for _, cve := range db.CVEs {
		if cve.IsVersionAffected(version) && !cve.IsVersionFixed(version) {
			result = append(result, cve)
		}
	}
	return result
}

// GetSignaturesByType returns signatures filtered by type
func (db *VulnerabilityDatabase) GetSignaturesByType(sigType string) []Signature {
	var result []Signature
	for _, sig := range db.Signatures {
		if strings.EqualFold(sig.Type, sigType) {
			result = append(result, sig)
		}
	}
	return result
}

// ToJSON converts the vulnerability database to JSON
func (db *VulnerabilityDatabase) ToJSON() ([]byte, error) {
	return json.MarshalIndent(db, "", "  ")
}

// FromJSON loads vulnerability database from JSON
func FromJSON(data []byte) (*VulnerabilityDatabase, error) {
	var db VulnerabilityDatabase
	err := json.Unmarshal(data, &db)
	if err != nil {
		return nil, fmt.Errorf("failed to parse vulnerability database: %w", err)
	}
	return &db, nil
}