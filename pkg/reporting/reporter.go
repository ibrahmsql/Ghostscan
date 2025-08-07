package reporting

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/ibrahmsql/ghostscan/pkg/exploits"
	"github.com/ibrahmsql/ghostscan/pkg/scanner"
)

// ScanReport represents a comprehensive scan report
type ScanReport struct {
	Metadata        ReportMetadata           `json:"metadata"`
	Target          TargetInfo               `json:"target"`
	Detection       *DetectionResults        `json:"detection,omitempty"`
	Vulnerabilities []VulnerabilityResult    `json:"vulnerabilities,omitempty"`
	Exploits        []ExploitResult          `json:"exploits,omitempty"`
	Enumeration     *EnumerationResults      `json:"enumeration,omitempty"`
	BruteForce      *BruteForceResults       `json:"brute_force,omitempty"`
	Summary         ScanSummary              `json:"summary"`
	Recommendations []SecurityRecommendation `json:"recommendations,omitempty"`
}

// ReportMetadata contains report generation information
type ReportMetadata struct {
	GeneratedAt   time.Time `json:"generated_at"`
	ScanDuration  string    `json:"scan_duration"`
	ToolVersion   string    `json:"tool_version"`
	ScannerConfig ScanConfig `json:"scanner_config"`
}

// TargetInfo contains information about the scanned target
type TargetInfo struct {
	URL         string            `json:"url"`
	IPAddress   string            `json:"ip_address,omitempty"`
	Hostname    string            `json:"hostname,omitempty"`
	Port        int               `json:"port,omitempty"`
	SSL         bool              `json:"ssl"`
	Headers     map[string]string `json:"headers,omitempty"`
	StatusCode  int               `json:"status_code,omitempty"`
	ContentType string            `json:"content_type,omitempty"`
}

// DetectionResults contains Ghost CMS detection results
type DetectionResults struct {
	IsGhost     bool              `json:"is_ghost"`
	Confidence  float64           `json:"confidence"`
	Version     string            `json:"version,omitempty"`
	Fingerprint map[string]string `json:"fingerprint,omitempty"`
	Indicators  []string          `json:"indicators,omitempty"`
}

// VulnerabilityResult represents a vulnerability finding
type VulnerabilityResult struct {
	CVE         string                 `json:"cve,omitempty"`
	Title       string                 `json:"title"`
	Severity    string                 `json:"severity"`
	Description string                 `json:"description"`
	Affected    bool                   `json:"affected"`
	Evidence    []Evidence             `json:"evidence,omitempty"`
	References  []string               `json:"references,omitempty"`
	CVSS        float64                `json:"cvss,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// ExploitResult represents an exploit attempt result
type ExploitResult struct {
	ExploitID   string                 `json:"exploit_id"`
	Name        string                 `json:"name"`
	Success     bool                   `json:"success"`
	Severity    string                 `json:"severity"`
	Description string                 `json:"description"`
	Evidence    []Evidence             `json:"evidence,omitempty"`
	Payload     string                 `json:"payload,omitempty"`
	Response    *HTTPResponse          `json:"response,omitempty"`
	Timestamp   time.Time              `json:"timestamp"`
	Duration    time.Duration          `json:"duration"`
}

// EnumerationResults contains enumeration findings
type EnumerationResults struct {
	Themes       []ThemeInfo       `json:"themes,omitempty"`
	Users        []UserInfo        `json:"users,omitempty"`
	Posts        []PostInfo        `json:"posts,omitempty"`
	Tags         []TagInfo         `json:"tags,omitempty"`
	Integrations []IntegrationInfo `json:"integrations,omitempty"`
	Endpoints    []EndpointInfo    `json:"endpoints,omitempty"`
}

// BruteForceResults contains brute force attack results
type BruteForceResults struct {
	Attempted     int                    `json:"attempted"`
	Successful    int                    `json:"successful"`
	Credentials   []CredentialResult     `json:"credentials,omitempty"`
	RateLimit     *RateLimitInfo         `json:"rate_limit,omitempty"`
	Duration      time.Duration          `json:"duration"`
	Blocked       bool                   `json:"blocked"`
}

// ScanSummary provides an overview of scan results
type ScanSummary struct {
	TotalVulnerabilities int               `json:"total_vulnerabilities"`
	CriticalCount        int               `json:"critical_count"`
	HighCount            int               `json:"high_count"`
	MediumCount          int               `json:"medium_count"`
	LowCount             int               `json:"low_count"`
	InfoCount            int               `json:"info_count"`
	ExploitableCount     int               `json:"exploitable_count"`
	RiskScore            float64           `json:"risk_score"`
	SecurityPosture      string            `json:"security_posture"`
	TopVulnerabilities   []string          `json:"top_vulnerabilities,omitempty"`
}

// SecurityRecommendation provides security improvement suggestions
type SecurityRecommendation struct {
	Category    string   `json:"category"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Priority    string   `json:"priority"`
	Steps       []string `json:"steps,omitempty"`
	References  []string `json:"references,omitempty"`
}

// Supporting types
type ScanConfig struct {
	UserAgent   string `json:"user_agent"`
	Timeout     int    `json:"timeout"`
	Threads     int    `json:"threads"`
	Verbose     bool   `json:"verbose"`
	Enumeration bool   `json:"enumeration"`
	BruteForce  bool   `json:"brute_force"`
}

type Evidence struct {
	Type        string `json:"type"`
	Description string `json:"description"`
	Data        string `json:"data"`
	Location    string `json:"location,omitempty"`
}

type HTTPResponse struct {
	StatusCode int               `json:"status_code"`
	Headers    map[string]string `json:"headers"`
	Body       string            `json:"body,omitempty"`
	Size       int               `json:"size"`
}

type ThemeInfo struct {
	Name        string   `json:"name"`
	Version     string   `json:"version,omitempty"`
	Active      bool     `json:"active"`
	Vulnerable  bool     `json:"vulnerable,omitempty"`
	Description string   `json:"description,omitempty"`
	Author      string   `json:"author,omitempty"`
	Files       []string `json:"files,omitempty"`
}

type UserInfo struct {
	ID       string `json:"id,omitempty"`
	Slug     string `json:"slug"`
	Name     string `json:"name,omitempty"`
	Email    string `json:"email,omitempty"`
	Role     string `json:"role,omitempty"`
	Status   string `json:"status,omitempty"`
	Location string `json:"location,omitempty"`
	Website  string `json:"website,omitempty"`
}

type PostInfo struct {
	ID          string    `json:"id,omitempty"`
	Slug        string    `json:"slug"`
	Title       string    `json:"title,omitempty"`
	Status      string    `json:"status,omitempty"`
	PublishedAt time.Time `json:"published_at,omitempty"`
	Author      string    `json:"author,omitempty"`
	Tags        []string  `json:"tags,omitempty"`
}

type TagInfo struct {
	ID          string `json:"id,omitempty"`
	Slug        string `json:"slug"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
	PostCount   int    `json:"post_count,omitempty"`
}

type IntegrationInfo struct {
	Name        string            `json:"name"`
	Type        string            `json:"type"`
	Enabled     bool              `json:"enabled"`
	Version     string            `json:"version,omitempty"`
	Config      map[string]string `json:"config,omitempty"`
	Vulnerable  bool              `json:"vulnerable,omitempty"`
}

type EndpointInfo struct {
	Path        string `json:"path"`
	Method      string `json:"method"`
	StatusCode  int    `json:"status_code"`
	ContentType string `json:"content_type,omitempty"`
	Size        int    `json:"size,omitempty"`
	Accessible  bool   `json:"accessible"`
}

type CredentialResult struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Success  bool   `json:"success"`
	Response string `json:"response,omitempty"`
}

type RateLimitInfo struct {
	Detected    bool          `json:"detected"`
	Limit       int           `json:"limit,omitempty"`
	Window      time.Duration `json:"window,omitempty"`
	Bypassable  bool          `json:"bypassable,omitempty"`
}

// Reporter handles report generation and formatting
type Reporter struct {
	verbose bool
	format  string
}

// NewReporter creates a new reporter instance
func NewReporter(verbose bool, format string) *Reporter {
	return &Reporter{
		verbose: verbose,
		format:  format,
	}
}

// GenerateReport creates a comprehensive scan report
func (r *Reporter) GenerateReport(scanResults *scanner.ScanResult, exploitResults []*exploits.ExploitResult, startTime time.Time, targetURL string) *ScanReport {
	report := &ScanReport{
		Metadata: ReportMetadata{
			GeneratedAt:  time.Now(),
			ScanDuration: time.Since(startTime).String(),
			ToolVersion:  "1.0.0",
			ScannerConfig: ScanConfig{
				UserAgent:   "GhostScan/1.0",
				Timeout:     10,
				Verbose:     r.verbose,
			},
		},
		Target: TargetInfo{
			URL: targetURL,
			SSL: strings.HasPrefix(targetURL, "https://"),
		},
	}

	// Convert detection results
	if scanResults.IsGhost {
		report.Detection = &DetectionResults{
			IsGhost:     scanResults.IsGhost,
			Confidence:  100.0, // Default confidence
			Version:     scanResults.Version,
			Fingerprint: scanResults.Headers,
		}
	}

	// Convert vulnerability results
	for _, vuln := range scanResults.Vulns {
		vulnResult := VulnerabilityResult{
			CVE:         vuln.CVE,
			Title:       vuln.Title,
			Severity:    vuln.Severity,
			Description: vuln.Description,
			Affected:    true, // Assuming affected if detected
		}
		report.Vulnerabilities = append(report.Vulnerabilities, vulnResult)
	}

	// Convert exploit results
	for _, exploit := range exploitResults {
		exploitResult := ExploitResult{
			ExploitID:   exploit.ExploitID,
			Name:        exploit.Name,
			Success:     exploit.Success,
			Severity:    exploit.Severity,
			Description: exploit.Description,
			Payload:     exploit.Payload,
			Timestamp:   exploit.Timestamp,
			Duration:    exploit.Duration,
		}
		
		// Convert evidence
		for _, evidence := range exploit.Evidence {
			exploitResult.Evidence = append(exploitResult.Evidence, Evidence{
				Type:        evidence.Type,
				Description: evidence.Description,
				Data:        evidence.Data,
				Location:    evidence.Location,
			})
		}
		
		// Convert HTTP response
		if exploit.Response != nil {
			exploitResult.Response = &HTTPResponse{
				StatusCode: exploit.Response.StatusCode,
				Headers:    exploit.Response.Headers,
				Body:       exploit.Response.Body,
				Size:       exploit.Response.Size,
			}
		}
		
		report.Exploits = append(report.Exploits, exploitResult)
	}

	// Generate summary
	report.Summary = r.generateSummary(report)

	// Generate recommendations
	report.Recommendations = r.generateRecommendations(report)

	return report
}

// generateSummary creates a summary of scan results
func (r *Reporter) generateSummary(report *ScanReport) ScanSummary {
	summary := ScanSummary{}

	// Count vulnerabilities by severity
	for _, vuln := range report.Vulnerabilities {
		summary.TotalVulnerabilities++
		switch strings.ToLower(vuln.Severity) {
		case "critical":
			summary.CriticalCount++
		case "high":
			summary.HighCount++
		case "medium":
			summary.MediumCount++
		case "low":
			summary.LowCount++
		default:
			summary.InfoCount++
		}
	}

	// Count successful exploits
	for _, exploit := range report.Exploits {
		if exploit.Success {
			summary.ExploitableCount++
		}
	}

	// Calculate risk score
	summary.RiskScore = r.calculateRiskScore(summary)

	// Determine security posture
	summary.SecurityPosture = r.determineSecurityPosture(summary)

	// Get top vulnerabilities
	summary.TopVulnerabilities = r.getTopVulnerabilities(report.Vulnerabilities)

	return summary
}

// calculateRiskScore calculates an overall risk score
func (r *Reporter) calculateRiskScore(summary ScanSummary) float64 {
	score := float64(summary.CriticalCount*10 + summary.HighCount*7 + summary.MediumCount*4 + summary.LowCount*2 + summary.InfoCount*1)
	maxScore := 100.0
	if score > maxScore {
		score = maxScore
	}
	return score
}

// determineSecurityPosture determines the overall security posture
func (r *Reporter) determineSecurityPosture(summary ScanSummary) string {
	if summary.CriticalCount > 0 || summary.ExploitableCount > 0 {
		return "Critical"
	}
	if summary.HighCount > 2 {
		return "Poor"
	}
	if summary.HighCount > 0 || summary.MediumCount > 3 {
		return "Fair"
	}
	if summary.MediumCount > 0 || summary.LowCount > 5 {
		return "Good"
	}
	return "Excellent"
}

// getTopVulnerabilities returns the most critical vulnerabilities
func (r *Reporter) getTopVulnerabilities(vulnerabilities []VulnerabilityResult) []string {
	// Sort by severity and get top 5
	sort.Slice(vulnerabilities, func(i, j int) bool {
		severityOrder := map[string]int{
			"critical": 5,
			"high":     4,
			"medium":   3,
			"low":      2,
			"info":     1,
		}
		return severityOrder[strings.ToLower(vulnerabilities[i].Severity)] > severityOrder[strings.ToLower(vulnerabilities[j].Severity)]
	})

	var top []string
	for i, vuln := range vulnerabilities {
		if i >= 5 {
			break
		}
		if vuln.CVE != "" {
			top = append(top, vuln.CVE)
		} else {
			top = append(top, vuln.Title)
		}
	}

	return top
}

// generateRecommendations generates security recommendations
func (r *Reporter) generateRecommendations(report *ScanReport) []SecurityRecommendation {
	var recommendations []SecurityRecommendation

	// Version-based recommendations
	if report.Detection != nil && report.Detection.Version != "" {
		recommendations = append(recommendations, SecurityRecommendation{
			Category:    "Version Management",
			Title:       "Update Ghost CMS",
			Description: "Ensure Ghost CMS is updated to the latest stable version",
			Priority:    "High",
			Steps: []string{
				"Check current Ghost version",
				"Review release notes for security updates",
				"Backup your Ghost installation",
				"Update to the latest stable version",
				"Test functionality after update",
			},
			References: []string{
				"https://ghost.org/docs/update/",
				"https://github.com/TryGhost/Ghost/releases",
			},
		})
	}

	// Critical vulnerability recommendations
	if report.Summary.CriticalCount > 0 {
		recommendations = append(recommendations, SecurityRecommendation{
			Category:    "Critical Security",
			Title:       "Address Critical Vulnerabilities",
			Description: "Critical vulnerabilities require immediate attention",
			Priority:    "Critical",
			Steps: []string{
				"Review all critical vulnerabilities",
				"Apply security patches immediately",
				"Consider taking the site offline if necessary",
				"Monitor for exploitation attempts",
				"Implement additional security controls",
			},
		})
	}

	// Exploit-based recommendations
	if report.Summary.ExploitableCount > 0 {
		recommendations = append(recommendations, SecurityRecommendation{
			Category:    "Exploit Prevention",
			Title:       "Mitigate Exploitable Vulnerabilities",
			Description: "Active exploits were successful and require immediate mitigation",
			Priority:    "Critical",
			Steps: []string{
				"Review successful exploit attempts",
				"Check for signs of compromise",
				"Apply security patches",
				"Implement WAF rules",
				"Monitor access logs",
			},
		})
	}

	// General security recommendations
	recommendations = append(recommendations, []SecurityRecommendation{
		{
			Category:    "Access Control",
			Title:       "Secure Admin Interface",
			Description: "Protect the Ghost admin interface from unauthorized access",
			Priority:    "High",
			Steps: []string{
				"Use strong, unique passwords",
				"Enable two-factor authentication",
				"Restrict admin access by IP",
				"Use HTTPS for all admin access",
				"Regularly review user accounts",
			},
		},
		{
			Category:    "Configuration",
			Title:       "Harden Ghost Configuration",
			Description: "Implement security best practices in Ghost configuration",
			Priority:    "Medium",
			Steps: []string{
				"Disable debug mode in production",
				"Configure proper file permissions",
				"Use environment variables for secrets",
				"Enable security headers",
				"Configure rate limiting",
			},
		},
		{
			Category:    "Monitoring",
			Title:       "Implement Security Monitoring",
			Description: "Set up monitoring and alerting for security events",
			Priority:    "Medium",
			Steps: []string{
				"Enable Ghost logging",
				"Monitor failed login attempts",
				"Set up file integrity monitoring",
				"Implement intrusion detection",
				"Regular security scans",
			},
		},
	}...)

	return recommendations
}

// FormatReport formats the report according to the specified format
func (r *Reporter) FormatReport(report *ScanReport) (string, error) {
	switch r.format {
	case "json":
		return r.formatJSON(report)
	case "text":
		return r.formatText(report)
	case "html":
		return r.formatHTML(report)
	default:
		return r.formatText(report)
	}
}

// formatJSON formats the report as JSON
func (r *Reporter) formatJSON(report *ScanReport) (string, error) {
	var jsonData []byte
	var err error
	
	if r.verbose {
		jsonData, err = json.MarshalIndent(report, "", "  ")
	} else {
		jsonData, err = json.Marshal(report)
	}
	
	if err != nil {
		return "", fmt.Errorf("failed to marshal JSON: %v", err)
	}
	
	return string(jsonData), nil
}

// formatText formats the report as plain text
func (r *Reporter) formatText(report *ScanReport) (string, error) {
	var output strings.Builder

	// Header
	output.WriteString("\n" + strings.Repeat("=", 60) + "\n")
	output.WriteString("                    GHOSTSCAN REPORT\n")
	output.WriteString(strings.Repeat("=", 60) + "\n\n")

	// Target Information
	output.WriteString("TARGET INFORMATION\n")
	output.WriteString(strings.Repeat("-", 20) + "\n")
	output.WriteString(fmt.Sprintf("URL: %s\n", report.Target.URL))
	if report.Target.IPAddress != "" {
		output.WriteString(fmt.Sprintf("IP Address: %s\n", report.Target.IPAddress))
	}
	output.WriteString(fmt.Sprintf("SSL: %t\n", report.Target.SSL))
	output.WriteString(fmt.Sprintf("Scan Duration: %s\n", report.Metadata.ScanDuration))
	output.WriteString("\n")

	// Detection Results
	if report.Detection != nil {
		output.WriteString("GHOST CMS DETECTION\n")
		output.WriteString(strings.Repeat("-", 20) + "\n")
		output.WriteString(fmt.Sprintf("Ghost Detected: %t\n", report.Detection.IsGhost))
		output.WriteString(fmt.Sprintf("Confidence: %.2f%%\n", report.Detection.Confidence*100))
		if report.Detection.Version != "" {
			output.WriteString(fmt.Sprintf("Version: %s\n", report.Detection.Version))
		}
		output.WriteString("\n")
	}

	// Summary
	output.WriteString("SCAN SUMMARY\n")
	output.WriteString(strings.Repeat("-", 20) + "\n")
	output.WriteString(fmt.Sprintf("Total Vulnerabilities: %d\n", report.Summary.TotalVulnerabilities))
	output.WriteString(fmt.Sprintf("Critical: %d, High: %d, Medium: %d, Low: %d\n",
		report.Summary.CriticalCount, report.Summary.HighCount,
		report.Summary.MediumCount, report.Summary.LowCount))
	output.WriteString(fmt.Sprintf("Exploitable: %d\n", report.Summary.ExploitableCount))
	output.WriteString(fmt.Sprintf("Risk Score: %.1f/100\n", report.Summary.RiskScore))
	output.WriteString(fmt.Sprintf("Security Posture: %s\n", report.Summary.SecurityPosture))
	output.WriteString("\n")

	// Vulnerabilities
	if len(report.Vulnerabilities) > 0 {
		output.WriteString("VULNERABILITIES\n")
		output.WriteString(strings.Repeat("-", 20) + "\n")
		for i, vuln := range report.Vulnerabilities {
			output.WriteString(fmt.Sprintf("%d. %s\n", i+1, vuln.Title))
			if vuln.CVE != "" {
				output.WriteString(fmt.Sprintf("   CVE: %s\n", vuln.CVE))
			}
			output.WriteString(fmt.Sprintf("   Severity: %s\n", vuln.Severity))
			output.WriteString(fmt.Sprintf("   Affected: %t\n", vuln.Affected))
			if r.verbose {
				output.WriteString(fmt.Sprintf("   Description: %s\n", vuln.Description))
			}
			output.WriteString("\n")
		}
	}

	// Successful Exploits
	successfulExploits := make([]ExploitResult, 0)
	for _, exploit := range report.Exploits {
		if exploit.Success {
			successfulExploits = append(successfulExploits, exploit)
		}
	}

	if len(successfulExploits) > 0 {
		output.WriteString("SUCCESSFUL EXPLOITS\n")
		output.WriteString(strings.Repeat("-", 20) + "\n")
		for i, exploit := range successfulExploits {
			output.WriteString(fmt.Sprintf("%d. %s\n", i+1, exploit.Name))
			output.WriteString(fmt.Sprintf("   Exploit ID: %s\n", exploit.ExploitID))
			output.WriteString(fmt.Sprintf("   Severity: %s\n", exploit.Severity))
			if r.verbose && exploit.Payload != "" {
				output.WriteString(fmt.Sprintf("   Payload: %s\n", exploit.Payload))
			}
			output.WriteString("\n")
		}
	}

	// Recommendations
	if len(report.Recommendations) > 0 {
		output.WriteString("SECURITY RECOMMENDATIONS\n")
		output.WriteString(strings.Repeat("-", 30) + "\n")
		for i, rec := range report.Recommendations {
			if i >= 5 && !r.verbose { // Limit to top 5 unless verbose
				break
			}
			output.WriteString(fmt.Sprintf("%d. %s [%s]\n", i+1, rec.Title, rec.Priority))
			output.WriteString(fmt.Sprintf("   %s\n", rec.Description))
			if r.verbose && len(rec.Steps) > 0 {
				output.WriteString("   Steps:\n")
				for _, step := range rec.Steps {
					output.WriteString(fmt.Sprintf("   - %s\n", step))
				}
			}
			output.WriteString("\n")
		}
	}

	// Footer
	output.WriteString(strings.Repeat("=", 60) + "\n")
	output.WriteString(fmt.Sprintf("Report generated at: %s\n", report.Metadata.GeneratedAt.Format("2006-01-02 15:04:05")))
	output.WriteString(fmt.Sprintf("GhostScan version: %s\n", report.Metadata.ToolVersion))
	output.WriteString(strings.Repeat("=", 60) + "\n")

	return output.String(), nil
}

// formatHTML formats the report as HTML
func (r *Reporter) formatHTML(report *ScanReport) (string, error) {
	// Basic HTML template - could be expanded with CSS styling
	html := `<!DOCTYPE html>
<html>
<head>
    <title>GhostScan Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #f0f0f0; padding: 20px; text-align: center; }
        .section { margin: 20px 0; }
        .vulnerability { border: 1px solid #ddd; padding: 10px; margin: 10px 0; }
        .critical { border-left: 5px solid #d32f2f; }
        .high { border-left: 5px solid #f57c00; }
        .medium { border-left: 5px solid #fbc02d; }
        .low { border-left: 5px solid #388e3c; }
        .success { color: #4caf50; }
        .failure { color: #f44336; }
    </style>
</head>
<body>
    <div class="header">
        <h1>GhostScan Security Report</h1>
        <p>Generated: ` + report.Metadata.GeneratedAt.Format("2006-01-02 15:04:05") + `</p>
    </div>
`

	// Add target information
	html += `    <div class="section">
        <h2>Target Information</h2>
        <p><strong>URL:</strong> ` + report.Target.URL + `</p>
        <p><strong>SSL:</strong> ` + fmt.Sprintf("%t", report.Target.SSL) + `</p>
        <p><strong>Scan Duration:</strong> ` + report.Metadata.ScanDuration + `</p>
    </div>
`

	// Add detection results
	if report.Detection != nil {
		html += `    <div class="section">
        <h2>Ghost CMS Detection</h2>
        <p><strong>Ghost Detected:</strong> ` + fmt.Sprintf("%t", report.Detection.IsGhost) + `</p>
        <p><strong>Confidence:</strong> ` + fmt.Sprintf("%.2f%%", report.Detection.Confidence*100) + `</p>
`
		if report.Detection.Version != "" {
			html += `        <p><strong>Version:</strong> ` + report.Detection.Version + `</p>
`
		}
		html += `    </div>
`
	}

	// Add summary
	html += `    <div class="section">
        <h2>Scan Summary</h2>
        <p><strong>Total Vulnerabilities:</strong> ` + fmt.Sprintf("%d", report.Summary.TotalVulnerabilities) + `</p>
        <p><strong>Critical:</strong> ` + fmt.Sprintf("%d", report.Summary.CriticalCount) + ` | <strong>High:</strong> ` + fmt.Sprintf("%d", report.Summary.HighCount) + ` | <strong>Medium:</strong> ` + fmt.Sprintf("%d", report.Summary.MediumCount) + ` | <strong>Low:</strong> ` + fmt.Sprintf("%d", report.Summary.LowCount) + `</p>
        <p><strong>Exploitable:</strong> ` + fmt.Sprintf("%d", report.Summary.ExploitableCount) + `</p>
        <p><strong>Risk Score:</strong> ` + fmt.Sprintf("%.1f/100", report.Summary.RiskScore) + `</p>
        <p><strong>Security Posture:</strong> ` + report.Summary.SecurityPosture + `</p>
    </div>
`

	// Add vulnerabilities
	if len(report.Vulnerabilities) > 0 {
		html += `    <div class="section">
        <h2>Vulnerabilities</h2>
`
		for _, vuln := range report.Vulnerabilities {
			severityClass := strings.ToLower(vuln.Severity)
			html += `        <div class="vulnerability ` + severityClass + `">
            <h3>` + vuln.Title + `</h3>
`
			if vuln.CVE != "" {
				html += `            <p><strong>CVE:</strong> ` + vuln.CVE + `</p>
`
			}
			html += `            <p><strong>Severity:</strong> ` + vuln.Severity + `</p>
            <p><strong>Affected:</strong> ` + fmt.Sprintf("%t", vuln.Affected) + `</p>
            <p>` + vuln.Description + `</p>
        </div>
`
		}
		html += `    </div>
`
	}

	html += `</body>
</html>`

	return html, nil
}

// SaveReport saves the report to a file
func (r *Reporter) SaveReport(report *ScanReport, filename string) error {
	formattedReport, err := r.FormatReport(report)
	if err != nil {
		return fmt.Errorf("failed to format report: %v", err)
	}

	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create file: %v", err)
	}
	defer file.Close()

	_, err = file.WriteString(formattedReport)
	if err != nil {
		return fmt.Errorf("failed to write report: %v", err)
	}

	return nil
}

// PrintReport prints the report to stdout
func (r *Reporter) PrintReport(report *ScanReport) error {
	formattedReport, err := r.FormatReport(report)
	if err != nil {
		return fmt.Errorf("failed to format report: %v", err)
	}

	fmt.Print(formattedReport)
	return nil
}