package output

import (
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// FormatManager handles different output formats
type FormatManager struct {
	formats map[string]OutputFormatter
}

// OutputFormatter interface for different output formats
type OutputFormatter interface {
	Format(data interface{}) ([]byte, error)
	GetExtension() string
	GetMimeType() string
}

// JSONFormatter formats output as JSON
type JSONFormatter struct {
	Pretty bool
}

// XMLFormatter formats output as XML
type XMLFormatter struct {
	Pretty bool
}

// CSVFormatter formats output as CSV
type CSVFormatter struct {
	Delimiter rune
}

// HTMLFormatter formats output as HTML
type HTMLFormatter struct {
	Template string
	Title    string
}

// TextFormatter formats output as plain text
type TextFormatter struct {
	Verbose bool
}

// MarkdownFormatter formats output as Markdown
type MarkdownFormatter struct {
	IncludeTOC bool
}

// ScanResultForOutput represents scan results for output formatting
type ScanResultForOutput struct {
	Target        string                 `json:"target" xml:"target"`
	Timestamp     time.Time              `json:"timestamp" xml:"timestamp"`
	ScanDuration  time.Duration          `json:"scan_duration" xml:"scan_duration"`
	IsGhost       bool                   `json:"is_ghost" xml:"is_ghost"`
	Confidence    float64                `json:"confidence" xml:"confidence"`
	Version       string                 `json:"version" xml:"version"`
	Theme         string                 `json:"theme" xml:"theme"`
	Vulnerabilities []VulnerabilityOutput `json:"vulnerabilities" xml:"vulnerabilities"`
	Endpoints     []EndpointOutput       `json:"endpoints" xml:"endpoints"`
	Users         []UserOutput           `json:"users" xml:"users"`
	Themes        []ThemeOutput          `json:"themes" xml:"themes"`
	Plugins       []PluginOutput         `json:"plugins" xml:"plugins"`
	Security      SecurityOutput         `json:"security" xml:"security"`
	Metadata      MetadataOutput         `json:"metadata" xml:"metadata"`
	Errors        []string               `json:"errors" xml:"errors"`
	Warnings      []string               `json:"warnings" xml:"warnings"`
}

// VulnerabilityOutput represents vulnerability information for output
type VulnerabilityOutput struct {
	CVE         string    `json:"cve" xml:"cve"`
	Title       string    `json:"title" xml:"title"`
	Description string    `json:"description" xml:"description"`
	Severity    string    `json:"severity" xml:"severity"`
	CVSS        float64   `json:"cvss" xml:"cvss"`
	Affected    string    `json:"affected" xml:"affected"`
	Fixed       string    `json:"fixed" xml:"fixed"`
	Exploitable bool      `json:"exploitable" xml:"exploitable"`
	Exploited   bool      `json:"exploited" xml:"exploited"`
	FoundAt     time.Time `json:"found_at" xml:"found_at"`
}

// EndpointOutput represents endpoint information for output
type EndpointOutput struct {
	URL        string `json:"url" xml:"url"`
	Method     string `json:"method" xml:"method"`
	StatusCode int    `json:"status_code" xml:"status_code"`
	Size       int    `json:"size" xml:"size"`
	Type       string `json:"type" xml:"type"`
	Protected  bool   `json:"protected" xml:"protected"`
	Accessible bool   `json:"accessible" xml:"accessible"`
}

// UserOutput represents user information for output
type UserOutput struct {
	ID       string `json:"id" xml:"id"`
	Name     string `json:"name" xml:"name"`
	Slug     string `json:"slug" xml:"slug"`
	Email    string `json:"email" xml:"email"`
	Role     string `json:"role" xml:"role"`
	Status   string `json:"status" xml:"status"`
	Location string `json:"location" xml:"location"`
	Website  string `json:"website" xml:"website"`
	Bio      string `json:"bio" xml:"bio"`
}

// ThemeOutput represents theme information for output
type ThemeOutput struct {
	Name        string   `json:"name" xml:"name"`
	Version     string   `json:"version" xml:"version"`
	Author      string   `json:"author" xml:"author"`
	Description string   `json:"description" xml:"description"`
	Active      bool     `json:"active" xml:"active"`
	Custom      bool     `json:"custom" xml:"custom"`
	Files       []string `json:"files" xml:"files"`
	Vulnerable  bool     `json:"vulnerable" xml:"vulnerable"`
	RiskScore   float64  `json:"risk_score" xml:"risk_score"`
}

// PluginOutput represents plugin information for output
type PluginOutput struct {
	Name        string  `json:"name" xml:"name"`
	Version     string  `json:"version" xml:"version"`
	Description string  `json:"description" xml:"description"`
	Active      bool    `json:"active" xml:"active"`
	Vulnerable  bool    `json:"vulnerable" xml:"vulnerable"`
	RiskScore   float64 `json:"risk_score" xml:"risk_score"`
}

// SecurityOutput represents security information for output
type SecurityOutput struct {
	HTTPS           bool              `json:"https" xml:"https"`
	HSTS            bool              `json:"hsts" xml:"hsts"`
	CSP             bool              `json:"csp" xml:"csp"`
	XFrameOptions   bool              `json:"x_frame_options" xml:"x_frame_options"`
	XSSProtection   bool              `json:"xss_protection" xml:"xss_protection"`
	SecurityHeaders map[string]string `json:"security_headers" xml:"security_headers"`
	TLSVersion      string            `json:"tls_version" xml:"tls_version"`
	WeakCiphers     []string          `json:"weak_ciphers" xml:"weak_ciphers"`
	SecurityScore   float64           `json:"security_score" xml:"security_score"`
}

// MetadataOutput represents metadata information for output
type MetadataOutput struct {
	Title       string            `json:"title" xml:"title"`
	Description string            `json:"description" xml:"description"`
	Keywords    []string          `json:"keywords" xml:"keywords"`
	Author      string            `json:"author" xml:"author"`
	Generator   string            `json:"generator" xml:"generator"`
	Language    string            `json:"language" xml:"language"`
	OpenGraph   map[string]string `json:"open_graph" xml:"open_graph"`
	TwitterCard map[string]string `json:"twitter_card" xml:"twitter_card"`
}

// NewFormatManager creates a new format manager
func NewFormatManager() *FormatManager {
	fm := &FormatManager{
		formats: make(map[string]OutputFormatter),
	}

	// Register default formatters
	fm.RegisterFormatter("json", &JSONFormatter{Pretty: true})
	fm.RegisterFormatter("xml", &XMLFormatter{Pretty: true})
	fm.RegisterFormatter("csv", &CSVFormatter{Delimiter: ','})
	fm.RegisterFormatter("html", &HTMLFormatter{Title: "GhostScan Report"})
	fm.RegisterFormatter("txt", &TextFormatter{Verbose: true})
	fm.RegisterFormatter("md", &MarkdownFormatter{IncludeTOC: true})

	return fm
}

// RegisterFormatter registers a new output formatter
func (fm *FormatManager) RegisterFormatter(name string, formatter OutputFormatter) {
	fm.formats[strings.ToLower(name)] = formatter
}

// GetFormatter returns a formatter by name
func (fm *FormatManager) GetFormatter(name string) (OutputFormatter, bool) {
	formatter, exists := fm.formats[strings.ToLower(name)]
	return formatter, exists
}

// GetAvailableFormats returns list of available formats
func (fm *FormatManager) GetAvailableFormats() []string {
	formats := make([]string, 0, len(fm.formats))
	for name := range fm.formats {
		formats = append(formats, name)
	}
	return formats
}

// FormatAndSave formats data and saves to file
func (fm *FormatManager) FormatAndSave(data interface{}, format, filename string) error {
	formatter, exists := fm.GetFormatter(format)
	if !exists {
		return fmt.Errorf("unsupported format: %s", format)
	}

	// Format data
	formatted, err := formatter.Format(data)
	if err != nil {
		return fmt.Errorf("failed to format data: %w", err)
	}

	// Ensure directory exists
	dir := filepath.Dir(filename)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Write to file
	if err := os.WriteFile(filename, formatted, 0644); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}

// JSON Formatter Implementation

// Format formats data as JSON
func (jf *JSONFormatter) Format(data interface{}) ([]byte, error) {
	if jf.Pretty {
		return json.MarshalIndent(data, "", "  ")
	}
	return json.Marshal(data)
}

// GetExtension returns file extension for JSON
func (jf *JSONFormatter) GetExtension() string {
	return ".json"
}

// GetMimeType returns MIME type for JSON
func (jf *JSONFormatter) GetMimeType() string {
	return "application/json"
}

// XML Formatter Implementation

// Format formats data as XML
func (xf *XMLFormatter) Format(data interface{}) ([]byte, error) {
	var result []byte
	var err error

	if xf.Pretty {
		result, err = xml.MarshalIndent(data, "", "  ")
	} else {
		result, err = xml.Marshal(data)
	}

	if err != nil {
		return nil, err
	}

	// Add XML header
	header := []byte(xml.Header)
	return append(header, result...), nil
}

// GetExtension returns file extension for XML
func (xf *XMLFormatter) GetExtension() string {
	return ".xml"
}

// GetMimeType returns MIME type for XML
func (xf *XMLFormatter) GetMimeType() string {
	return "application/xml"
}

// CSV Formatter Implementation

// Format formats data as CSV
func (cf *CSVFormatter) Format(data interface{}) ([]byte, error) {
	// Convert data to ScanResultForOutput if needed
	scanResult, ok := data.(*ScanResultForOutput)
	if !ok {
		return nil, fmt.Errorf("unsupported data type for CSV format")
	}

	// Create CSV content
	var csvData [][]string

	// Add headers
	headers := []string{"Type", "Name", "Value", "Severity", "Description"}
	csvData = append(csvData, headers)

	// Add basic info
	csvData = append(csvData, []string{"Info", "Target", scanResult.Target, "Info", "Scan target"})
	csvData = append(csvData, []string{"Info", "Ghost Detected", fmt.Sprintf("%t", scanResult.IsGhost), "Info", "Ghost CMS detection result"})
	csvData = append(csvData, []string{"Info", "Confidence", fmt.Sprintf("%.2f%%", scanResult.Confidence), "Info", "Detection confidence"})
	csvData = append(csvData, []string{"Info", "Version", scanResult.Version, "Info", "Ghost CMS version"})
	csvData = append(csvData, []string{"Info", "Theme", scanResult.Theme, "Info", "Active theme"})

	// Add vulnerabilities
	for _, vuln := range scanResult.Vulnerabilities {
		csvData = append(csvData, []string{
			"Vulnerability",
			vuln.CVE,
			vuln.Title,
			vuln.Severity,
			vuln.Description,
		})
	}

	// Add endpoints
	for _, endpoint := range scanResult.Endpoints {
		csvData = append(csvData, []string{
			"Endpoint",
			endpoint.URL,
			fmt.Sprintf("%d", endpoint.StatusCode),
			endpoint.Type,
			fmt.Sprintf("Protected: %t", endpoint.Protected),
		})
	}

	// Add users
	for _, user := range scanResult.Users {
		csvData = append(csvData, []string{
			"User",
			user.Name,
			user.Email,
			user.Role,
			user.Status,
		})
	}

	// Convert to CSV bytes
	var buf strings.Builder
	writer := csv.NewWriter(&buf)
	writer.Comma = cf.Delimiter

	for _, record := range csvData {
		if err := writer.Write(record); err != nil {
			return nil, err
		}
	}

	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, err
	}

	return []byte(buf.String()), nil
}

// GetExtension returns file extension for CSV
func (cf *CSVFormatter) GetExtension() string {
	return ".csv"
}

// GetMimeType returns MIME type for CSV
func (cf *CSVFormatter) GetMimeType() string {
	return "text/csv"
}

// HTML Formatter Implementation

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{.Title}}</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            padding: 30px;
        }
        .header {
            border-bottom: 2px solid #e1e5e9;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }
        .title {
            color: #2c3e50;
            margin: 0;
            font-size: 2.5em;
        }
        .subtitle {
            color: #7f8c8d;
            margin: 5px 0 0 0;
            font-size: 1.1em;
        }
        .section {
            margin-bottom: 30px;
        }
        .section-title {
            color: #34495e;
            border-left: 4px solid #3498db;
            padding-left: 15px;
            margin-bottom: 15px;
            font-size: 1.4em;
        }
        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }
        .info-item {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 6px;
            border-left: 3px solid #3498db;
        }
        .info-label {
            font-weight: bold;
            color: #2c3e50;
            display: block;
            margin-bottom: 5px;
        }
        .info-value {
            color: #34495e;
        }
        .table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
            background: white;
            border-radius: 6px;
            overflow: hidden;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        .table th {
            background: #34495e;
            color: white;
            padding: 12px;
            text-align: left;
            font-weight: 600;
        }
        .table td {
            padding: 12px;
            border-bottom: 1px solid #e1e5e9;
        }
        .table tr:hover {
            background: #f8f9fa;
        }
        .severity-critical { color: #e74c3c; font-weight: bold; }
        .severity-high { color: #e67e22; font-weight: bold; }
        .severity-medium { color: #f39c12; font-weight: bold; }
        .severity-low { color: #27ae60; }
        .status-vulnerable { color: #e74c3c; font-weight: bold; }
        .status-secure { color: #27ae60; font-weight: bold; }
        .badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.85em;
            font-weight: bold;
        }
        .badge-success { background: #d4edda; color: #155724; }
        .badge-danger { background: #f8d7da; color: #721c24; }
        .badge-warning { background: #fff3cd; color: #856404; }
        .badge-info { background: #d1ecf1; color: #0c5460; }
        .footer {
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #e1e5e9;
            text-align: center;
            color: #7f8c8d;
            font-size: 0.9em;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1 class="title">{{.Title}}</h1>
            <p class="subtitle">Generated on {{.Data.Timestamp.Format "2006-01-02 15:04:05"}}</p>
        </div>

        <div class="section">
            <h2 class="section-title">Scan Summary</h2>
            <div class="info-grid">
                <div class="info-item">
                    <span class="info-label">Target</span>
                    <span class="info-value">{{.Data.Target}}</span>
                </div>
                <div class="info-item">
                    <span class="info-label">Ghost CMS Detected</span>
                    <span class="info-value">
                        {{if .Data.IsGhost}}
                            <span class="badge badge-success">Yes</span>
                        {{else}}
                            <span class="badge badge-danger">No</span>
                        {{end}}
                    </span>
                </div>
                <div class="info-item">
                    <span class="info-label">Confidence</span>
                    <span class="info-value">{{printf "%.2f%%" .Data.Confidence}}</span>
                </div>
                <div class="info-item">
                    <span class="info-label">Version</span>
                    <span class="info-value">{{if .Data.Version}}{{.Data.Version}}{{else}}Unknown{{end}}</span>
                </div>
                <div class="info-item">
                    <span class="info-label">Theme</span>
                    <span class="info-value">{{if .Data.Theme}}{{.Data.Theme}}{{else}}Unknown{{end}}</span>
                </div>
                <div class="info-item">
                    <span class="info-label">Scan Duration</span>
                    <span class="info-value">{{.Data.ScanDuration}}</span>
                </div>
            </div>
        </div>

        {{if .Data.Vulnerabilities}}
        <div class="section">
            <h2 class="section-title">Vulnerabilities</h2>
            <table class="table">
                <thead>
                    <tr>
                        <th>CVE</th>
                        <th>Title</th>
                        <th>Severity</th>
                        <th>CVSS</th>
                        <th>Exploitable</th>
                        <th>Description</th>
                    </tr>
                </thead>
                <tbody>
                    {{range .Data.Vulnerabilities}}
                    <tr>
                        <td>{{.CVE}}</td>
                        <td>{{.Title}}</td>
                        <td><span class="severity-{{.Severity | lower}}">{{.Severity}}</span></td>
                        <td>{{.CVSS}}</td>
                        <td>
                            {{if .Exploitable}}
                                <span class="badge badge-danger">Yes</span>
                            {{else}}
                                <span class="badge badge-success">No</span>
                            {{end}}
                        </td>
                        <td>{{.Description}}</td>
                    </tr>
                    {{end}}
                </tbody>
            </table>
        </div>
        {{end}}

        {{if .Data.Endpoints}}
        <div class="section">
            <h2 class="section-title">Discovered Endpoints</h2>
            <table class="table">
                <thead>
                    <tr>
                        <th>URL</th>
                        <th>Method</th>
                        <th>Status</th>
                        <th>Type</th>
                        <th>Protected</th>
                        <th>Size</th>
                    </tr>
                </thead>
                <tbody>
                    {{range .Data.Endpoints}}
                    <tr>
                        <td>{{.URL}}</td>
                        <td>{{.Method}}</td>
                        <td>{{.StatusCode}}</td>
                        <td><span class="badge badge-info">{{.Type}}</span></td>
                        <td>
                            {{if .Protected}}
                                <span class="badge badge-warning">Yes</span>
                            {{else}}
                                <span class="badge badge-success">No</span>
                            {{end}}
                        </td>
                        <td>{{.Size}} bytes</td>
                    </tr>
                    {{end}}
                </tbody>
            </table>
        </div>
        {{end}}

        {{if .Data.Users}}
        <div class="section">
            <h2 class="section-title">Discovered Users</h2>
            <table class="table">
                <thead>
                    <tr>
                        <th>Name</th>
                        <th>Slug</th>
                        <th>Email</th>
                        <th>Role</th>
                        <th>Status</th>
                        <th>Website</th>
                    </tr>
                </thead>
                <tbody>
                    {{range .Data.Users}}
                    <tr>
                        <td>{{.Name}}</td>
                        <td>{{.Slug}}</td>
                        <td>{{.Email}}</td>
                        <td><span class="badge badge-info">{{.Role}}</span></td>
                        <td>{{.Status}}</td>
                        <td>{{.Website}}</td>
                    </tr>
                    {{end}}
                </tbody>
            </table>
        </div>
        {{end}}

        <div class="footer">
            <p>Report generated by GhostScan - Ghost CMS Security Scanner</p>
        </div>
    </div>
</body>
</html>`

// Format formats data as HTML
func (hf *HTMLFormatter) Format(data interface{}) ([]byte, error) {
	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"lower": strings.ToLower,
	}).Parse(htmlTemplate)
	if err != nil {
		return nil, err
	}

	templateData := struct {
		Title string
		Data  interface{}
	}{
		Title: hf.Title,
		Data:  data,
	}

	var buf strings.Builder
	if err := tmpl.Execute(&buf, templateData); err != nil {
		return nil, err
	}

	return []byte(buf.String()), nil
}

// GetExtension returns file extension for HTML
func (hf *HTMLFormatter) GetExtension() string {
	return ".html"
}

// GetMimeType returns MIME type for HTML
func (hf *HTMLFormatter) GetMimeType() string {
	return "text/html"
}

// Text Formatter Implementation

// Format formats data as plain text
func (tf *TextFormatter) Format(data interface{}) ([]byte, error) {
	scanResult, ok := data.(*ScanResultForOutput)
	if !ok {
		return nil, fmt.Errorf("unsupported data type for text format")
	}

	var buf strings.Builder

	// Header
	buf.WriteString("=== GhostScan Report ===\n")
	buf.WriteString(fmt.Sprintf("Generated: %s\n", scanResult.Timestamp.Format("2006-01-02 15:04:05")))
	buf.WriteString(fmt.Sprintf("Target: %s\n", scanResult.Target))
	buf.WriteString(fmt.Sprintf("Scan Duration: %s\n", scanResult.ScanDuration))
	buf.WriteString("\n")

	// Basic Info
	buf.WriteString("=== Basic Information ===\n")
	buf.WriteString(fmt.Sprintf("Ghost CMS Detected: %t\n", scanResult.IsGhost))
	buf.WriteString(fmt.Sprintf("Confidence: %.2f%%\n", scanResult.Confidence))
	buf.WriteString(fmt.Sprintf("Version: %s\n", scanResult.Version))
	buf.WriteString(fmt.Sprintf("Theme: %s\n", scanResult.Theme))
	buf.WriteString("\n")

	// Vulnerabilities
	if len(scanResult.Vulnerabilities) > 0 {
		buf.WriteString("=== Vulnerabilities ===\n")
		for _, vuln := range scanResult.Vulnerabilities {
			buf.WriteString(fmt.Sprintf("CVE: %s\n", vuln.CVE))
			buf.WriteString(fmt.Sprintf("Title: %s\n", vuln.Title))
			buf.WriteString(fmt.Sprintf("Severity: %s\n", vuln.Severity))
			buf.WriteString(fmt.Sprintf("CVSS: %.1f\n", vuln.CVSS))
			buf.WriteString(fmt.Sprintf("Exploitable: %t\n", vuln.Exploitable))
			if tf.Verbose {
				buf.WriteString(fmt.Sprintf("Description: %s\n", vuln.Description))
			}
			buf.WriteString("\n")
		}
	}

	// Endpoints
	if len(scanResult.Endpoints) > 0 {
		buf.WriteString("=== Discovered Endpoints ===\n")
		for _, endpoint := range scanResult.Endpoints {
			buf.WriteString(fmt.Sprintf("%s [%s] - %d (%s)\n",
				endpoint.URL, endpoint.Method, endpoint.StatusCode, endpoint.Type))
			if endpoint.Protected {
				buf.WriteString("  [PROTECTED]\n")
			}
		}
		buf.WriteString("\n")
	}

	// Users
	if len(scanResult.Users) > 0 {
		buf.WriteString("=== Discovered Users ===\n")
		for _, user := range scanResult.Users {
			buf.WriteString(fmt.Sprintf("%s (%s) - %s\n", user.Name, user.Slug, user.Role))
			if tf.Verbose && user.Email != "" {
				buf.WriteString(fmt.Sprintf("  Email: %s\n", user.Email))
			}
		}
		buf.WriteString("\n")
	}

	// Errors and Warnings
	if len(scanResult.Errors) > 0 {
		buf.WriteString("=== Errors ===\n")
		for _, err := range scanResult.Errors {
			buf.WriteString(fmt.Sprintf("- %s\n", err))
		}
		buf.WriteString("\n")
	}

	if len(scanResult.Warnings) > 0 {
		buf.WriteString("=== Warnings ===\n")
		for _, warning := range scanResult.Warnings {
			buf.WriteString(fmt.Sprintf("- %s\n", warning))
		}
		buf.WriteString("\n")
	}

	return []byte(buf.String()), nil
}

// GetExtension returns file extension for text
func (tf *TextFormatter) GetExtension() string {
	return ".txt"
}

// GetMimeType returns MIME type for text
func (tf *TextFormatter) GetMimeType() string {
	return "text/plain"
}

// Markdown Formatter Implementation

// Format formats data as Markdown
func (mf *MarkdownFormatter) Format(data interface{}) ([]byte, error) {
	scanResult, ok := data.(*ScanResultForOutput)
	if !ok {
		return nil, fmt.Errorf("unsupported data type for markdown format")
	}

	var buf strings.Builder

	// Title
	buf.WriteString("# GhostScan Report\n\n")
	buf.WriteString(fmt.Sprintf("**Generated:** %s  \n", scanResult.Timestamp.Format("2006-01-02 15:04:05")))
	buf.WriteString(fmt.Sprintf("**Target:** %s  \n", scanResult.Target))
	buf.WriteString(fmt.Sprintf("**Scan Duration:** %s  \n\n", scanResult.ScanDuration))

	// Table of Contents
	if mf.IncludeTOC {
		buf.WriteString("## Table of Contents\n\n")
		buf.WriteString("- [Basic Information](#basic-information)\n")
		if len(scanResult.Vulnerabilities) > 0 {
			buf.WriteString("- [Vulnerabilities](#vulnerabilities)\n")
		}
		if len(scanResult.Endpoints) > 0 {
			buf.WriteString("- [Discovered Endpoints](#discovered-endpoints)\n")
		}
		if len(scanResult.Users) > 0 {
			buf.WriteString("- [Discovered Users](#discovered-users)\n")
		}
		buf.WriteString("\n")
	}

	// Basic Information
	buf.WriteString("## Basic Information\n\n")
	buf.WriteString("| Property | Value |\n")
	buf.WriteString("|----------|-------|\n")
	buf.WriteString(fmt.Sprintf("| Ghost CMS Detected | %t |\n", scanResult.IsGhost))
	buf.WriteString(fmt.Sprintf("| Confidence | %.2f%% |\n", scanResult.Confidence))
	buf.WriteString(fmt.Sprintf("| Version | %s |\n", scanResult.Version))
	buf.WriteString(fmt.Sprintf("| Theme | %s |\n\n", scanResult.Theme))

	// Vulnerabilities
	if len(scanResult.Vulnerabilities) > 0 {
		buf.WriteString("## Vulnerabilities\n\n")
		buf.WriteString("| CVE | Title | Severity | CVSS | Exploitable |\n")
		buf.WriteString("|-----|-------|----------|------|-------------|\n")
		for _, vuln := range scanResult.Vulnerabilities {
			exploitable := "No"
			if vuln.Exploitable {
				exploitable = "**Yes**"
			}
			buf.WriteString(fmt.Sprintf("| %s | %s | **%s** | %.1f | %s |\n",
				vuln.CVE, vuln.Title, vuln.Severity, vuln.CVSS, exploitable))
		}
		buf.WriteString("\n")
	}

	// Endpoints
	if len(scanResult.Endpoints) > 0 {
		buf.WriteString("## Discovered Endpoints\n\n")
		buf.WriteString("| URL | Method | Status | Type | Protected |\n")
		buf.WriteString("|-----|--------|--------|------|-----------|\n")
		for _, endpoint := range scanResult.Endpoints {
			protected := "No"
			if endpoint.Protected {
				protected = "**Yes**"
			}
			buf.WriteString(fmt.Sprintf("| `%s` | %s | %d | %s | %s |\n",
				endpoint.URL, endpoint.Method, endpoint.StatusCode, endpoint.Type, protected))
		}
		buf.WriteString("\n")
	}

	// Users
	if len(scanResult.Users) > 0 {
		buf.WriteString("## Discovered Users\n\n")
		buf.WriteString("| Name | Slug | Role | Status |\n")
		buf.WriteString("|------|------|------|--------|\n")
		for _, user := range scanResult.Users {
			buf.WriteString(fmt.Sprintf("| %s | `%s` | %s | %s |\n",
				user.Name, user.Slug, user.Role, user.Status))
		}
		buf.WriteString("\n")
	}

	// Footer
	buf.WriteString("---\n\n")
	buf.WriteString("*Report generated by GhostScan - Ghost CMS Security Scanner*\n")

	return []byte(buf.String()), nil
}

// GetExtension returns file extension for Markdown
func (mf *MarkdownFormatter) GetExtension() string {
	return ".md"
}

// GetMimeType returns MIME type for Markdown
func (mf *MarkdownFormatter) GetMimeType() string {
	return "text/markdown"
}