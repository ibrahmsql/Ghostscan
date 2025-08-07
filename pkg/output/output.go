package output

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ibrahmsql/ghostscan/pkg/scanner"
)

// OutputFormat represents different output formats
type OutputFormat string

const (
	FormatText OutputFormat = "text"
	FormatJSON OutputFormat = "json"
	FormatXML  OutputFormat = "xml"
)

// Reporter handles output formatting and reporting
type Reporter struct {
	format   OutputFormat
	noColor  bool
	verbose  bool
	outFile  string
}

// NewReporter creates a new output reporter
func NewReporter(format OutputFormat, noColor, verbose bool, outputFile string) *Reporter {
	return &Reporter{
		format:  format,
		noColor: noColor,
		verbose: verbose,
		outFile: outputFile,
	}
}

// ReportScanResults outputs the complete scan results
func (r *Reporter) ReportScanResults(scanResult *scanner.ScanResult) error {
	switch r.format {
	case FormatJSON:
		return r.outputJSON(scanResult)
	case FormatText:
		return r.outputText(scanResult)
	default:
		return r.outputText(scanResult)
	}
}

// outputText outputs results in human-readable text format
func (r *Reporter) outputText(scanResult *scanner.ScanResult) error {
	var output strings.Builder
	
	// Header
	output.WriteString("\n=== GhostScan Results ===\n\n")
	
	// Basic Info
	output.WriteString(fmt.Sprintf("Target: %s\n", scanResult.Target))
	output.WriteString(fmt.Sprintf("Timestamp: %s\n", scanResult.Timestamp.Format(time.RFC3339)))
	output.WriteString(fmt.Sprintf("Scan Duration: %s\n", scanResult.ScanDuration))
	
	// Ghost Detection
	if scanResult.IsGhost {
		output.WriteString("[+] Ghost CMS Detected!\n")
		output.WriteString(fmt.Sprintf("    Confidence: %d%%\n", scanResult.Confidence))
		if scanResult.Version != "" {
			output.WriteString(fmt.Sprintf("    Version: %s\n", scanResult.Version))
		}
		if scanResult.Theme != "" {
			output.WriteString(fmt.Sprintf("    Active Theme: %s\n", scanResult.Theme))
		}
	} else {
		output.WriteString("[-] Ghost CMS not detected\n")
		return r.writeOutput(output.String())
	}
	
	// Users
	if len(scanResult.Users) > 0 {
		output.WriteString("\n[+] Users Found:\n")
		for _, user := range scanResult.Users {
			output.WriteString(fmt.Sprintf("    - %s", user.Username))
			if user.Name != "" && user.Name != user.Username {
				output.WriteString(fmt.Sprintf(" (%s)", user.Name))
			}
			output.WriteString("\n")
		}
	}
	
	// Plugins
	if len(scanResult.Plugins) > 0 {
		output.WriteString("\n[+] Plugins Found:\n")
		for _, plugin := range scanResult.Plugins {
			output.WriteString(fmt.Sprintf("    - %s", plugin.Name))
			if plugin.Version != "" {
				output.WriteString(fmt.Sprintf(" (v%s)", plugin.Version))
			}
			output.WriteString("\n")
		}
	}
	
	// Vulnerabilities
	if len(scanResult.Vulns) > 0 {
		output.WriteString("\n[!] Vulnerabilities Found:\n")
		for _, vuln := range scanResult.Vulns {
			output.WriteString(fmt.Sprintf("    [%s] %s (%s)\n",
				vuln.Severity,
				vuln.Title,
				vuln.CVE))
			if r.verbose {
				output.WriteString(fmt.Sprintf("        Description: %s\n", vuln.Description))
				output.WriteString(fmt.Sprintf("        Affected: %s\n", vuln.Affected))
				output.WriteString(fmt.Sprintf("        Fixed in: %s\n", vuln.Fixed))
			}
		}
	} else {
		output.WriteString("\n[+] No known vulnerabilities found\n")
	}
	
	// Misconfigurations
	if len(scanResult.Misconfigs) > 0 {
		output.WriteString("\n[!] Security Misconfigurations:\n")
		for _, misconfig := range scanResult.Misconfigs {
			output.WriteString(fmt.Sprintf("    [%s] %s: %s\n",
				misconfig.Severity,
				misconfig.Type,
				misconfig.Description))
			if r.verbose && misconfig.URL != "" {
				output.WriteString(fmt.Sprintf("        URL: %s\n", misconfig.URL))
		}
	}
	} else {
		output.WriteString("\n[+] No security misconfigurations found\n")
	}
	
	// Interesting Files
	if len(scanResult.Interesting) > 0 {
		output.WriteString("\n[*] Interesting Files:\n")
		for _, file := range scanResult.Interesting {
			output.WriteString(fmt.Sprintf("    %s\n", file))
		}
	}
	
	// Summary
	output.WriteString("\n=== Scan Summary ===\n")
	output.WriteString(fmt.Sprintf("Vulnerabilities: %d\n", len(scanResult.Vulns)))
	output.WriteString(fmt.Sprintf("Misconfigurations: %d\n", len(scanResult.Misconfigs)))
	output.WriteString(fmt.Sprintf("Users: %d\n", len(scanResult.Users)))
	output.WriteString(fmt.Sprintf("Plugins: %d\n", len(scanResult.Plugins)))
	output.WriteString(fmt.Sprintf("Interesting Files: %d\n", len(scanResult.Interesting)))
	
	return r.writeOutput(output.String())
}

// outputJSON outputs results in JSON format
func (r *Reporter) outputJSON(scanResult *scanner.ScanResult) error {
	result := map[string]interface{}{
		"timestamp":    time.Now().UTC().Format(time.RFC3339),
		"scan_result":  scanResult,
	}
	
	jsonData, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %v", err)
	}
	
	return r.writeOutput(string(jsonData))
}

// writeOutput writes the output to file or stdout
func (r *Reporter) writeOutput(content string) error {
	if r.outFile != "" {
		file, err := os.Create(r.outFile)
		if err != nil {
			return fmt.Errorf("failed to create output file: %v", err)
		}
		defer file.Close()
		
		_, err = file.WriteString(content)
		if err != nil {
			return fmt.Errorf("failed to write to output file: %v", err)
		}
		
		fmt.Printf("Results saved to: %s\n", r.outFile)
	} else {
		fmt.Print(content)
	}
	
	return nil
}

// PrintBanner prints the GhostScan banner
func PrintBanner() {
	banner := `
██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗███████╗ ██████╗ █████╗ ███╗   ██╗
██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝██╔════╝██╔════╝██╔══██╗████╗  ██║
██║  ███╗███████║██║   ██║███████╗   ██║   ███████╗██║     ███████║██╔██╗ ██║
██║   ██║██╔══██║██║   ██║╚════██║   ██║   ╚════██║██║     ██╔══██║██║╚██╗██║
╚██████╔╝██║  ██║╚██████╔╝███████║   ██║   ███████║╚██████╗██║  ██║██║ ╚████║
 ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝

GhostScan v1.0 - Ghost CMS Security Scanner
https://github.com/ibrahmsql/ghostscan
_______________________________________________________________
`
	fmt.Print(banner)
}

// PrintSummary prints a summary of the scan results
func PrintSummary(result *scanner.ScanResult) {
	fmt.Printf("\n=== Scan Summary ===\n")
	fmt.Printf("Target: %s\n", result.Target)
	fmt.Printf("Ghost CMS Detected: %v\n", result.IsGhost)
	if result.IsGhost {
		fmt.Printf("Confidence: %d%%\n", result.Confidence)
		if result.Version != "" {
			fmt.Printf("Version: %s\n", result.Version)
		}
		if result.Theme != "" {
			fmt.Printf("Theme: %s\n", result.Theme)
		}
	}
	fmt.Printf("Vulnerabilities: %d\n", len(result.Vulns))
	fmt.Printf("Misconfigurations: %d\n", len(result.Misconfigs))
	fmt.Printf("Users Found: %d\n", len(result.Users))
	fmt.Printf("Plugins Found: %d\n", len(result.Plugins))
	fmt.Printf("Interesting Files: %d\n", len(result.Interesting))
	fmt.Printf("Scan Duration: %v\n", result.ScanDuration)
}