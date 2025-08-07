package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/ibrahmsql/ghostscan/pkg/output"
	"github.com/ibrahmsql/ghostscan/pkg/scanner"
)

var vulnCmd = &cobra.Command{
	Use:   "vuln",
	Short: "Vulnerability scanning only",
	Long: `Perform vulnerability scanning against the target Ghost CMS installation.
This command focuses specifically on identifying known security vulnerabilities and misconfigurations.`,
	Run: func(cmd *cobra.Command, args []string) {
		if targetURL == "" {
			color.Red("Error: Target URL is required. Use --url flag.")
			os.Exit(1)
		}
		runVulnScan()
	},
}

func init() {
	rootCmd.AddCommand(vulnCmd)
}

func runVulnScan() {
	// Print banner
	if !noColor {
		output.PrintBanner()
	}
	
	fmt.Printf("[+] Target: %s\n", targetURL)
	fmt.Printf("[+] Threads: %d\n", threads)
	fmt.Printf("[+] Timeout: %ds\n", timeout)
	fmt.Printf("[+] Vulnerability scan: enabled\n")
	fmt.Println()
	
	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout*10)*time.Second)
	defer cancel()
	
	// Initialize scanner
	scanner, err := scanner.NewScanner(targetURL, verbose, threads, timeout, userAgent)
	if err != nil {
		color.Red("Error initializing scanner: %v", err)
		os.Exit(1)
	}
	
	// Perform scan with vulnerability focus
	if verbose {
		fmt.Println("[*] Starting vulnerability scan...")
	}
	scanResult, err := scanner.Scan(ctx)
	if err != nil {
		color.Red("Vulnerability scan failed: %v", err)
		os.Exit(1)
	}
	
	// Display results
	if scanResult.IsGhost {
		color.Green("[+] Ghost CMS detected!")
		if scanResult.Version != "" {
			fmt.Printf("[+] Version: %s\n", scanResult.Version)
		}
		
		// Display vulnerabilities
		if len(scanResult.Vulns) > 0 {
			color.Red("\n[!] Vulnerabilities found (%d):\n", len(scanResult.Vulns))
			for _, vuln := range scanResult.Vulns {
				fmt.Printf("  - %s", vuln.Title)
				if vuln.CVE != "" {
					fmt.Printf(" (%s)", vuln.CVE)
				}
				fmt.Printf(" - Severity: %s\n", vuln.Severity)
				if vuln.Description != "" {
					fmt.Printf("    %s\n", vuln.Description)
				}
			}
		} else {
			color.Green("\n[+] No known vulnerabilities found")
		}
		

		
	} else {
		color.Yellow("[-] Ghost CMS not detected. Vulnerability scan may not be accurate.")
	}
	
	fmt.Println("\n[+] Vulnerability scan completed!")
}