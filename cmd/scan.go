package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/ibrahmsql/ghostscan/pkg/enumeration"
	"github.com/ibrahmsql/ghostscan/pkg/output"
	"github.com/ibrahmsql/ghostscan/pkg/scanner"
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Perform comprehensive security scan",
	Long: `Perform a comprehensive security scan of the target Ghost CMS installation.
This includes version detection, theme enumeration, user discovery, and vulnerability assessment.`,
	Run: func(cmd *cobra.Command, args []string) {
		if targetURL == "" {
			color.Red("Error: Target URL is required. Use --url flag.")
			os.Exit(1)
		}
		runScanCommand()
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)
}

func runScanCommand() {
	// Print banner
	if !noColor {
		output.PrintBanner()
	}
	
	fmt.Printf("[+] Target: %s\n", targetURL)
	fmt.Printf("[+] Threads: %d\n", threads)
	fmt.Printf("[+] Timeout: %ds\n", timeout)
	if enumerate != "" {
		fmt.Printf("[+] Enumeration: %s\n", enumerate)
	}
	if bruteForce {
		fmt.Printf("[+] Brute force: enabled\n")
	}
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
	
	// Perform main scan
	if verbose {
		fmt.Println("[*] Starting Ghost CMS scan...")
	}
	scanResult, err := scanner.Scan(ctx)
	if err != nil {
		color.Red("Scan failed: %v", err)
		os.Exit(1)
	}
	
	var enumResult *enumeration.EnumerationResult
	
	// Perform enumeration if requested
	if enumerate != "" && scanResult.IsGhost {
		if verbose {
			fmt.Println("[*] Starting enumeration...")
		}
		enumerator := enumeration.NewEnumerator(targetURL, threads, verbose, timeout, userAgent)
		enumResult, err = enumerator.EnumerateAll(ctx)
		if err != nil && verbose {
			fmt.Printf("[!] Enumeration warning: %v\n", err)
		}
	}
	
	// Display results
	if scanResult.IsGhost {
		color.Green("[+] Ghost CMS detected!")
		if scanResult.Version != "" {
			fmt.Printf("[+] Version: %s\n", scanResult.Version)
		}
	} else {
		color.Yellow("[-] Ghost CMS not detected")
	}
	
	if enumResult != nil {
		if len(enumResult.Themes) > 0 {
			fmt.Printf("[+] Themes found: %d\n", len(enumResult.Themes))
		}
		if len(enumResult.Users) > 0 {
			fmt.Printf("[+] Users found: %d\n", len(enumResult.Users))
		}
	}
}