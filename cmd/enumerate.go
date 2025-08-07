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

var enumerateCmd = &cobra.Command{
	Use:   "enumerate",
	Short: "Enumerate Ghost CMS components",
	Long: `Enumerate various Ghost CMS components including themes, users, posts, tags, and integrations.
This command focuses specifically on information gathering and component discovery.`,
	Run: func(cmd *cobra.Command, args []string) {
		if targetURL == "" {
			color.Red("Error: Target URL is required. Use --url flag.")
			os.Exit(1)
		}
		runEnumeration()
	},
}

func init() {
	rootCmd.AddCommand(enumerateCmd)
}

func runEnumeration() {
	// Print banner
	if !noColor {
		output.PrintBanner()
	}
	
	fmt.Printf("[+] Target: %s\n", targetURL)
	fmt.Printf("[+] Threads: %d\n", threads)
	fmt.Printf("[+] Timeout: %ds\n", timeout)
	if enumerate != "" {
		fmt.Printf("[+] Enumeration: %s\n", enumerate)
	} else {
		fmt.Printf("[+] Enumeration: all\n")
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
		color.Yellow("[-] Ghost CMS not detected. Enumeration may not be accurate.")
		if !verbose {
			os.Exit(1)
		}
	}
	
	// Initialize enumerator
	if verbose {
		fmt.Println("[*] Starting enumeration...")
	}
	
	enumerator := enumeration.NewEnumerator(targetURL, threads, verbose, timeout, userAgent)
	enumResult, err := enumerator.EnumerateAll(ctx)
	if err != nil {
		color.Red("Enumeration failed: %v", err)
		os.Exit(1)
	}
	
	// Display results
	color.Green("[+] Enumeration completed!")
	
	if len(enumResult.Themes) > 0 {
		fmt.Printf("\n[+] Themes found (%d):\n", len(enumResult.Themes))
		for _, theme := range enumResult.Themes {
			fmt.Printf("  - %s", theme.Name)
			if theme.Version != "" {
				fmt.Printf(" (v%s)", theme.Version)
			}
			fmt.Println()
		}
	}
	
	if len(enumResult.Users) > 0 {
		fmt.Printf("\n[+] Users found (%d):\n", len(enumResult.Users))
		for _, user := range enumResult.Users {
			fmt.Printf("  - %s", user.Name)
			if user.Slug != "" {
				fmt.Printf(" (%s)", user.Slug)
			}
			fmt.Println()
		}
	}
	
	if len(enumResult.Posts) > 0 {
		fmt.Printf("\n[+] Posts found (%d):\n", len(enumResult.Posts))
		for i, post := range enumResult.Posts {
			if i >= 10 { // Limit display to first 10
				fmt.Printf("  ... and %d more\n", len(enumResult.Posts)-10)
				break
			}
			fmt.Printf("  - %s\n", post.Title)
		}
	}
	
	if len(enumResult.Tags) > 0 {
		fmt.Printf("\n[+] Tags found (%d):\n", len(enumResult.Tags))
		for i, tag := range enumResult.Tags {
			if i >= 10 { // Limit display to first 10
				fmt.Printf("  ... and %d more\n", len(enumResult.Tags)-10)
				break
			}
			fmt.Printf("  - %s\n", tag.Name)
		}
	}
	
	if len(enumResult.Integrations) > 0 {
		fmt.Printf("\n[+] Integrations found (%d):\n", len(enumResult.Integrations))
		for _, integration := range enumResult.Integrations {
			fmt.Printf("  - %s\n", integration.Name)
		}
	}
	
	fmt.Println("\n[+] Enumeration completed successfully!")
}