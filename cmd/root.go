package cmd

import (
	"fmt"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	// Global variables
	targetURL    string
	verbose      bool
	outputFile   string
	userAgent    string
	timeout      int
	threads      int
	noColor      bool
	enumerate    string
	bruteForce   bool
	userList     string
	passList     string
	outputFormat string
	
	// Ghost CMS specific flags
	detectVersion    bool
	detectThemes     bool
	detectPlugins    bool
	detectUsers      bool
	detectPosts      bool
	detectTags       bool
	detectPages      bool
	detectIntegrations bool
	detectConfig     bool
	detectAPI        bool
	detectAdmin      bool
	detectWebhooks   bool
	detectRoutes     bool
	detectDatabase   bool
	
	// Security scanning flags
	vulnScan         bool
	passiveOnly      bool
	aggressiveScan   bool
	skipSSL          bool
	followRedirects  bool
	randomUserAgent  bool
	proxy            string
	cookies          string
	headers          string
	delay            int
	randomDelay      bool
	maxRetries       int
	
	// Brute force specific
	bruteUsers       bool
	bruteAdmin       bool
	bruteAPI         bool
	bruteLogin       bool
	brutePassword    string
	bruteStopOnSuccess bool
	
	// Output and reporting
	quiet            bool
	logFile          string
	updateDB         bool
	skipPlugins      string
	skipThemes       string
	includeOnly      string
	exclude          string
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "ghostscan",
	Short: "Ghost CMS Security Scanner",
	Long: `GhostScan is a comprehensive security scanner that detects Ghost CMS installations, enumerates components, and checks for known vulnerabilities.`,

}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() error {
	printBanner()
	return rootCmd.Execute()
}

func printBanner() {
	// Color styles
	versionStyle := color.New(color.FgCyan, color.Bold)
	textStyle := color.New(color.FgHiBlack, color.Bold)
	
	logo := `
  ________  ___ ___ ________    ______________________________________     _____    _______   
 /  _____/ /   |   \\_____  \  /   _____/\__    ___/   _____/\_   ___ \   /  _  \   \      \  
/   \  ___/    ~    \/   |   \ \_____  \   |    |  \_____  \ /    \  \/  /  /_\  \  /   |   \ 
\    \_\  \    Y    /    |    \/        \  |    |  /        \\     \____/    |    \/    |    \
 \______  /\___|_  /\_______  /_______  /  |____| /_______  / \______  /\____|__  /\____|__  /
        \/       \/         \/        \/                  \/         \/         \/         \/`
	
	// Print logo and version on same line
	fmt.Print(logo)
	versionStyle.Print("  v1.0.0")
	fmt.Println()
	fmt.Println()
	textStyle.Println("Ghost CMS Security Scanner - By @ibrahmsql")
	fmt.Println()
}

func init() {
	// Disable Cobra's default help template
	rootCmd.SetHelpTemplate(rootCmd.Long + "\n")
	
	// Core flags
	rootCmd.PersistentFlags().StringVarP(&targetURL, "url", "u", "", "Target URL (required)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
	rootCmd.PersistentFlags().BoolVarP(&quiet, "quiet", "q", false, "Quiet mode")
	rootCmd.PersistentFlags().StringVarP(&outputFile, "output", "o", "", "Output file")
	rootCmd.PersistentFlags().StringVar(&logFile, "log", "", "Log file")
	rootCmd.PersistentFlags().StringVar(&outputFormat, "format", "text", "Output format (text,json,xml,csv)")
	rootCmd.PersistentFlags().BoolVar(&noColor, "no-color", false, "Disable colors")
	
	// Ghost CMS Detection & Enumeration
	rootCmd.PersistentFlags().StringVarP(&enumerate, "enumerate", "e", "", "Components to enumerate")
	rootCmd.PersistentFlags().BoolVar(&detectVersion, "detect-version", true, "Detect version")
	rootCmd.PersistentFlags().BoolVar(&detectThemes, "detect-themes", false, "Enumerate themes")
	rootCmd.PersistentFlags().BoolVar(&detectPlugins, "detect-plugins", false, "Enumerate plugins")
	rootCmd.PersistentFlags().BoolVar(&detectUsers, "detect-users", false, "Enumerate users")
	rootCmd.PersistentFlags().BoolVar(&detectPosts, "detect-posts", false, "Enumerate posts")
	rootCmd.PersistentFlags().BoolVar(&detectTags, "detect-tags", false, "Enumerate tags")
	rootCmd.PersistentFlags().BoolVar(&detectPages, "detect-pages", false, "Enumerate pages")
	rootCmd.PersistentFlags().BoolVar(&detectIntegrations, "detect-integrations", false, "Detect integrations")
	rootCmd.PersistentFlags().BoolVar(&detectConfig, "detect-config", false, "Detect config")
	rootCmd.PersistentFlags().BoolVar(&detectAPI, "detect-api", false, "Enumerate API")
	rootCmd.PersistentFlags().BoolVar(&detectAdmin, "detect-admin", false, "Detect admin panel")
	rootCmd.PersistentFlags().BoolVar(&detectWebhooks, "detect-webhooks", false, "Detect webhooks")
	rootCmd.PersistentFlags().BoolVar(&detectRoutes, "detect-routes", false, "Enumerate routes")
	rootCmd.PersistentFlags().BoolVar(&detectDatabase, "detect-database", false, "Detect database")
	
	// Security Scanning
	rootCmd.PersistentFlags().BoolVar(&vulnScan, "vuln-scan", true, "Vulnerability scanning")
	rootCmd.PersistentFlags().BoolVar(&passiveOnly, "passive", false, "Passive mode only")
	rootCmd.PersistentFlags().BoolVar(&aggressiveScan, "aggressive", false, "Aggressive scanning")
	rootCmd.PersistentFlags().BoolVar(&updateDB, "update", false, "Update vuln database")
	
	// Network & Request Configuration
	rootCmd.PersistentFlags().StringVar(&userAgent, "user-agent", "GhostScan/2.0", "User agent")
	rootCmd.PersistentFlags().BoolVar(&randomUserAgent, "random-user-agent", false, "Random user agents")
	rootCmd.PersistentFlags().IntVar(&timeout, "timeout", 30, "Timeout (seconds)")
	rootCmd.PersistentFlags().IntVar(&threads, "threads", 10, "Concurrent threads")
	rootCmd.PersistentFlags().IntVar(&delay, "delay", 0, "Request delay (ms)")
	rootCmd.PersistentFlags().BoolVar(&randomDelay, "random-delay", false, "Random delays")
	rootCmd.PersistentFlags().IntVar(&maxRetries, "max-retries", 3, "Max retries")
	rootCmd.PersistentFlags().BoolVar(&skipSSL, "skip-ssl", false, "Skip SSL verification")
	rootCmd.PersistentFlags().BoolVar(&followRedirects, "follow-redirects", true, "Follow redirects")
	rootCmd.PersistentFlags().StringVar(&proxy, "proxy", "", "HTTP proxy")
	rootCmd.PersistentFlags().StringVar(&cookies, "cookies", "", "HTTP cookies")
	rootCmd.PersistentFlags().StringVar(&headers, "headers", "", "Custom headers")
	
	// Brute Force Configuration
	rootCmd.PersistentFlags().BoolVar(&bruteForce, "brute-force", false, "Enable brute force")
	rootCmd.PersistentFlags().BoolVar(&bruteUsers, "brute-users", false, "Brute force users")
	rootCmd.PersistentFlags().BoolVar(&bruteAdmin, "brute-admin", false, "Brute force admin")
	rootCmd.PersistentFlags().BoolVar(&bruteAPI, "brute-api", false, "Brute force API")
	rootCmd.PersistentFlags().BoolVar(&bruteLogin, "brute-login", false, "Brute force login")
	rootCmd.PersistentFlags().StringVar(&userList, "userlist", "", "Username list file")
	rootCmd.PersistentFlags().StringVar(&passList, "passlist", "", "Password list file")
	rootCmd.PersistentFlags().StringVar(&brutePassword, "password", "", "Single password")
	rootCmd.PersistentFlags().BoolVar(&bruteStopOnSuccess, "stop-on-success", false, "Stop on success")
	
	// Filtering & Exclusion
	rootCmd.PersistentFlags().StringVar(&skipPlugins, "skip-plugins", "", "Skip plugins")
	rootCmd.PersistentFlags().StringVar(&skipThemes, "skip-themes", "", "Skip themes")
	rootCmd.PersistentFlags().StringVar(&includeOnly, "include-only", "", "Include only")
	rootCmd.PersistentFlags().StringVar(&exclude, "exclude", "", "Exclude types")
	
	// Mark required flags
	rootCmd.MarkPersistentFlagRequired("url")
	
	// Hide advanced flags from main help
	rootCmd.PersistentFlags().MarkHidden("log")
	rootCmd.PersistentFlags().MarkHidden("user-agent")
	rootCmd.PersistentFlags().MarkHidden("random-user-agent")
	rootCmd.PersistentFlags().MarkHidden("delay")
	rootCmd.PersistentFlags().MarkHidden("random-delay")
	rootCmd.PersistentFlags().MarkHidden("max-retries")
	rootCmd.PersistentFlags().MarkHidden("follow-redirects")
	rootCmd.PersistentFlags().MarkHidden("cookies")
	rootCmd.PersistentFlags().MarkHidden("headers")
	rootCmd.PersistentFlags().MarkHidden("update")
	rootCmd.PersistentFlags().MarkHidden("brute-users")
	rootCmd.PersistentFlags().MarkHidden("brute-api")
	rootCmd.PersistentFlags().MarkHidden("brute-login")
	rootCmd.PersistentFlags().MarkHidden("password")
	rootCmd.PersistentFlags().MarkHidden("stop-on-success")
	rootCmd.PersistentFlags().MarkHidden("skip-plugins")
	rootCmd.PersistentFlags().MarkHidden("skip-themes")
	rootCmd.PersistentFlags().MarkHidden("include-only")
	rootCmd.PersistentFlags().MarkHidden("exclude")
	rootCmd.PersistentFlags().MarkHidden("detect-version")
	rootCmd.PersistentFlags().MarkHidden("detect-themes")
	rootCmd.PersistentFlags().MarkHidden("detect-plugins")
	rootCmd.PersistentFlags().MarkHidden("detect-users")
	rootCmd.PersistentFlags().MarkHidden("detect-posts")
	rootCmd.PersistentFlags().MarkHidden("detect-tags")
	rootCmd.PersistentFlags().MarkHidden("detect-pages")
	rootCmd.PersistentFlags().MarkHidden("detect-integrations")
	rootCmd.PersistentFlags().MarkHidden("detect-config")
	rootCmd.PersistentFlags().MarkHidden("detect-api")
	rootCmd.PersistentFlags().MarkHidden("detect-admin")
	rootCmd.PersistentFlags().MarkHidden("detect-webhooks")
	rootCmd.PersistentFlags().MarkHidden("detect-routes")
	rootCmd.PersistentFlags().MarkHidden("detect-database")
}