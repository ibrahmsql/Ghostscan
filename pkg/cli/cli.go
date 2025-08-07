package cli

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// CLI represents the command line interface
type CLI struct {
	rootCmd *cobra.Command
	verbose bool
}

// GlobalOptions holds global command line options
type GlobalOptions struct {
	Target       string
	TargetFile   string
	Output       string
	Format       string
	Verbose      bool
	Timeout      int
	Threads      int
	UserAgent    string
	Proxy        string
	Delay        time.Duration
	RandomDelay  bool
	DeepScan     bool
	ConfigFile   string
	Silent       bool
	NoColor      bool
}

// ScanOptions holds scan-specific options
type ScanOptions struct {
	DetectOnly     bool
	Enumerate      bool
	Bruteforce     bool
	VulnScan       bool
	ThemeScan      bool
	PluginScan     bool
	UserEnum       bool
	EndpointEnum   bool
	SkipSSL        bool
	FollowRedirect bool
	MaxRedirects   int
}

// BruteforceOptions holds bruteforce-specific options
type BruteforceOptions struct {
	Usernames     []string
	Passwords     []string
	UsernameFile  string
	PasswordFile  string
	StopOnSuccess bool
	MaxAttempts   int
}

// NewCLI creates a new CLI instance
func NewCLI() *CLI {
	cli := &CLI{}
	cli.setupRootCommand()
	cli.setupCommands()
	return cli
}

// Execute runs the CLI
func (c *CLI) Execute() error {
	return c.rootCmd.Execute()
}

// setupRootCommand sets up the root command
func (c *CLI) setupRootCommand() {
	c.rootCmd = &cobra.Command{
		Use:   "ghostscan",
		Short: "Ghost CMS Security Scanner",
		Long: `GhostScan is a comprehensive security scanner for Ghost CMS.

It can detect Ghost installations, enumerate users and themes,
perform brute force attacks, and scan for vulnerabilities.`,
		Version: "1.0.0",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			c.initConfig()
		},
	}

	// Global flags
	c.rootCmd.PersistentFlags().StringP("config", "c", "", "config file (default is ./config.yaml)")
	c.rootCmd.PersistentFlags().BoolP("verbose", "v", false, "verbose output")
	c.rootCmd.PersistentFlags().Bool("silent", false, "silent mode")
	c.rootCmd.PersistentFlags().Bool("no-color", false, "disable colored output")
	c.rootCmd.PersistentFlags().StringP("output", "o", "", "output file")
	c.rootCmd.PersistentFlags().StringP("format", "f", "json", "output format (json, xml, csv, html, txt, md)")
	c.rootCmd.PersistentFlags().IntP("timeout", "t", 10, "request timeout in seconds")
	c.rootCmd.PersistentFlags().IntP("threads", "T", 5, "number of threads")
	c.rootCmd.PersistentFlags().StringP("user-agent", "u", "GhostScan/1.0", "user agent string")
	c.rootCmd.PersistentFlags().StringP("proxy", "p", "", "proxy URL (http://host:port)")
	c.rootCmd.PersistentFlags().Duration("delay", time.Second, "delay between requests")
	c.rootCmd.PersistentFlags().Bool("random-delay", false, "randomize delay")

	// Bind flags to viper
	viper.BindPFlag("verbose", c.rootCmd.PersistentFlags().Lookup("verbose"))
	viper.BindPFlag("silent", c.rootCmd.PersistentFlags().Lookup("silent"))
	viper.BindPFlag("output", c.rootCmd.PersistentFlags().Lookup("output"))
	viper.BindPFlag("format", c.rootCmd.PersistentFlags().Lookup("format"))
	viper.BindPFlag("timeout", c.rootCmd.PersistentFlags().Lookup("timeout"))
	viper.BindPFlag("threads", c.rootCmd.PersistentFlags().Lookup("threads"))
	viper.BindPFlag("user-agent", c.rootCmd.PersistentFlags().Lookup("user-agent"))
	viper.BindPFlag("proxy", c.rootCmd.PersistentFlags().Lookup("proxy"))
	viper.BindPFlag("delay", c.rootCmd.PersistentFlags().Lookup("delay"))
	viper.BindPFlag("random-delay", c.rootCmd.PersistentFlags().Lookup("random-delay"))
}

// setupCommands sets up all CLI commands
func (c *CLI) setupCommands() {
	// Commands will be added here
	// TODO: Implement individual command setup methods
}

// initConfig initializes configuration
func (c *CLI) initConfig() {
	configFile := viper.GetString("config")
	if configFile != "" {
		viper.SetConfigFile(configFile)
	} else {
		viper.SetConfigName("config")
		viper.SetConfigType("yaml")
		viper.AddConfigPath(".")
		viper.AddConfigPath("./configs")
		viper.AddConfigPath("$HOME/.ghostscan")
	}

	viper.AutomaticEnv()
	viper.SetEnvPrefix("GHOSTSCAN")
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))

	if err := viper.ReadInConfig(); err == nil {
		if viper.GetBool("verbose") {
			fmt.Printf("Using config file: %s\n", viper.ConfigFileUsed())
		}
	}

	// Config manager initialization will be added later
}