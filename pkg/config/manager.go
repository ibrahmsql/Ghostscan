package config

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// Config represents the main configuration structure
type Config struct {
	General        GeneralConfig        `yaml:"general"`
	Scanning       ScanningConfig       `yaml:"scanning"`
	Vulnerabilities VulnerabilitiesConfig `yaml:"vulnerabilities"`
	Enumeration    EnumerationConfig    `yaml:"enumeration"`
	Bruteforce     BruteforceConfig     `yaml:"bruteforce"`
	Stealth        StealthConfig        `yaml:"stealth"`
	Output         OutputConfig         `yaml:"output"`
	Database       DatabaseConfig       `yaml:"database"`
	Logging        LoggingConfig        `yaml:"logging"`
	API            APIConfig            `yaml:"api"`
	Security       SecurityConfig       `yaml:"security"`
	Wordlists      WordlistsConfig      `yaml:"wordlists"`
	Updates        UpdatesConfig        `yaml:"updates"`
	Notifications  NotificationsConfig  `yaml:"notifications"`
	Performance    PerformanceConfig    `yaml:"performance"`
	Plugins        PluginsConfig        `yaml:"plugins"`
}

// GeneralConfig contains general application settings
type GeneralConfig struct {
	Timeout       int    `yaml:"timeout"`
	MaxConcurrent int    `yaml:"max_concurrent"`
	UserAgent     string `yaml:"user_agent"`
	Verbose       bool   `yaml:"verbose"`
	Debug         bool   `yaml:"debug"`
	OutputDir     string `yaml:"output_dir"`
	OutputFormat  string `yaml:"output_format"`
}

// ScanningConfig contains scanning-related settings
type ScanningConfig struct {
	DetectGhost         bool `yaml:"detect_ghost"`
	DetectVersion       bool `yaml:"detect_version"`
	DetectTheme         bool `yaml:"detect_theme"`
	ScanVulnerabilities bool `yaml:"scan_vulnerabilities"`
	EnumerateEndpoints  bool `yaml:"enumerate_endpoints"`
	EnumerateUsers      bool `yaml:"enumerate_users"`
	EnumerateThemes     bool `yaml:"enumerate_themes"`
	EnumeratePlugins    bool `yaml:"enumerate_plugins"`
	AnalyzeSecurity     bool `yaml:"analyze_security"`
	Fingerprint         bool `yaml:"fingerprint"`
	MaxDepth            int  `yaml:"max_depth"`
	FollowRedirects     bool `yaml:"follow_redirects"`
	MaxRedirects        int  `yaml:"max_redirects"`
}

// VulnerabilitiesConfig contains vulnerability scanning settings
type VulnerabilitiesConfig struct {
	EnableCVEScan   bool     `yaml:"enable_cve_scan"`
	CVEDatabase     string   `yaml:"cve_database"`
	TestExploits    bool     `yaml:"test_exploits"`
	ExploitTimeout  int      `yaml:"exploit_timeout"`
	TargetCVEs      []string `yaml:"target_cves"`
	SeverityLevels  []string `yaml:"severity_levels"`
}

// EnumerationConfig contains enumeration settings
type EnumerationConfig struct {
	Users     UserEnumConfig     `yaml:"users"`
	Themes    ThemeEnumConfig    `yaml:"themes"`
	Endpoints EndpointEnumConfig `yaml:"endpoints"`
}

// UserEnumConfig contains user enumeration settings
type UserEnumConfig struct {
	Enabled           bool     `yaml:"enabled"`
	MaxUsers          int      `yaml:"max_users"`
	Methods           []string `yaml:"methods"`
	CommonUsernames   []string `yaml:"common_usernames"`
}

// ThemeEnumConfig contains theme enumeration settings
type ThemeEnumConfig struct {
	Enabled      bool     `yaml:"enabled"`
	MaxThemes    int      `yaml:"max_themes"`
	Methods      []string `yaml:"methods"`
	CommonThemes []string `yaml:"common_themes"`
}

// EndpointEnumConfig contains endpoint enumeration settings
type EndpointEnumConfig struct {
	Enabled         bool     `yaml:"enabled"`
	MaxEndpoints    int      `yaml:"max_endpoints"`
	Wordlist        string   `yaml:"wordlist"`
	CommonEndpoints []string `yaml:"common_endpoints"`
}

// BruteforceConfig contains brute force settings
type BruteforceConfig struct {
	Enabled             bool                `yaml:"enabled"`
	Targets             []string            `yaml:"targets"`
	UsernameWordlist    string              `yaml:"username_wordlist"`
	PasswordWordlist    string              `yaml:"password_wordlist"`
	MaxAttempts         int                 `yaml:"max_attempts"`
	Delay               int                 `yaml:"delay"`
	DetectLockout       bool                `yaml:"detect_lockout"`
	StopOnSuccess       bool                `yaml:"stop_on_success"`
	CommonCredentials   []CredentialConfig  `yaml:"common_credentials"`
}

// CredentialConfig represents a username/password pair
type CredentialConfig struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

// StealthConfig contains stealth mode settings
type StealthConfig struct {
	Enabled           bool              `yaml:"enabled"`
	RandomDelay       DelayConfig       `yaml:"random_delay"`
	RotateUserAgents  bool              `yaml:"rotate_user_agents"`
	UserAgents        []string          `yaml:"user_agents"`
	UseProxy          bool              `yaml:"use_proxy"`
	Proxy             ProxyConfig       `yaml:"proxy"`
	RateLimit         RateLimitConfig   `yaml:"rate_limit"`
}

// DelayConfig contains delay settings
type DelayConfig struct {
	Min int `yaml:"min"`
	Max int `yaml:"max"`
}

// ProxyConfig contains proxy settings
type ProxyConfig struct {
	HTTP   string `yaml:"http"`
	HTTPS  string `yaml:"https"`
	SOCKS5 string `yaml:"socks5"`
}

// RateLimitConfig contains rate limiting settings
type RateLimitConfig struct {
	RPS   int `yaml:"rps"`
	Burst int `yaml:"burst"`
}

// OutputConfig contains output settings
type OutputConfig struct {
	SaveToFile           bool                    `yaml:"save_to_file"`
	TimestampFilenames   bool                    `yaml:"timestamp_filenames"`
	Compress             bool                    `yaml:"compress"`
	PrettyJSON           bool                    `yaml:"pretty_json"`
	IncludeRawResponses  bool                    `yaml:"include_raw_responses"`
	MaxFileSize          int                     `yaml:"max_file_size"`
	Templates            TemplateConfig          `yaml:"templates"`
}

// TemplateConfig contains template settings
type TemplateConfig struct {
	HTML     HTMLTemplateConfig     `yaml:"html"`
	Markdown MarkdownTemplateConfig `yaml:"markdown"`
}

// HTMLTemplateConfig contains HTML template settings
type HTMLTemplateConfig struct {
	Title      string `yaml:"title"`
	IncludeTOC bool   `yaml:"include_toc"`
	Theme      string `yaml:"theme"`
}

// MarkdownTemplateConfig contains Markdown template settings
type MarkdownTemplateConfig struct {
	IncludeTOC      bool `yaml:"include_toc"`
	IncludeMetadata bool `yaml:"include_metadata"`
}

// DatabaseConfig contains database settings
type DatabaseConfig struct {
	Enabled           bool          `yaml:"enabled"`
	Path              string        `yaml:"path"`
	CleanupAfterDays  int           `yaml:"cleanup_after_days"`
	Compress          bool          `yaml:"compress"`
	Backup            BackupConfig  `yaml:"backup"`
}

// BackupConfig contains backup settings
type BackupConfig struct {
	Enabled     bool   `yaml:"enabled"`
	Interval    string `yaml:"interval"`
	KeepBackups int    `yaml:"keep_backups"`
	BackupDir   string `yaml:"backup_dir"`
}

// LoggingConfig contains logging settings
type LoggingConfig struct {
	Level      string `yaml:"level"`
	File       string `yaml:"file"`
	MaxSize    int    `yaml:"max_size"`
	MaxFiles   int    `yaml:"max_files"`
	Format     string `yaml:"format"`
	Console    bool   `yaml:"console"`
	FileOutput bool   `yaml:"file_output"`
}

// APIConfig contains API settings
type APIConfig struct {
	Ghost GhostAPIConfig `yaml:"ghost"`
}

// GhostAPIConfig contains Ghost API settings
type GhostAPIConfig struct {
	Version    string `yaml:"version"`
	ContentKey string `yaml:"content_key"`
	AdminKey   string `yaml:"admin_key"`
	Timeout    int    `yaml:"timeout"`
	MaxRetries int    `yaml:"max_retries"`
}

// SecurityConfig contains security settings
type SecurityConfig struct {
	TLS  TLSConfig  `yaml:"tls"`
	HTTP HTTPConfig `yaml:"http"`
}

// TLSConfig contains TLS settings
type TLSConfig struct {
	VerifyCertificates   bool   `yaml:"verify_certificates"`
	MinVersion           string `yaml:"min_version"`
	AnalyzeCertificates  bool   `yaml:"analyze_certificates"`
}

// HTTPConfig contains HTTP settings
type HTTPConfig struct {
	FollowRedirects bool              `yaml:"follow_redirects"`
	MaxRedirects    int               `yaml:"max_redirects"`
	EnableCookies   bool              `yaml:"enable_cookies"`
	Headers         map[string]string `yaml:"headers"`
}

// WordlistsConfig contains wordlist settings
type WordlistsConfig struct {
	BaseDir string                 `yaml:"base_dir"`
	Files   map[string]string      `yaml:"files"`
}

// UpdatesConfig contains update settings
type UpdatesConfig struct {
	AutoUpdate        bool   `yaml:"auto_update"`
	CheckInterval     int    `yaml:"check_interval"`
	ServerURL         string `yaml:"server_url"`
	IncludePrerelease bool   `yaml:"include_prerelease"`
}

// NotificationsConfig contains notification settings
type NotificationsConfig struct {
	Enabled  bool                      `yaml:"enabled"`
	Methods  NotificationMethodsConfig `yaml:"methods"`
	Triggers []string                  `yaml:"triggers"`
}

// NotificationMethodsConfig contains notification method settings
type NotificationMethodsConfig struct {
	Email   EmailConfig   `yaml:"email"`
	Slack   SlackConfig   `yaml:"slack"`
	Discord DiscordConfig `yaml:"discord"`
}

// EmailConfig contains email notification settings
type EmailConfig struct {
	Enabled    bool     `yaml:"enabled"`
	SMTPServer string   `yaml:"smtp_server"`
	SMTPPort   int      `yaml:"smtp_port"`
	Username   string   `yaml:"username"`
	Password   string   `yaml:"password"`
	From       string   `yaml:"from"`
	To         []string `yaml:"to"`
}

// SlackConfig contains Slack notification settings
type SlackConfig struct {
	Enabled    bool   `yaml:"enabled"`
	WebhookURL string `yaml:"webhook_url"`
	Channel    string `yaml:"channel"`
}

// DiscordConfig contains Discord notification settings
type DiscordConfig struct {
	Enabled    bool   `yaml:"enabled"`
	WebhookURL string `yaml:"webhook_url"`
}

// PerformanceConfig contains performance settings
type PerformanceConfig struct {
	Memory MemoryConfig `yaml:"memory"`
	CPU    CPUConfig    `yaml:"cpu"`
	Cache  CacheConfig  `yaml:"cache"`
}

// MemoryConfig contains memory settings
type MemoryConfig struct {
	MaxUsage  int  `yaml:"max_usage"`
	Profiling bool `yaml:"profiling"`
}

// CPUConfig contains CPU settings
type CPUConfig struct {
	MaxCores  int  `yaml:"max_cores"`
	Profiling bool `yaml:"profiling"`
}

// CacheConfig contains cache settings
type CacheConfig struct {
	Enabled bool `yaml:"enabled"`
	Size    int  `yaml:"size"`
	TTL     int  `yaml:"ttl"`
}

// PluginsConfig contains plugin settings
type PluginsConfig struct {
	Enabled        bool                   `yaml:"enabled"`
	Directory      string                 `yaml:"directory"`
	AutoLoad       bool                   `yaml:"auto_load"`
	EnabledPlugins []string               `yaml:"enabled_plugins"`
	Settings       map[string]interface{} `yaml:"settings"`
}

// Manager handles configuration loading and management
type Manager struct {
	config     *Config
	configPath string
	lastMod    time.Time
}

// NewManager creates a new configuration manager
func NewManager(configPath string) *Manager {
	return &Manager{
		configPath: configPath,
	}
}

// LoadConfig loads configuration from file
func (m *Manager) LoadConfig() error {
	// Check if config file exists
	if _, err := os.Stat(m.configPath); os.IsNotExist(err) {
		return fmt.Errorf("config file not found: %s", m.configPath)
	}

	// Read config file
	data, err := ioutil.ReadFile(m.configPath)
	if err != nil {
		return fmt.Errorf("failed to read config file: %v", err)
	}

	// Parse YAML
	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("failed to parse config file: %v", err)
	}

	// Validate configuration
	if err := m.validateConfig(&config); err != nil {
		return fmt.Errorf("invalid configuration: %v", err)
	}

	// Set defaults
	m.setDefaults(&config)

	// Update manager state
	m.config = &config
	if stat, err := os.Stat(m.configPath); err == nil {
		m.lastMod = stat.ModTime()
	}

	return nil
}

// GetConfig returns the current configuration
func (m *Manager) GetConfig() *Config {
	return m.config
}

// ReloadConfig reloads configuration if file has changed
func (m *Manager) ReloadConfig() error {
	stat, err := os.Stat(m.configPath)
	if err != nil {
		return err
	}

	if stat.ModTime().After(m.lastMod) {
		return m.LoadConfig()
	}

	return nil
}

// SaveConfig saves current configuration to file
func (m *Manager) SaveConfig() error {
	if m.config == nil {
		return fmt.Errorf("no configuration to save")
	}

	// Create directory if it doesn't exist
	dir := filepath.Dir(m.configPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %v", err)
	}

	// Marshal to YAML
	data, err := yaml.Marshal(m.config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %v", err)
	}

	// Write to file
	if err := ioutil.WriteFile(m.configPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %v", err)
	}

	return nil
}

// UpdateConfig updates specific configuration values
func (m *Manager) UpdateConfig(updates map[string]interface{}) error {
	if m.config == nil {
		return fmt.Errorf("no configuration loaded")
	}

	// Apply updates (simplified implementation)
	// In a real implementation, you'd want to use reflection or a more sophisticated approach
	for key, value := range updates {
		switch key {
		case "general.verbose":
			if v, ok := value.(bool); ok {
				m.config.General.Verbose = v
			}
		case "general.debug":
			if v, ok := value.(bool); ok {
				m.config.General.Debug = v
			}
		case "general.timeout":
			if v, ok := value.(int); ok {
				m.config.General.Timeout = v
			}
		// Add more cases as needed
		}
	}

	return nil
}

// validateConfig validates the configuration
func (m *Manager) validateConfig(config *Config) error {
	// Validate general settings
	if config.General.Timeout <= 0 {
		return fmt.Errorf("general.timeout must be positive")
	}
	if config.General.MaxConcurrent <= 0 {
		return fmt.Errorf("general.max_concurrent must be positive")
	}
	if config.General.UserAgent == "" {
		return fmt.Errorf("general.user_agent cannot be empty")
	}

	// Validate scanning settings
	if config.Scanning.MaxDepth < 0 {
		return fmt.Errorf("scanning.max_depth cannot be negative")
	}
	if config.Scanning.MaxRedirects < 0 {
		return fmt.Errorf("scanning.max_redirects cannot be negative")
	}

	// Validate vulnerability settings
	if config.Vulnerabilities.ExploitTimeout <= 0 {
		return fmt.Errorf("vulnerabilities.exploit_timeout must be positive")
	}

	// Validate enumeration settings
	if config.Enumeration.Users.MaxUsers < 0 {
		return fmt.Errorf("enumeration.users.max_users cannot be negative")
	}
	if config.Enumeration.Themes.MaxThemes < 0 {
		return fmt.Errorf("enumeration.themes.max_themes cannot be negative")
	}
	if config.Enumeration.Endpoints.MaxEndpoints < 0 {
		return fmt.Errorf("enumeration.endpoints.max_endpoints cannot be negative")
	}

	// Validate brute force settings
	if config.Bruteforce.MaxAttempts < 0 {
		return fmt.Errorf("bruteforce.max_attempts cannot be negative")
	}
	if config.Bruteforce.Delay < 0 {
		return fmt.Errorf("bruteforce.delay cannot be negative")
	}

	// Validate stealth settings
	if config.Stealth.RandomDelay.Min < 0 {
		return fmt.Errorf("stealth.random_delay.min cannot be negative")
	}
	if config.Stealth.RandomDelay.Max < config.Stealth.RandomDelay.Min {
		return fmt.Errorf("stealth.random_delay.max must be >= min")
	}
	if config.Stealth.RateLimit.RPS <= 0 {
		return fmt.Errorf("stealth.rate_limit.rps must be positive")
	}
	if config.Stealth.RateLimit.Burst <= 0 {
		return fmt.Errorf("stealth.rate_limit.burst must be positive")
	}

	// Validate output settings
	if config.Output.MaxFileSize <= 0 {
		return fmt.Errorf("output.max_file_size must be positive")
	}

	// Validate database settings
	if config.Database.CleanupAfterDays < 0 {
		return fmt.Errorf("database.cleanup_after_days cannot be negative")
	}
	if config.Database.Backup.KeepBackups < 0 {
		return fmt.Errorf("database.backup.keep_backups cannot be negative")
	}

	// Validate logging settings
	validLogLevels := []string{"debug", "info", "warn", "error"}
	validLevel := false
	for _, level := range validLogLevels {
		if config.Logging.Level == level {
			validLevel = true
			break
		}
	}
	if !validLevel {
		return fmt.Errorf("logging.level must be one of: %v", validLogLevels)
	}

	if config.Logging.MaxSize <= 0 {
		return fmt.Errorf("logging.max_size must be positive")
	}
	if config.Logging.MaxFiles <= 0 {
		return fmt.Errorf("logging.max_files must be positive")
	}

	validLogFormats := []string{"json", "text"}
	validFormat := false
	for _, format := range validLogFormats {
		if config.Logging.Format == format {
			validFormat = true
			break
		}
	}
	if !validFormat {
		return fmt.Errorf("logging.format must be one of: %v", validLogFormats)
	}

	// Validate API settings
	if config.API.Ghost.Timeout <= 0 {
		return fmt.Errorf("api.ghost.timeout must be positive")
	}
	if config.API.Ghost.MaxRetries < 0 {
		return fmt.Errorf("api.ghost.max_retries cannot be negative")
	}

	// Validate performance settings
	if config.Performance.Memory.MaxUsage <= 0 {
		return fmt.Errorf("performance.memory.max_usage must be positive")
	}
	if config.Performance.CPU.MaxCores < 0 {
		return fmt.Errorf("performance.cpu.max_cores cannot be negative")
	}
	if config.Performance.Cache.Size <= 0 {
		return fmt.Errorf("performance.cache.size must be positive")
	}
	if config.Performance.Cache.TTL <= 0 {
		return fmt.Errorf("performance.cache.ttl must be positive")
	}

	return nil
}

// setDefaults sets default values for missing configuration
func (m *Manager) setDefaults(config *Config) {
	// Set general defaults
	if config.General.Timeout == 0 {
		config.General.Timeout = 30
	}
	if config.General.MaxConcurrent == 0 {
		config.General.MaxConcurrent = 10
	}
	if config.General.UserAgent == "" {
		config.General.UserAgent = "Mozilla/5.0 (compatible; GhostScan/1.0)"
	}
	if config.General.OutputDir == "" {
		config.General.OutputDir = "./reports"
	}
	if config.General.OutputFormat == "" {
		config.General.OutputFormat = "json"
	}

	// Set scanning defaults
	if config.Scanning.MaxDepth == 0 {
		config.Scanning.MaxDepth = 3
	}
	if config.Scanning.MaxRedirects == 0 {
		config.Scanning.MaxRedirects = 5
	}

	// Set vulnerability defaults
	if config.Vulnerabilities.ExploitTimeout == 0 {
		config.Vulnerabilities.ExploitTimeout = 10
	}
	if config.Vulnerabilities.CVEDatabase == "" {
		config.Vulnerabilities.CVEDatabase = "./data/cve_database.json"
	}

	// Set enumeration defaults
	if config.Enumeration.Users.MaxUsers == 0 {
		config.Enumeration.Users.MaxUsers = 100
	}
	if config.Enumeration.Themes.MaxThemes == 0 {
		config.Enumeration.Themes.MaxThemes = 50
	}
	if config.Enumeration.Endpoints.MaxEndpoints == 0 {
		config.Enumeration.Endpoints.MaxEndpoints = 200
	}

	// Set brute force defaults
	if config.Bruteforce.MaxAttempts == 0 {
		config.Bruteforce.MaxAttempts = 100
	}
	if config.Bruteforce.Delay == 0 {
		config.Bruteforce.Delay = 1000
	}

	// Set stealth defaults
	if config.Stealth.RandomDelay.Min == 0 {
		config.Stealth.RandomDelay.Min = 500
	}
	if config.Stealth.RandomDelay.Max == 0 {
		config.Stealth.RandomDelay.Max = 2000
	}
	if config.Stealth.RateLimit.RPS == 0 {
		config.Stealth.RateLimit.RPS = 5
	}
	if config.Stealth.RateLimit.Burst == 0 {
		config.Stealth.RateLimit.Burst = 10
	}

	// Set output defaults
	if config.Output.MaxFileSize == 0 {
		config.Output.MaxFileSize = 100
	}

	// Set database defaults
	if config.Database.Path == "" {
		config.Database.Path = "./data/ghostscan.db"
	}
	if config.Database.CleanupAfterDays == 0 {
		config.Database.CleanupAfterDays = 30
	}
	if config.Database.Backup.KeepBackups == 0 {
		config.Database.Backup.KeepBackups = 7
	}
	if config.Database.Backup.BackupDir == "" {
		config.Database.Backup.BackupDir = "./data/backups"
	}

	// Set logging defaults
	if config.Logging.Level == "" {
		config.Logging.Level = "info"
	}
	if config.Logging.File == "" {
		config.Logging.File = "./logs/ghostscan.log"
	}
	if config.Logging.MaxSize == 0 {
		config.Logging.MaxSize = 10
	}
	if config.Logging.MaxFiles == 0 {
		config.Logging.MaxFiles = 5
	}
	if config.Logging.Format == "" {
		config.Logging.Format = "text"
	}

	// Set API defaults
	if config.API.Ghost.Version == "" {
		config.API.Ghost.Version = "v4"
	}
	if config.API.Ghost.Timeout == 0 {
		config.API.Ghost.Timeout = 15
	}
	if config.API.Ghost.MaxRetries == 0 {
		config.API.Ghost.MaxRetries = 3
	}

	// Set security defaults
	if config.Security.TLS.MinVersion == "" {
		config.Security.TLS.MinVersion = "1.2"
	}
	if config.Security.HTTP.MaxRedirects == 0 {
		config.Security.HTTP.MaxRedirects = 5
	}

	// Set wordlist defaults
	if config.Wordlists.BaseDir == "" {
		config.Wordlists.BaseDir = "./wordlists"
	}

	// Set update defaults
	if config.Updates.CheckInterval == 0 {
		config.Updates.CheckInterval = 24
	}
	if config.Updates.ServerURL == "" {
		config.Updates.ServerURL = "https://api.github.com/repos/ghostscan/ghostscan"
	}

	// Set performance defaults
	if config.Performance.Memory.MaxUsage == 0 {
		config.Performance.Memory.MaxUsage = 512
	}
	if config.Performance.Cache.Size == 0 {
		config.Performance.Cache.Size = 50
	}
	if config.Performance.Cache.TTL == 0 {
		config.Performance.Cache.TTL = 60
	}

	// Set plugin defaults
	if config.Plugins.Directory == "" {
		config.Plugins.Directory = "./plugins"
	}
}

// GetWordlistPath returns the full path to a wordlist file
func (m *Manager) GetWordlistPath(name string) string {
	if m.config == nil {
		return ""
	}

	if filename, exists := m.config.Wordlists.Files[name]; exists {
		return filepath.Join(m.config.Wordlists.BaseDir, filename)
	}

	return ""
}

// IsFeatureEnabled checks if a specific feature is enabled
func (m *Manager) IsFeatureEnabled(feature string) bool {
	if m.config == nil {
		return false
	}

	switch feature {
	case "ghost_detection":
		return m.config.Scanning.DetectGhost
	case "version_detection":
		return m.config.Scanning.DetectVersion
	case "theme_detection":
		return m.config.Scanning.DetectTheme
	case "vulnerability_scanning":
		return m.config.Scanning.ScanVulnerabilities
	case "endpoint_enumeration":
		return m.config.Scanning.EnumerateEndpoints
	case "user_enumeration":
		return m.config.Scanning.EnumerateUsers
	case "theme_enumeration":
		return m.config.Scanning.EnumerateThemes
	case "plugin_enumeration":
		return m.config.Scanning.EnumeratePlugins
	case "security_analysis":
		return m.config.Scanning.AnalyzeSecurity
	case "fingerprinting":
		return m.config.Scanning.Fingerprint
	case "brute_force":
		return m.config.Bruteforce.Enabled
	case "stealth_mode":
		return m.config.Stealth.Enabled
	case "database":
		return m.config.Database.Enabled
	case "plugins":
		return m.config.Plugins.Enabled
	case "notifications":
		return m.config.Notifications.Enabled
	default:
		return false
	}
}

// GetConfigPath returns the configuration file path
func (m *Manager) GetConfigPath() string {
	return m.configPath
}

// GetLastModified returns the last modification time of the config file
func (m *Manager) GetLastModified() time.Time {
	return m.lastMod
}