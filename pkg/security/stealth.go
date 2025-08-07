package security

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/go-resty/resty/v2"
)

// StealthScanner provides stealth scanning capabilities
type StealthScanner struct {
	client           *resty.Client
	userAgents       []string
	proxies          []string
	randomDelay      bool
	minDelay         time.Duration
	maxDelay         time.Duration
	randomHeaders    bool
	rotateUserAgent  bool
	rotateProxy      bool
	avoidDetection   bool
	maxRetries       int
	requestSpacing   time.Duration
}

// StealthOptions holds configuration for stealth scanning
type StealthOptions struct {
	UserAgents       []string
	Proxies          []string
	RandomDelay      bool
	MinDelay         time.Duration
	MaxDelay         time.Duration
	RandomHeaders    bool
	RotateUserAgent  bool
	RotateProxy      bool
	AvoidDetection   bool
	MaxRetries       int
	RequestSpacing   time.Duration
	Timeout          time.Duration
}

// NewStealthScanner creates a new stealth scanner
func NewStealthScanner(options StealthOptions) *StealthScanner {
	client := resty.New()
	client.SetTimeout(options.Timeout)

	// Default user agents if none provided
	if len(options.UserAgents) == 0 {
		options.UserAgents = getDefaultUserAgents()
	}

	// Default delays
	if options.MinDelay == 0 {
		options.MinDelay = 1 * time.Second
	}
	if options.MaxDelay == 0 {
		options.MaxDelay = 5 * time.Second
	}

	return &StealthScanner{
		client:           client,
		userAgents:       options.UserAgents,
		proxies:          options.Proxies,
		randomDelay:      options.RandomDelay,
		minDelay:         options.MinDelay,
		maxDelay:         options.MaxDelay,
		randomHeaders:    options.RandomHeaders,
		rotateUserAgent:  options.RotateUserAgent,
		rotateProxy:      options.RotateProxy,
		avoidDetection:   options.AvoidDetection,
		maxRetries:       options.MaxRetries,
		requestSpacing:   options.RequestSpacing,
	}
}

// Request performs a stealth HTTP request
func (s *StealthScanner) Request(ctx context.Context, method, url string) (*resty.Response, error) {
	req := s.client.R().SetContext(ctx)

	// Apply stealth techniques
	if err := s.applyStealthTechniques(req); err != nil {
		return nil, fmt.Errorf("failed to apply stealth techniques: %w", err)
	}

	// Add random delay before request
	if s.randomDelay {
		delay := s.getRandomDelay()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(delay):
		}
	}

	// Perform request with retries
	var resp *resty.Response
	var err error

	for attempt := 0; attempt <= s.maxRetries; attempt++ {
		resp, err = req.Execute(method, url)
		if err == nil {
			break
		}

		// Wait before retry
		if attempt < s.maxRetries {
			retryDelay := time.Duration(attempt+1) * time.Second
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(retryDelay):
			}
		}
	}

	// Add spacing after request
	if s.requestSpacing > 0 {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(s.requestSpacing):
		}
	}

	return resp, err
}

// applyStealthTechniques applies various stealth techniques to the request
func (s *StealthScanner) applyStealthTechniques(req *resty.Request) error {
	// Rotate User-Agent
	if s.rotateUserAgent && len(s.userAgents) > 0 {
		userAgent, err := s.getRandomUserAgent()
		if err != nil {
			return err
		}
		req.SetHeader("User-Agent", userAgent)
	}

	// Add random headers to mimic real browsers
	if s.randomHeaders {
		headers := s.getRandomHeaders()
		for key, value := range headers {
			req.SetHeader(key, value)
		}
	}

	// Set proxy if available
	if s.rotateProxy && len(s.proxies) > 0 {
		proxy, err := s.getRandomProxy()
		if err != nil {
			return err
		}
		s.client.SetProxy(proxy)
	}

	// Apply detection avoidance techniques
	if s.avoidDetection {
		s.applyDetectionAvoidance(req)
	}

	return nil
}

// getRandomUserAgent returns a random user agent
func (s *StealthScanner) getRandomUserAgent() (string, error) {
	if len(s.userAgents) == 0 {
		return "", fmt.Errorf("no user agents available")
	}

	index, err := rand.Int(rand.Reader, big.NewInt(int64(len(s.userAgents))))
	if err != nil {
		return "", err
	}

	return s.userAgents[index.Int64()], nil
}

// getRandomProxy returns a random proxy
func (s *StealthScanner) getRandomProxy() (string, error) {
	if len(s.proxies) == 0 {
		return "", fmt.Errorf("no proxies available")
	}

	index, err := rand.Int(rand.Reader, big.NewInt(int64(len(s.proxies))))
	if err != nil {
		return "", err
	}

	return s.proxies[index.Int64()], nil
}

// getRandomDelay returns a random delay between min and max
func (s *StealthScanner) getRandomDelay() time.Duration {
	diff := s.maxDelay - s.minDelay
	if diff <= 0 {
		return s.minDelay
	}

	randomNs, _ := rand.Int(rand.Reader, big.NewInt(int64(diff)))
	return s.minDelay + time.Duration(randomNs.Int64())
}

// getRandomHeaders returns random HTTP headers to mimic real browsers
func (s *StealthScanner) getRandomHeaders() map[string]string {
	headers := make(map[string]string)

	// Accept headers
	acceptHeaders := []string{
		"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
		"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
	}

	// Accept-Language headers
	acceptLanguages := []string{
		"en-US,en;q=0.9",
		"en-US,en;q=0.8",
		"en-GB,en-US;q=0.9,en;q=0.8",
		"en-US,en;q=0.5",
	}

	// Accept-Encoding headers
	acceptEncodings := []string{
		"gzip, deflate, br",
		"gzip, deflate",
		"gzip",
	}

	// DNT (Do Not Track) headers
	dntValues := []string{"1", "0"}

	// Randomly select headers
	if acceptHeader := s.getRandomFromSlice(acceptHeaders); acceptHeader != "" {
		headers["Accept"] = acceptHeader
	}

	if acceptLang := s.getRandomFromSlice(acceptLanguages); acceptLang != "" {
		headers["Accept-Language"] = acceptLang
	}

	if acceptEnc := s.getRandomFromSlice(acceptEncodings); acceptEnc != "" {
		headers["Accept-Encoding"] = acceptEnc
	}

	if dnt := s.getRandomFromSlice(dntValues); dnt != "" {
		headers["DNT"] = dnt
	}

	// Connection header
	headers["Connection"] = "keep-alive"

	// Upgrade-Insecure-Requests
	headers["Upgrade-Insecure-Requests"] = "1"

	return headers
}

// getRandomFromSlice returns a random element from a string slice
func (s *StealthScanner) getRandomFromSlice(slice []string) string {
	if len(slice) == 0 {
		return ""
	}

	index, err := rand.Int(rand.Reader, big.NewInt(int64(len(slice))))
	if err != nil {
		return slice[0] // Fallback to first element
	}

	return slice[index.Int64()]
}

// applyDetectionAvoidance applies techniques to avoid detection
func (s *StealthScanner) applyDetectionAvoidance(req *resty.Request) {
	// Add cache control headers
	req.SetHeader("Cache-Control", "no-cache")
	req.SetHeader("Pragma", "no-cache")

	// Add referer header (sometimes)
	if shouldAddReferer, _ := rand.Int(rand.Reader, big.NewInt(2)); shouldAddReferer.Int64() == 1 {
		referers := []string{
			"https://www.google.com/",
			"https://www.bing.com/",
			"https://duckduckgo.com/",
			"https://www.yahoo.com/",
		}
		if referer := s.getRandomFromSlice(referers); referer != "" {
			req.SetHeader("Referer", referer)
		}
	}

	// Add X-Forwarded-For header (sometimes)
	if shouldAddXFF, _ := rand.Int(rand.Reader, big.NewInt(3)); shouldAddXFF.Int64() == 1 {
		ip := s.generateRandomIP()
		req.SetHeader("X-Forwarded-For", ip)
	}

	// Add X-Real-IP header (sometimes)
	if shouldAddRealIP, _ := rand.Int(rand.Reader, big.NewInt(4)); shouldAddRealIP.Int64() == 1 {
		ip := s.generateRandomIP()
		req.SetHeader("X-Real-IP", ip)
	}
}

// generateRandomIP generates a random IP address
func (s *StealthScanner) generateRandomIP() string {
	// Generate random private IP addresses to avoid issues
	privateRanges := []string{
		"192.168.%d.%d",
		"10.%d.%d.%d",
		"172.16.%d.%d",
	}

	rangeIndex, _ := rand.Int(rand.Reader, big.NewInt(int64(len(privateRanges))))
	rangeFormat := privateRanges[rangeIndex.Int64()]

	switch rangeFormat {
	case "192.168.%d.%d":
		a, _ := rand.Int(rand.Reader, big.NewInt(256))
		b, _ := rand.Int(rand.Reader, big.NewInt(256))
		return fmt.Sprintf(rangeFormat, a.Int64(), b.Int64())
	case "10.%d.%d.%d":
		a, _ := rand.Int(rand.Reader, big.NewInt(256))
		b, _ := rand.Int(rand.Reader, big.NewInt(256))
		c, _ := rand.Int(rand.Reader, big.NewInt(256))
		return fmt.Sprintf(rangeFormat, a.Int64(), b.Int64(), c.Int64())
	case "172.16.%d.%d":
		a, _ := rand.Int(rand.Reader, big.NewInt(256))
		b, _ := rand.Int(rand.Reader, big.NewInt(256))
		return fmt.Sprintf(rangeFormat, a.Int64(), b.Int64())
	default:
		return "192.168.1.100"
	}
}

// getDefaultUserAgents returns a list of common user agents
func getDefaultUserAgents() []string {
	return []string{
		// Chrome
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",

		// Firefox
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
		"Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",

		// Safari
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",

		// Edge
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",

		// Opera
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0",

		// Mobile browsers
		"Mozilla/5.0 (Android 14; Mobile; rv:121.0) Gecko/121.0 Firefox/121.0",
		"Mozilla/5.0 (Linux; Android 14; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
	}
}

// WAFEvasion provides Web Application Firewall evasion techniques
type WAFEvasion struct {
	techniques []EvasionTechnique
}

// EvasionTechnique represents a WAF evasion technique
type EvasionTechnique struct {
	Name        string
	Description string
	Apply       func(*resty.Request, string) string
}

// NewWAFEvasion creates a new WAF evasion instance
func NewWAFEvasion() *WAFEvasion {
	return &WAFEvasion{
		techniques: []EvasionTechnique{
			{
				Name:        "Case Variation",
				Description: "Varies the case of URL path",
				Apply:       applyCaseVariation,
			},
			{
				Name:        "URL Encoding",
				Description: "Applies URL encoding to path",
				Apply:       applyURLEncoding,
			},
			{
				Name:        "Double URL Encoding",
				Description: "Applies double URL encoding",
				Apply:       applyDoubleURLEncoding,
			},
			{
				Name:        "Unicode Encoding",
				Description: "Uses Unicode encoding",
				Apply:       applyUnicodeEncoding,
			},
			{
				Name:        "Path Traversal",
				Description: "Adds path traversal sequences",
				Apply:       applyPathTraversal,
			},
		},
	}
}

// ApplyEvasion applies a random evasion technique to the URL
func (w *WAFEvasion) ApplyEvasion(req *resty.Request, url string) string {
	if len(w.techniques) == 0 {
		return url
	}

	index, err := rand.Int(rand.Reader, big.NewInt(int64(len(w.techniques))))
	if err != nil {
		return url
	}

	technique := w.techniques[index.Int64()]
	return technique.Apply(req, url)
}

// applyCaseVariation varies the case of the URL path
func applyCaseVariation(req *resty.Request, url string) string {
	// Simple case variation - alternate upper/lower case
	result := make([]rune, len(url))
	for i, char := range url {
		if i%2 == 0 {
			result[i] = char
		} else {
			if char >= 'a' && char <= 'z' {
				result[i] = char - 32 // Convert to uppercase
			} else if char >= 'A' && char <= 'Z' {
				result[i] = char + 32 // Convert to lowercase
			} else {
				result[i] = char
			}
		}
	}
	return string(result)
}

// applyURLEncoding applies URL encoding to certain characters
func applyURLEncoding(req *resty.Request, url string) string {
	// URL encode some common characters
	replacements := map[string]string{
		" ": "%20",
		"!": "%21",
		"#": "%23",
		"$": "%24",
		"&": "%26",
		"'": "%27",
		"(": "%28",
		")": "%29",
		"*": "%2A",
		"+": "%2B",
		",": "%2C",
		"/": "%2F",
		":": "%3A",
		";": "%3B",
		"=": "%3D",
		"?": "%3F",
		"@": "%40",
		"[": "%5B",
		"]": "%5D",
	}

	result := url
	for char, encoded := range replacements {
		if strings.Contains(result, char) {
			// Only encode some occurrences randomly
			if shouldEncode, _ := rand.Int(rand.Reader, big.NewInt(3)); shouldEncode.Int64() == 1 {
				result = strings.ReplaceAll(result, char, encoded)
			}
		}
	}

	return result
}

// applyDoubleURLEncoding applies double URL encoding
func applyDoubleURLEncoding(req *resty.Request, url string) string {
	// First apply URL encoding
	encoded := applyURLEncoding(req, url)
	// Then encode the % characters
	return strings.ReplaceAll(encoded, "%", "%25")
}

// applyUnicodeEncoding applies Unicode encoding
func applyUnicodeEncoding(req *resty.Request, url string) string {
	// Convert some characters to Unicode encoding
	unicodeReplacements := map[string]string{
		"a": "\u0061",
		"e": "\u0065",
		"i": "\u0069",
		"o": "\u006F",
		"u": "\u0075",
	}

	result := url
	for char, unicode := range unicodeReplacements {
		if strings.Contains(result, char) {
			// Only encode some occurrences randomly
			if shouldEncode, _ := rand.Int(rand.Reader, big.NewInt(4)); shouldEncode.Int64() == 1 {
				result = strings.ReplaceAll(result, char, unicode)
			}
		}
	}

	return result
}

// applyPathTraversal adds path traversal sequences
func applyPathTraversal(req *resty.Request, url string) string {
	// Add some path traversal sequences
	traversalSequences := []string{
		"./",
		"../",
		".//",
		"..//",
		".//../",
	}

	// Randomly select a sequence
	index, err := rand.Int(rand.Reader, big.NewInt(int64(len(traversalSequences))))
	if err != nil {
		return url
	}

	sequence := traversalSequences[index.Int64()]
	
	// Insert the sequence at a random position in the path
	if strings.Contains(url, "/") {
		parts := strings.Split(url, "/")
		if len(parts) > 2 {
			insertPos, _ := rand.Int(rand.Reader, big.NewInt(int64(len(parts)-1)))
			parts[insertPos.Int64()+1] = sequence + parts[insertPos.Int64()+1]
			return strings.Join(parts, "/")
		}
	}

	return url
}

// RateLimitBypass provides rate limiting bypass techniques
type RateLimitBypass struct {
	techniques []BypassTechnique
}

// BypassTechnique represents a rate limit bypass technique
type BypassTechnique struct {
	Name        string
	Description string
	Apply       func(*resty.Request)
}

// NewRateLimitBypass creates a new rate limit bypass instance
func NewRateLimitBypass() *RateLimitBypass {
	return &RateLimitBypass{
		techniques: []BypassTechnique{
			{
				Name:        "X-Forwarded-For",
				Description: "Uses X-Forwarded-For header",
				Apply:       applyXForwardedFor,
			},
			{
				Name:        "X-Real-IP",
				Description: "Uses X-Real-IP header",
				Apply:       applyXRealIP,
			},
			{
				Name:        "X-Originating-IP",
				Description: "Uses X-Originating-IP header",
				Apply:       applyXOriginatingIP,
			},
			{
				Name:        "X-Remote-IP",
				Description: "Uses X-Remote-IP header",
				Apply:       applyXRemoteIP,
			},
			{
				Name:        "X-Client-IP",
				Description: "Uses X-Client-IP header",
				Apply:       applyXClientIP,
			},
		},
	}
}

// ApplyBypass applies a random bypass technique
func (r *RateLimitBypass) ApplyBypass(req *resty.Request) {
	if len(r.techniques) == 0 {
		return
	}

	index, err := rand.Int(rand.Reader, big.NewInt(int64(len(r.techniques))))
	if err != nil {
		return
	}

	technique := r.techniques[index.Int64()]
	technique.Apply(req)
}

// Rate limit bypass technique implementations
func applyXForwardedFor(req *resty.Request) {
	ip := generateRandomPublicIP()
	req.SetHeader("X-Forwarded-For", ip)
}

func applyXRealIP(req *resty.Request) {
	ip := generateRandomPublicIP()
	req.SetHeader("X-Real-IP", ip)
}

func applyXOriginatingIP(req *resty.Request) {
	ip := generateRandomPublicIP()
	req.SetHeader("X-Originating-IP", ip)
}

func applyXRemoteIP(req *resty.Request) {
	ip := generateRandomPublicIP()
	req.SetHeader("X-Remote-IP", ip)
}

func applyXClientIP(req *resty.Request) {
	ip := generateRandomPublicIP()
	req.SetHeader("X-Client-IP", ip)
}

// generateRandomPublicIP generates a random public IP address
func generateRandomPublicIP() string {
	// Generate random public IP ranges (avoiding private ranges)
	publicRanges := []func() string{
		func() string {
			// 1.0.0.0 - 126.255.255.255 (Class A)
			a, _ := rand.Int(rand.Reader, big.NewInt(126))
			b, _ := rand.Int(rand.Reader, big.NewInt(256))
			c, _ := rand.Int(rand.Reader, big.NewInt(256))
			d, _ := rand.Int(rand.Reader, big.NewInt(256))
			return fmt.Sprintf("%d.%d.%d.%d", a.Int64()+1, b.Int64(), c.Int64(), d.Int64())
		},
		func() string {
			// 128.0.0.0 - 191.255.255.255 (Class B)
			a, _ := rand.Int(rand.Reader, big.NewInt(64))
			b, _ := rand.Int(rand.Reader, big.NewInt(256))
			c, _ := rand.Int(rand.Reader, big.NewInt(256))
			d, _ := rand.Int(rand.Reader, big.NewInt(256))
			return fmt.Sprintf("%d.%d.%d.%d", a.Int64()+128, b.Int64(), c.Int64(), d.Int64())
		},
		func() string {
			// 192.0.0.0 - 223.255.255.255 (Class C, excluding 192.168.x.x)
			a := 192
			b, _ := rand.Int(rand.Reader, big.NewInt(256))
			for b.Int64() == 168 { // Avoid 192.168.x.x
				b, _ = rand.Int(rand.Reader, big.NewInt(256))
			}
			c, _ := rand.Int(rand.Reader, big.NewInt(256))
			d, _ := rand.Int(rand.Reader, big.NewInt(256))
			return fmt.Sprintf("%d.%d.%d.%d", a, b.Int64(), c.Int64(), d.Int64())
		},
	}

	index, _ := rand.Int(rand.Reader, big.NewInt(int64(len(publicRanges))))
	return publicRanges[index.Int64()]()
}