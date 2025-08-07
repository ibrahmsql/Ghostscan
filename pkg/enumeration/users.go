package enumeration

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/go-resty/resty/v2"
)

// UserEnumerator handles Ghost CMS user enumeration
type UserEnumerator struct {
	client  *resty.Client
	baseURL string
	verbose bool
	config  *UserEnumConfig
}

// UserEnumConfig contains user enumeration configuration
type UserEnumConfig struct {
	MaxUsers        int
	Timeout         time.Duration
	UserAgent       string
	FollowRedirects bool
	SkipSSL         bool
	Proxy           string
	Cookies         string
	Headers         map[string]string
	Delay           time.Duration
	RandomDelay     bool
	PassiveOnly     bool
	AggressiveMode  bool
	UserList        []string
}

// GhostUser represents a discovered Ghost user
type GhostUser struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Slug        string            `json:"slug"`
	Email       string            `json:"email,omitempty"`
	Role        string            `json:"role"`
	Status      string            `json:"status"`
	Location    string            `json:"location,omitempty"`
	Website     string            `json:"website,omitempty"`
	Bio         string            `json:"bio,omitempty"`
	ProfileImg  string            `json:"profile_image,omitempty"`
	CoverImg    string            `json:"cover_image,omitempty"`
	PostCount   int               `json:"post_count"`
	URL         string            `json:"url"`
	FoundBy     []string          `json:"found_by"`
	Confidence  int               `json:"confidence"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// UserEnumResult contains enumeration results
type UserEnumResult struct {
	Users       []*GhostUser `json:"users"`
	TotalFound  int          `json:"total_found"`
	Methods     []string     `json:"methods_used"`
	Duration    time.Duration `json:"duration"`
	Errors      []string     `json:"errors,omitempty"`
}

// NewUserEnumerator creates a new user enumerator
func NewUserEnumerator(baseURL string, config *UserEnumConfig) *UserEnumerator {
	if config == nil {
		config = &UserEnumConfig{
			MaxUsers:        100,
			Timeout:         30 * time.Second,
			UserAgent:       "GhostScan/1.0 (User Enumerator)",
			FollowRedirects: true,
			Delay:           100 * time.Millisecond,
		}
	}

	client := resty.New()
	client.SetTimeout(config.Timeout)
	client.SetHeader("User-Agent", config.UserAgent)
	client.SetRedirectPolicy(resty.FlexibleRedirectPolicy(10))

	if config.SkipSSL {
		client.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})
	}

	if config.Proxy != "" {
		client.SetProxy(config.Proxy)
	}

	return &UserEnumerator{
		client:  client,
		baseURL: strings.TrimSuffix(baseURL, "/"),
		config:  config,
	}
}

// EnumerateUsers performs comprehensive user enumeration
func (ue *UserEnumerator) EnumerateUsers(verbose bool) (*UserEnumResult, error) {
	ue.verbose = verbose
	start := time.Now()

	if verbose {
		color.Blue("[*] Starting Ghost CMS user enumeration...")
	}

	result := &UserEnumResult{
		Users:   make([]*GhostUser, 0),
		Methods: make([]string, 0),
		Errors:  make([]string, 0),
	}

	userMap := make(map[string]*GhostUser)

	// Method 1: Content API Authors Endpoint
	if !ue.config.PassiveOnly {
		if verbose {
			color.Yellow("[*] Enumerating via Content API authors endpoint...")
		}
		apiUsers, err := ue.enumerateViaContentAPI()
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("Content API enumeration failed: %v", err))
		} else {
			users := apiUsers
			result.Methods = append(result.Methods, "Content API")
			for _, user := range users {
				if existing, exists := userMap[user.Slug]; exists {
					existing.FoundBy = append(existing.FoundBy, "Content API")
					existing.Confidence += 20
				} else {
					user.FoundBy = []string{"Content API"}
					user.Confidence = 90
					userMap[user.Slug] = user
				}
			}
			if verbose {
				color.Green("[+] Found %d users via Content API", len(users))
			}
		}
		ue.applyDelay()
	}

	// Method 2: RSS Feed Analysis
	if verbose {
		color.Yellow("[*] Analyzing RSS feeds for authors...")
	}
	rssUsers, err := ue.enumerateViaRSS()
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("RSS enumeration failed: %v", err))
	} else {
		result.Methods = append(result.Methods, "RSS Feed Analysis")
		for _, user := range rssUsers {
			if existing, exists := userMap[user.Slug]; exists {
				existing.FoundBy = append(existing.FoundBy, "RSS Feed")
				existing.Confidence += 15
			} else {
				user.FoundBy = []string{"RSS Feed"}
				user.Confidence = 80
				userMap[user.Slug] = user
			}
		}
		if verbose {
			color.Green("[+] Found %d users via RSS analysis", len(rssUsers))
		}
	}
	ue.applyDelay()

	// Method 3: Author Page Discovery
	if !ue.config.PassiveOnly {
		if verbose {
			color.Yellow("[*] Discovering author pages...")
		}
		users, err := ue.enumerateViaAuthorPages()
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("Author page enumeration failed: %v", err))
		} else {
			result.Methods = append(result.Methods, "Author Page Discovery")
			for _, user := range users {
				if existing, exists := userMap[user.Slug]; exists {
					existing.FoundBy = append(existing.FoundBy, "Author Pages")
					existing.Confidence += 25
				} else {
					user.FoundBy = []string{"Author Pages"}
					user.Confidence = 85
					userMap[user.Slug] = user
				}
			}
			if verbose {
				color.Green("[+] Found %d users via author pages", len(users))
			}
		}
		ue.applyDelay()
	}

	// Method 4: Post Metadata Analysis
	if verbose {
		color.Yellow("[*] Analyzing post metadata...")
	}
	users, err := ue.enumerateViaPostMetadata()
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Post metadata enumeration failed: %v", err))
	} else {
		result.Methods = append(result.Methods, "Post Metadata Analysis")
		for _, user := range users {
			if existing, exists := userMap[user.Slug]; exists {
				existing.FoundBy = append(existing.FoundBy, "Post Metadata")
				existing.Confidence += 10
			} else {
				user.FoundBy = []string{"Post Metadata"}
				user.Confidence = 70
				userMap[user.Slug] = user
			}
		}
		if verbose {
			color.Green("[+] Found %d users via post metadata", len(users))
		}
	}
	ue.applyDelay()

	// Method 5: Admin API Enumeration (Aggressive)
	if ue.config.AggressiveMode {
		if verbose {
			color.Yellow("[*] Attempting admin API enumeration (aggressive)...")
		}
		users, err := ue.enumerateViaAdminAPI()
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("Admin API enumeration failed: %v", err))
		} else {
			result.Methods = append(result.Methods, "Admin API")
			for _, user := range users {
				if existing, exists := userMap[user.Slug]; exists {
					existing.FoundBy = append(existing.FoundBy, "Admin API")
					existing.Confidence += 30
				} else {
					user.FoundBy = []string{"Admin API"}
					user.Confidence = 95
					userMap[user.Slug] = user
				}
			}
			if verbose {
				color.Green("[+] Found %d users via admin API", len(users))
			}
		}
		ue.applyDelay()
	}

	// Method 6: Login Error Analysis
	if ue.config.AggressiveMode {
		if verbose {
			color.Yellow("[*] Analyzing login errors for user validation...")
		}
		users, err := ue.enumerateViaLoginErrors()
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("Login error enumeration failed: %v", err))
		} else {
			result.Methods = append(result.Methods, "Login Error Analysis")
			for _, user := range users {
				if existing, exists := userMap[user.Slug]; exists {
					existing.FoundBy = append(existing.FoundBy, "Login Errors")
					existing.Confidence += 20
				} else {
					user.FoundBy = []string{"Login Errors"}
					user.Confidence = 75
					userMap[user.Slug] = user
				}
			}
			if verbose {
				color.Green("[+] Found %d users via login error analysis", len(users))
			}
		}
		ue.applyDelay()
	}

	// Convert map to slice
	for _, user := range userMap {
		result.Users = append(result.Users, user)
	}

	result.TotalFound = len(result.Users)
	result.Duration = time.Since(start)

	if verbose {
		color.Green("[+] User enumeration completed in %v", result.Duration)
		color.Green("[+] Total users found: %d", result.TotalFound)
	}

	return result, nil
}

// enumerateViaContentAPI enumerates users via Ghost Content API
func (ue *UserEnumerator) enumerateViaContentAPI() ([]*GhostUser, error) {
	var users []*GhostUser

	// Try different API versions
	apiVersions := []string{"v4", "v3", "v2"}

	for _, version := range apiVersions {
		url := fmt.Sprintf("%s/ghost/api/%s/content/authors/?limit=%d&include=count.posts", ue.baseURL, version, ue.config.MaxUsers)
		
		resp, err := ue.client.R().Get(url)
		if err != nil {
			continue
		}

		if resp.StatusCode() == 200 {
			var apiResponse struct {
				Authors []struct {
					ID           string `json:"id"`
					Name         string `json:"name"`
					Slug         string `json:"slug"`
					Email        string `json:"email"`
					ProfileImage string `json:"profile_image"`
					CoverImage   string `json:"cover_image"`
					Bio          string `json:"bio"`
					Website      string `json:"website"`
					Location     string `json:"location"`
					URL          string `json:"url"`
					CountPosts   int    `json:"count.posts"`
				} `json:"authors"`
			}

			err = json.Unmarshal(resp.Body(), &apiResponse)
			if err != nil {
				continue
			}

			for _, author := range apiResponse.Authors {
				user := &GhostUser{
					ID:         author.ID,
					Name:       author.Name,
					Slug:       author.Slug,
					Email:      author.Email,
					Bio:        author.Bio,
					Website:    author.Website,
					Location:   author.Location,
					URL:        author.URL,
					ProfileImg: author.ProfileImage,
					CoverImg:   author.CoverImage,
					PostCount:  author.CountPosts,
					Role:       "Author",
					Status:     "active",
				}
				users = append(users, user)
			}
			break
		}
	}

	return users, nil
}

// enumerateViaRSS enumerates users via RSS feed analysis
func (ue *UserEnumerator) enumerateViaRSS() ([]*GhostUser, error) {
	var users []*GhostUser
	userMap := make(map[string]*GhostUser)

	// RSS endpoints to check
	rssEndpoints := []string{
		"/rss/",
		"/feed/",
		"/rss.xml",
		"/feed.xml",
	}

	for _, endpoint := range rssEndpoints {
		url := ue.baseURL + endpoint
		resp, err := ue.client.R().Get(url)
		if err != nil || resp.StatusCode() != 200 {
			continue
		}

		// Parse RSS for author information
		body := string(resp.Body())
		
		// Extract authors from RSS items
		authorRegex := regexp.MustCompile(`<dc:creator><\!\[CDATA\[([^\]]+)\]\]></dc:creator>`)
		matches := authorRegex.FindAllStringSubmatch(body, -1)
		
		for _, match := range matches {
			if len(match) > 1 {
				authorName := strings.TrimSpace(match[1])
				slug := strings.ToLower(strings.ReplaceAll(authorName, " ", "-"))
				
				if _, exists := userMap[slug]; !exists {
					user := &GhostUser{
						Name: authorName,
						Slug: slug,
						Role: "Author",
						URL:  fmt.Sprintf("%s/author/%s/", ue.baseURL, slug),
					}
					userMap[slug] = user
				}
			}
		}
		break // Use first successful RSS feed
	}

	for _, user := range userMap {
		users = append(users, user)
	}

	return users, nil
}

// enumerateViaAuthorPages discovers users through author page enumeration
func (ue *UserEnumerator) enumerateViaAuthorPages() ([]*GhostUser, error) {
	var users []*GhostUser

	// Common author slugs to test
	commonSlugs := []string{
		"admin", "administrator", "ghost", "author", "editor", "owner",
		"john", "jane", "test", "demo", "user", "writer", "blogger",
		"staff", "team", "support", "info", "contact", "hello",
	}

	// Add custom user list if provided
	if len(ue.config.UserList) > 0 {
		commonSlugs = append(commonSlugs, ue.config.UserList...)
	}

	for _, slug := range commonSlugs {
		url := fmt.Sprintf("%s/author/%s/", ue.baseURL, slug)
		resp, err := ue.client.R().Get(url)
		if err != nil {
			continue
		}

		if resp.StatusCode() == 200 {
			body := string(resp.Body())
			
			// Extract user information from author page
			user := &GhostUser{
				Slug: slug,
				URL:  url,
				Role: "Author",
			}

			// Extract name from page title or h1
			nameRegex := regexp.MustCompile(`<h1[^>]*>([^<]+)</h1>`)
			if match := nameRegex.FindStringSubmatch(body); len(match) > 1 {
				user.Name = strings.TrimSpace(match[1])
			}

			// Extract bio from meta description or author bio section
			bioRegex := regexp.MustCompile(`<meta name="description" content="([^"]+)"`)
			if match := bioRegex.FindStringSubmatch(body); len(match) > 1 {
				user.Bio = strings.TrimSpace(match[1])
			}

			// Extract post count
			postCountRegex := regexp.MustCompile(`(\d+)\s+posts?`)
			if match := postCountRegex.FindStringSubmatch(body); len(match) > 1 {
				if count, err := strconv.Atoi(match[1]); err == nil {
					user.PostCount = count
				}
			}

			users = append(users, user)
		}

		ue.applyDelay()
	}

	return users, nil
}

// enumerateViaPostMetadata analyzes post metadata for author information
func (ue *UserEnumerator) enumerateViaPostMetadata() ([]*GhostUser, error) {
	var users []*GhostUser
	userMap := make(map[string]*GhostUser)

	// Get posts via Content API
	url := fmt.Sprintf("%s/ghost/api/v4/content/posts/?limit=50&include=authors", ue.baseURL)
	resp, err := ue.client.R().Get(url)
	if err != nil || resp.StatusCode() != 200 {
		return users, err
	}

	var apiResponse struct {
		Posts []struct {
			Authors []struct {
				ID           string `json:"id"`
				Name         string `json:"name"`
				Slug         string `json:"slug"`
				ProfileImage string `json:"profile_image"`
				URL          string `json:"url"`
			} `json:"authors"`
		} `json:"posts"`
	}

	err = json.Unmarshal(resp.Body(), &apiResponse)
	if err != nil {
		return users, err
	}

	for _, post := range apiResponse.Posts {
		for _, author := range post.Authors {
			if _, exists := userMap[author.Slug]; !exists {
				user := &GhostUser{
					ID:         author.ID,
					Name:       author.Name,
					Slug:       author.Slug,
					URL:        author.URL,
					ProfileImg: author.ProfileImage,
					Role:       "Author",
					Status:     "active",
				}
				userMap[author.Slug] = user
			}
		}
	}

	for _, user := range userMap {
		users = append(users, user)
	}

	return users, nil
}

// enumerateViaAdminAPI attempts to enumerate users via admin API
func (ue *UserEnumerator) enumerateViaAdminAPI() ([]*GhostUser, error) {
	var users []*GhostUser

	// Try to access admin users endpoint (usually requires authentication)
	url := fmt.Sprintf("%s/ghost/api/v4/admin/users/", ue.baseURL)
	resp, err := ue.client.R().Get(url)
	if err != nil {
		return users, err
	}

	// Even if unauthorized, sometimes error messages leak user information
	if resp.StatusCode() == 401 || resp.StatusCode() == 403 {
		body := string(resp.Body())
		
		// Look for user information in error messages
		userRegex := regexp.MustCompile(`"user":\s*"([^"]+)"`)
		if match := userRegex.FindStringSubmatch(body); len(match) > 1 {
			user := &GhostUser{
				Name: match[1],
				Slug: strings.ToLower(strings.ReplaceAll(match[1], " ", "-")),
				Role: "Unknown",
			}
			users = append(users, user)
		}
	}

	return users, nil
}

// enumerateViaLoginErrors analyzes login error messages for user validation
func (ue *UserEnumerator) enumerateViaLoginErrors() ([]*GhostUser, error) {
	var users []*GhostUser

	// Common usernames to test
	testUsers := []string{"admin", "administrator", "ghost", "owner", "editor"}
	if len(ue.config.UserList) > 0 {
		testUsers = append(testUsers, ue.config.UserList...)
	}

	loginURL := fmt.Sprintf("%s/ghost/api/v4/admin/session/", ue.baseURL)

	for _, username := range testUsers {
		// Test with invalid password to trigger error
		payload := map[string]interface{}{
			"username": username,
			"password": "invalid_password_test_123",
		}

		resp, err := ue.client.R().
			SetHeader("Content-Type", "application/json").
			SetBody(payload).
			Post(loginURL)

		if err != nil {
			continue
		}

		body := string(resp.Body())
		
		// Analyze error messages for user existence indicators
		if strings.Contains(body, "password") && !strings.Contains(body, "user") {
			// Password error without user error suggests user exists
			user := &GhostUser{
				Name: username,
				Slug: username,
				Role: "Unknown",
			}
			users = append(users, user)
		}

		ue.applyDelay()
	}

	return users, nil
}

// applyDelay applies configured delay between requests
func (ue *UserEnumerator) applyDelay() {
	if ue.config.Delay > 0 {
		if ue.config.RandomDelay {
			// Add random variation (50-150% of base delay)
			variation := time.Duration(float64(ue.config.Delay) * (0.5 + (float64(time.Now().UnixNano()%100) / 100.0)))
			time.Sleep(variation)
		} else {
			time.Sleep(ue.config.Delay)
		}
	}
}

// SetVerbose sets verbose output mode
func (ue *UserEnumerator) SetVerbose(verbose bool) {
	ue.verbose = verbose
}

// GetUserBySlug attempts to get detailed user information by slug
func (ue *UserEnumerator) GetUserBySlug(slug string) (*GhostUser, error) {
	// Try Content API first
	url := fmt.Sprintf("%s/ghost/api/v4/content/authors/slug/%s/?include=count.posts", ue.baseURL, slug)
	resp, err := ue.client.R().Get(url)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode() == 200 {
		var apiResponse struct {
			Authors []struct {
				ID           string `json:"id"`
				Name         string `json:"name"`
				Slug         string `json:"slug"`
				Email        string `json:"email"`
				ProfileImage string `json:"profile_image"`
				CoverImage   string `json:"cover_image"`
				Bio          string `json:"bio"`
				Website      string `json:"website"`
				Location     string `json:"location"`
				URL          string `json:"url"`
				CountPosts   int    `json:"count.posts"`
			} `json:"authors"`
		}

		err = json.Unmarshal(resp.Body(), &apiResponse)
		if err != nil {
			return nil, err
		}

		if len(apiResponse.Authors) > 0 {
			author := apiResponse.Authors[0]
			return &GhostUser{
				ID:         author.ID,
				Name:       author.Name,
				Slug:       author.Slug,
				Email:      author.Email,
				Bio:        author.Bio,
				Website:    author.Website,
				Location:   author.Location,
				URL:        author.URL,
				ProfileImg: author.ProfileImage,
				CoverImg:   author.CoverImage,
				PostCount:  author.CountPosts,
				Role:       "Author",
				Status:     "active",
				Confidence: 100,
			}, nil
		}
	}

	return nil, fmt.Errorf("user not found")
}