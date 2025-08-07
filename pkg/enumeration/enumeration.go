package enumeration

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/tidwall/gjson"
)

// Enumerator handles Ghost CMS component enumeration
type Enumerator struct {
	client    *resty.Client
	targetURL string
	threads   int
	verbose   bool
}

// EnumerationResult holds enumeration results
type EnumerationResult struct {
	Themes      []Theme      `json:"themes"`
	Users       []User       `json:"users"`
	Posts       []Post       `json:"posts"`
	Tags        []Tag        `json:"tags"`
	Integrations []Integration `json:"integrations"`
}

// Theme represents a Ghost theme
type Theme struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Active      bool   `json:"active"`
	Path        string `json:"path"`
	Description string `json:"description"`
	Author      string `json:"author"`
	Vulnerable  bool   `json:"vulnerable"`
}

// User represents a Ghost user
type User struct {
	ID       string `json:"id"`
	Slug     string `json:"slug"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Role     string `json:"role"`
	Bio      string `json:"bio"`
	Website  string `json:"website"`
	Location string `json:"location"`
}

// Post represents a Ghost post
type Post struct {
	ID          string   `json:"id"`
	Slug        string   `json:"slug"`
	Title       string   `json:"title"`
	Author      string   `json:"author"`
	PublishedAt string   `json:"published_at"`
	Tags        []string `json:"tags"`
	Excerpt     string   `json:"excerpt"`
}

// Tag represents a Ghost tag
type Tag struct {
	ID          string `json:"id"`
	Slug        string `json:"slug"`
	Name        string `json:"name"`
	Description string `json:"description"`
	PostCount   int    `json:"post_count"`
}

// Integration represents a Ghost integration
type Integration struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Enabled     bool   `json:"enabled"`
	Description string `json:"description"`
	Endpoint    string `json:"endpoint"`
}

// NewEnumerator creates a new Ghost CMS enumerator
func NewEnumerator(targetURL string, threads int, verbose bool, timeout int, userAgent string) *Enumerator {
	client := resty.New()
	client.SetTimeout(time.Duration(timeout) * time.Second)
	client.SetHeader("User-Agent", userAgent)
	
	return &Enumerator{
		client:    client,
		targetURL: targetURL,
		threads:   threads,
		verbose:   verbose,
	}
}

// EnumerateAll performs comprehensive enumeration
func (e *Enumerator) EnumerateAll(ctx context.Context) (*EnumerationResult, error) {
	result := &EnumerationResult{}
	
	// Enumerate themes
	if e.verbose {
		fmt.Println("[*] Enumerating themes...")
	}
	themes, err := e.EnumerateThemes(ctx)
	if err == nil {
		result.Themes = themes
	}
	
	// Enumerate users
	if e.verbose {
		fmt.Println("[*] Enumerating users...")
	}
	users, err := e.EnumerateUsers(ctx)
	if err == nil {
		result.Users = users
	}
	
	// Enumerate posts
	if e.verbose {
		fmt.Println("[*] Enumerating posts...")
	}
	posts, err := e.EnumeratePosts(ctx)
	if err == nil {
		result.Posts = posts
	}
	
	// Enumerate tags
	if e.verbose {
		fmt.Println("[*] Enumerating tags...")
	}
	tags, err := e.EnumerateTags(ctx)
	if err == nil {
		result.Tags = tags
	}
	
	// Enumerate integrations
	if e.verbose {
		fmt.Println("[*] Enumerating integrations...")
	}
	integrations, err := e.EnumerateIntegrations(ctx)
	if err == nil {
		result.Integrations = integrations
	}
	
	return result, nil
}

// EnumerateThemes discovers Ghost themes
func (e *Enumerator) EnumerateThemes(ctx context.Context) ([]Theme, error) {
	themes := []Theme{}
	
	// Method 1: Check active theme from main page
	resp, err := e.client.R().SetContext(ctx).Get(e.targetURL)
	if err != nil {
		return themes, err
	}
	
	body := resp.String()
	
	// Extract active theme from assets path
	themeRegex := regexp.MustCompile(`/content/themes/([^/]+)/`)
	matches := themeRegex.FindAllStringSubmatch(body, -1)
	themeNames := make(map[string]bool)
	
	for _, match := range matches {
		if len(match) > 1 {
			themeNames[match[1]] = true
		}
	}
	
	// Method 2: Try common theme names
	commonThemes := []string{
		"casper", "dawn", "edition", "london", "massively",
		"journal", "alto", "ease", "ghost", "default",
		"starter", "simple", "clean", "minimal", "blog",
	}
	
	for _, themeName := range commonThemes {
		themeNames[themeName] = true
	}
	
	// Check each theme
	var wg sync.WaitGroup
	themeChan := make(chan Theme, len(themeNames))
	
	for themeName := range themeNames {
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			if theme := e.checkTheme(ctx, name); theme.Name != "" {
				themeChan <- theme
			}
		}(themeName)
	}
	
	go func() {
		wg.Wait()
		close(themeChan)
	}()
	
	for theme := range themeChan {
		themes = append(themes, theme)
	}
	
	return themes, nil
}

// checkTheme checks if a theme exists and gathers information
func (e *Enumerator) checkTheme(ctx context.Context, themeName string) Theme {
	theme := Theme{Name: themeName}
	
	// Check theme directory
	themeURL := e.targetURL + "/content/themes/" + themeName + "/"
	resp, err := e.client.R().SetContext(ctx).Get(themeURL)
	if err != nil || resp.StatusCode() != 200 {
		return Theme{}
	}
	
	theme.Path = "/content/themes/" + themeName + "/"
	
	// Try to get package.json for theme info
	packageURL := e.targetURL + "/content/themes/" + themeName + "/package.json"
	packageResp, err := e.client.R().SetContext(ctx).Get(packageURL)
	if err == nil && packageResp.StatusCode() == 200 {
		packageBody := packageResp.String()
		theme.Version = gjson.Get(packageBody, "version").String()
		theme.Description = gjson.Get(packageBody, "description").String()
		theme.Author = gjson.Get(packageBody, "author").String()
	}
	
	// Check if theme is active (appears in main page)
	mainResp, err := e.client.R().SetContext(ctx).Get(e.targetURL)
	if err == nil {
		mainBody := mainResp.String()
		if strings.Contains(mainBody, "/content/themes/"+themeName+"/") {
			theme.Active = true
		}
	}
	
	// Check for known vulnerable themes
	theme.Vulnerable = e.isThemeVulnerable(themeName, theme.Version)
	
	return theme
}

// EnumerateUsers discovers Ghost users
func (e *Enumerator) EnumerateUsers(ctx context.Context) ([]User, error) {
	users := []User{}
	
	// Method 1: Public authors API
	authorsResp, err := e.client.R().SetContext(ctx).Get(e.targetURL + "/ghost/api/v4/content/authors/?limit=all")
	if err == nil && authorsResp.StatusCode() == 200 {
		authorsBody := authorsResp.String()
		authorsData := gjson.Get(authorsBody, "authors")
		
		authorsData.ForEach(func(key, value gjson.Result) bool {
			user := User{
				ID:       value.Get("id").String(),
				Slug:     value.Get("slug").String(),
				Name:     value.Get("name").String(),
				Bio:      value.Get("bio").String(),
				Website:  value.Get("website").String(),
				Location: value.Get("location").String(),
			}
			users = append(users, user)
			return true
		})
	}
	
	// Method 2: Extract from RSS feed
	rssResp, err := e.client.R().SetContext(ctx).Get(e.targetURL + "/rss/")
	if err == nil && rssResp.StatusCode() == 200 {
		rssBody := rssResp.String()
		authorRegex := regexp.MustCompile(`<dc:creator><!\[CDATA\[([^\]]+)\]\]></dc:creator>`)
		matches := authorRegex.FindAllStringSubmatch(rssBody, -1)
		
		for _, match := range matches {
			if len(match) > 1 {
				// Check if user already exists
				exists := false
				for _, existingUser := range users {
					if existingUser.Name == match[1] {
						exists = true
						break
					}
				}
				
				if !exists {
					users = append(users, User{
						Name: match[1],
						Slug: strings.ToLower(strings.ReplaceAll(match[1], " ", "-")),
					})
				}
			}
		}
	}
	
	return users, nil
}

// EnumeratePosts discovers Ghost posts
func (e *Enumerator) EnumeratePosts(ctx context.Context) ([]Post, error) {
	posts := []Post{}
	
	// Use content API to get posts
	postsResp, err := e.client.R().SetContext(ctx).Get(e.targetURL + "/ghost/api/v4/content/posts/?limit=50&include=authors,tags")
	if err != nil {
		return posts, err
	}
	
	if postsResp.StatusCode() != 200 {
		return posts, fmt.Errorf("failed to fetch posts: %d", postsResp.StatusCode())
	}
	
	postsBody := postsResp.String()
	postsData := gjson.Get(postsBody, "posts")
	
	postsData.ForEach(func(key, value gjson.Result) bool {
		post := Post{
			ID:          value.Get("id").String(),
			Slug:        value.Get("slug").String(),
			Title:       value.Get("title").String(),
			PublishedAt: value.Get("published_at").String(),
			Excerpt:     value.Get("excerpt").String(),
		}
		
		// Extract author
		authors := value.Get("authors")
		if authors.Exists() && authors.IsArray() {
			firstAuthor := authors.Array()[0]
			post.Author = firstAuthor.Get("name").String()
		}
		
		// Extract tags
		tags := value.Get("tags")
		if tags.Exists() && tags.IsArray() {
			for _, tag := range tags.Array() {
				post.Tags = append(post.Tags, tag.Get("name").String())
			}
		}
		
		posts = append(posts, post)
		return true
	})
	
	return posts, nil
}

// EnumerateTags discovers Ghost tags
func (e *Enumerator) EnumerateTags(ctx context.Context) ([]Tag, error) {
	tags := []Tag{}
	
	// Use content API to get tags
	tagsResp, err := e.client.R().SetContext(ctx).Get(e.targetURL + "/ghost/api/v4/content/tags/?limit=all&include=count.posts")
	if err != nil {
		return tags, err
	}
	
	if tagsResp.StatusCode() != 200 {
		return tags, fmt.Errorf("failed to fetch tags: %d", tagsResp.StatusCode())
	}
	
	tagsBody := tagsResp.String()
	tagsData := gjson.Get(tagsBody, "tags")
	
	tagsData.ForEach(func(key, value gjson.Result) bool {
		tag := Tag{
			ID:          value.Get("id").String(),
			Slug:        value.Get("slug").String(),
			Name:        value.Get("name").String(),
			Description: value.Get("description").String(),
			PostCount:   int(value.Get("count.posts").Int()),
		}
		tags = append(tags, tag)
		return true
	})
	
	return tags, nil
}

// EnumerateIntegrations discovers Ghost integrations
func (e *Enumerator) EnumerateIntegrations(ctx context.Context) ([]Integration, error) {
	integrations := []Integration{}
	
	// Check for common integrations by looking at the main page
	resp, err := e.client.R().SetContext(ctx).Get(e.targetURL)
	if err != nil {
		return integrations, err
	}
	
	body := resp.String()
	
	// Check for Google Analytics
	if strings.Contains(body, "google-analytics.com") || strings.Contains(body, "gtag") {
		integrations = append(integrations, Integration{
			Name:        "Google Analytics",
			Type:        "Analytics",
			Enabled:     true,
			Description: "Google Analytics tracking detected",
		})
	}
	
	// Check for Disqus
	if strings.Contains(body, "disqus.com") || strings.Contains(body, "disqus_shortname") {
		integrations = append(integrations, Integration{
			Name:        "Disqus",
			Type:        "Comments",
			Enabled:     true,
			Description: "Disqus comments system detected",
		})
	}
	
	// Check for Mailgun (newsletter)
	if strings.Contains(body, "mailgun") {
		integrations = append(integrations, Integration{
			Name:        "Mailgun",
			Type:        "Email",
			Enabled:     true,
			Description: "Mailgun email service detected",
		})
	}
	
	// Check for Stripe (payments)
	if strings.Contains(body, "stripe.com") || strings.Contains(body, "stripe") {
		integrations = append(integrations, Integration{
			Name:        "Stripe",
			Type:        "Payment",
			Enabled:     true,
			Description: "Stripe payment processing detected",
		})
	}
	
	// Check for members system
	membersResp, err := e.client.R().SetContext(ctx).Get(e.targetURL + "/members/")
	if err == nil && membersResp.StatusCode() == 200 {
		integrations = append(integrations, Integration{
			Name:        "Members",
			Type:        "Membership",
			Enabled:     true,
			Description: "Ghost members system enabled",
			Endpoint:    "/members/",
		})
	}
	
	return integrations, nil
}

// isThemeVulnerable checks if a theme has known vulnerabilities
func (e *Enumerator) isThemeVulnerable(themeName, version string) bool {
	// Define known vulnerable themes
	vulnerableThemes := map[string][]string{
		"casper": {"3.0.0", "3.0.1", "3.0.2"},
		"dawn":   {"1.0.0", "1.0.1"},
		"london": {"1.0.0"},
	}
	
	if vulnVersions, exists := vulnerableThemes[themeName]; exists {
		for _, vulnVersion := range vulnVersions {
			if version == vulnVersion {
				return true
			}
		}
	}
	
	return false
}