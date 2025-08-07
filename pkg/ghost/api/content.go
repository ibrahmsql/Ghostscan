package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-resty/resty/v2"
)

// ContentAPI represents the Ghost Content API client
type ContentAPI struct {
	client  *resty.Client
	baseURL string
	key     string
}

// ContentResponse represents a standard Ghost Content API response
type ContentResponse struct {
	Data []interface{} `json:"data"`
	Meta ContentMeta   `json:"meta"`
}

// ContentMeta represents pagination and metadata
type ContentMeta struct {
	Pagination Pagination `json:"pagination"`
}

// Pagination represents pagination information
type Pagination struct {
	Page  int `json:"page"`
	Limit int `json:"limit"`
	Pages int `json:"pages"`
	Total int `json:"total"`
	Next  int `json:"next"`
	Prev  int `json:"prev"`
}

// Post represents a Ghost post
type Post struct {
	ID              string    `json:"id"`
	UUID            string    `json:"uuid"`
	Title           string    `json:"title"`
	Slug            string    `json:"slug"`
	HTML            string    `json:"html"`
	CommentID       string    `json:"comment_id"`
	FeatureImage    string    `json:"feature_image"`
	Featured        bool      `json:"featured"`
	Visibility      string    `json:"visibility"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
	PublishedAt     time.Time `json:"published_at"`
	CustomExcerpt   string    `json:"custom_excerpt"`
	CodeinjectionHead string  `json:"codeinjection_head"`
	CodeinjectionFoot string  `json:"codeinjection_foot"`
	OgImage         string    `json:"og_image"`
	OgTitle         string    `json:"og_title"`
	OgDescription   string    `json:"og_description"`
	TwitterImage    string    `json:"twitter_image"`
	TwitterTitle    string    `json:"twitter_title"`
	TwitterDescription string `json:"twitter_description"`
	MetaTitle       string    `json:"meta_title"`
	MetaDescription string    `json:"meta_description"`
	EmailSubject    string    `json:"email_subject"`
	Frontmatter     string    `json:"frontmatter"`
	CanonicalURL    string    `json:"canonical_url"`
	Access          bool      `json:"access"`
	SendEmailWhenPublished bool `json:"send_email_when_published"`
	Tags            []Tag     `json:"tags"`
	Authors         []Author  `json:"authors"`
	PrimaryAuthor   Author    `json:"primary_author"`
	PrimaryTag      Tag       `json:"primary_tag"`
	URL             string    `json:"url"`
	Excerpt         string    `json:"excerpt"`
	ReadingTime     int       `json:"reading_time"`
}

// Author represents a Ghost author
type Author struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Slug            string `json:"slug"`
	ProfileImage    string `json:"profile_image"`
	CoverImage      string `json:"cover_image"`
	Bio             string `json:"bio"`
	Website         string `json:"website"`
	Location        string `json:"location"`
	Facebook        string `json:"facebook"`
	Twitter         string `json:"twitter"`
	MetaTitle       string `json:"meta_title"`
	MetaDescription string `json:"meta_description"`
	URL             string `json:"url"`
}

// Tag represents a Ghost tag
type Tag struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Slug            string `json:"slug"`
	Description     string `json:"description"`
	FeatureImage    string `json:"feature_image"`
	Visibility      string `json:"visibility"`
	OgImage         string `json:"og_image"`
	OgTitle         string `json:"og_title"`
	OgDescription   string `json:"og_description"`
	TwitterImage    string `json:"twitter_image"`
	TwitterTitle    string `json:"twitter_title"`
	TwitterDescription string `json:"twitter_description"`
	MetaTitle       string `json:"meta_title"`
	MetaDescription string `json:"meta_description"`
	CodeinjectionHead string `json:"codeinjection_head"`
	CodeinjectionFoot string `json:"codeinjection_foot"`
	CanonicalURL    string `json:"canonical_url"`
	AccentColor     string `json:"accent_color"`
	URL             string `json:"url"`
}

// Page represents a Ghost page
type Page struct {
	ID              string    `json:"id"`
	UUID            string    `json:"uuid"`
	Title           string    `json:"title"`
	Slug            string    `json:"slug"`
	HTML            string    `json:"html"`
	CommentID       string    `json:"comment_id"`
	FeatureImage    string    `json:"feature_image"`
	Featured        bool      `json:"featured"`
	Visibility      string    `json:"visibility"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
	PublishedAt     time.Time `json:"published_at"`
	CustomExcerpt   string    `json:"custom_excerpt"`
	CodeinjectionHead string  `json:"codeinjection_head"`
	CodeinjectionFoot string  `json:"codeinjection_foot"`
	OgImage         string    `json:"og_image"`
	OgTitle         string    `json:"og_title"`
	OgDescription   string    `json:"og_description"`
	TwitterImage    string    `json:"twitter_image"`
	TwitterTitle    string    `json:"twitter_title"`
	TwitterDescription string `json:"twitter_description"`
	MetaTitle       string    `json:"meta_title"`
	MetaDescription string    `json:"meta_description"`
	Frontmatter     string    `json:"frontmatter"`
	CanonicalURL    string    `json:"canonical_url"`
	Access          bool      `json:"access"`
	Tags            []Tag     `json:"tags"`
	Authors         []Author  `json:"authors"`
	PrimaryAuthor   Author    `json:"primary_author"`
	PrimaryTag      Tag       `json:"primary_tag"`
	URL             string    `json:"url"`
	Excerpt         string    `json:"excerpt"`
	ReadingTime     int       `json:"reading_time"`
}

// Settings represents Ghost site settings
type Settings struct {
	Title                 string `json:"title"`
	Description           string `json:"description"`
	Logo                  string `json:"logo"`
	Icon                  string `json:"icon"`
	AccentColor           string `json:"accent_color"`
	CoverImage            string `json:"cover_image"`
	Facebook              string `json:"facebook"`
	Twitter               string `json:"twitter"`
	Lang                  string `json:"lang"`
	Timezone              string `json:"timezone"`
	CodeinjectionHead     string `json:"codeinjection_head"`
	CodeinjectionFoot     string `json:"codeinjection_foot"`
	Navigation            []NavigationItem `json:"navigation"`
	SecondaryNavigation   []NavigationItem `json:"secondary_navigation"`
	MetaTitle             string `json:"meta_title"`
	MetaDescription       string `json:"meta_description"`
	OgImage               string `json:"og_image"`
	OgTitle               string `json:"og_title"`
	OgDescription         string `json:"og_description"`
	TwitterImage          string `json:"twitter_image"`
	TwitterTitle          string `json:"twitter_title"`
	TwitterDescription    string `json:"twitter_description"`
	MembersSupport        string `json:"members_support_address"`
	CommentsEnabled       string `json:"comments_enabled"`
	URL                   string `json:"url"`
}

// NavigationItem represents a navigation menu item
type NavigationItem struct {
	Label string `json:"label"`
	URL   string `json:"url"`
}

// NewContentAPI creates a new Ghost Content API client
func NewContentAPI(baseURL string, timeout time.Duration) *ContentAPI {
	client := resty.New()
	client.SetTimeout(timeout)
	client.SetHeader("User-Agent", "GhostScan/1.0")
	client.SetHeader("Accept", "application/json")

	return &ContentAPI{
		client:  client,
		baseURL: strings.TrimSuffix(baseURL, "/"),
	}
}

// SetKey sets the Content API key
func (c *ContentAPI) SetKey(key string) {
	c.key = key
}

// GetPosts retrieves Ghost posts
func (c *ContentAPI) GetPosts(limit int, include string) ([]Post, error) {
	url := fmt.Sprintf("%s/ghost/api/v4/content/posts/", c.baseURL)
	req := c.client.R().SetResult(&ContentResponse{})

	if c.key != "" {
		req.SetQueryParam("key", c.key)
	}
	if limit > 0 {
		req.SetQueryParam("limit", fmt.Sprintf("%d", limit))
	}
	if include != "" {
		req.SetQueryParam("include", include)
	}

	resp, err := req.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to get posts: %w", err)
	}

	if resp.StatusCode() != http.StatusOK {
		return nil, fmt.Errorf("API request failed with status %d", resp.StatusCode())
	}

	contentResp := resp.Result().(*ContentResponse)
	postsData, err := json.Marshal(contentResp.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal posts data: %w", err)
	}

	var posts []Post
	err = json.Unmarshal(postsData, &posts)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal posts: %w", err)
	}

	return posts, nil
}

// GetAuthors retrieves Ghost authors
func (c *ContentAPI) GetAuthors(limit int, include string) ([]Author, error) {
	url := fmt.Sprintf("%s/ghost/api/v4/content/authors/", c.baseURL)
	req := c.client.R().SetResult(&ContentResponse{})

	if c.key != "" {
		req.SetQueryParam("key", c.key)
	}
	if limit > 0 {
		req.SetQueryParam("limit", fmt.Sprintf("%d", limit))
	}
	if include != "" {
		req.SetQueryParam("include", include)
	}

	resp, err := req.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to get authors: %w", err)
	}

	if resp.StatusCode() != http.StatusOK {
		return nil, fmt.Errorf("API request failed with status %d", resp.StatusCode())
	}

	contentResp := resp.Result().(*ContentResponse)
	authorsData, err := json.Marshal(contentResp.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal authors data: %w", err)
	}

	var authors []Author
	err = json.Unmarshal(authorsData, &authors)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal authors: %w", err)
	}

	return authors, nil
}

// GetTags retrieves Ghost tags
func (c *ContentAPI) GetTags(limit int, include string) ([]Tag, error) {
	url := fmt.Sprintf("%s/ghost/api/v4/content/tags/", c.baseURL)
	req := c.client.R().SetResult(&ContentResponse{})

	if c.key != "" {
		req.SetQueryParam("key", c.key)
	}
	if limit > 0 {
		req.SetQueryParam("limit", fmt.Sprintf("%d", limit))
	}
	if include != "" {
		req.SetQueryParam("include", include)
	}

	resp, err := req.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to get tags: %w", err)
	}

	if resp.StatusCode() != http.StatusOK {
		return nil, fmt.Errorf("API request failed with status %d", resp.StatusCode())
	}

	contentResp := resp.Result().(*ContentResponse)
	tagsData, err := json.Marshal(contentResp.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal tags data: %w", err)
	}

	var tags []Tag
	err = json.Unmarshal(tagsData, &tags)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal tags: %w", err)
	}

	return tags, nil
}

// GetPages retrieves Ghost pages
func (c *ContentAPI) GetPages(limit int, include string) ([]Page, error) {
	url := fmt.Sprintf("%s/ghost/api/v4/content/pages/", c.baseURL)
	req := c.client.R().SetResult(&ContentResponse{})

	if c.key != "" {
		req.SetQueryParam("key", c.key)
	}
	if limit > 0 {
		req.SetQueryParam("limit", fmt.Sprintf("%d", limit))
	}
	if include != "" {
		req.SetQueryParam("include", include)
	}

	resp, err := req.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to get pages: %w", err)
	}

	if resp.StatusCode() != http.StatusOK {
		return nil, fmt.Errorf("API request failed with status %d", resp.StatusCode())
	}

	contentResp := resp.Result().(*ContentResponse)
	pagesData, err := json.Marshal(contentResp.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal pages data: %w", err)
	}

	var pages []Page
	err = json.Unmarshal(pagesData, &pages)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal pages: %w", err)
	}

	return pages, nil
}

// GetSettings retrieves Ghost site settings
func (c *ContentAPI) GetSettings() (*Settings, error) {
	url := fmt.Sprintf("%s/ghost/api/v4/content/settings/", c.baseURL)
	req := c.client.R().SetResult(&ContentResponse{})

	if c.key != "" {
		req.SetQueryParam("key", c.key)
	}

	resp, err := req.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to get settings: %w", err)
	}

	if resp.StatusCode() != http.StatusOK {
		return nil, fmt.Errorf("API request failed with status %d", resp.StatusCode())
	}

	contentResp := resp.Result().(*ContentResponse)
	if len(contentResp.Data) == 0 {
		return nil, fmt.Errorf("no settings data returned")
	}

	settingsData, err := json.Marshal(contentResp.Data[0])
	if err != nil {
		return nil, fmt.Errorf("failed to marshal settings data: %w", err)
	}

	var settings Settings
	err = json.Unmarshal(settingsData, &settings)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal settings: %w", err)
	}

	return &settings, nil
}

// TestEndpoint tests if the Content API endpoint is accessible
func (c *ContentAPI) TestEndpoint() (bool, error) {
	resp, err := c.client.R().
		Get(fmt.Sprintf("%s/ghost/api/v4/content/settings/", c.baseURL))

	if err != nil {
		return false, fmt.Errorf("endpoint test failed: %w", err)
	}

	return resp.StatusCode() == http.StatusOK, nil
}