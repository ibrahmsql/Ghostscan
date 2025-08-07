package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-resty/resty/v2"
)

// AdminAPI represents the Ghost Admin API client
type AdminAPI struct {
	client  *resty.Client
	baseURL string
	token   string
}

// AdminResponse represents a standard Ghost Admin API response
type AdminResponse struct {
	Data   interface{} `json:"data"`
	Meta   interface{} `json:"meta"`
	Errors []APIError  `json:"errors"`
}

// APIError represents an API error response
type APIError struct {
	Message string `json:"message"`
	Type    string `json:"type"`
	Code    string `json:"code"`
}

// SiteInfo represents Ghost site information
type SiteInfo struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	URL         string `json:"url"`
	Version     string `json:"version"`
	Timezone    string `json:"timezone"`
	Locale      string `json:"locale"`
}

// User represents a Ghost user
type User struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Slug     string `json:"slug"`
	Email    string `json:"email"`
	Status   string `json:"status"`
	Roles    []Role `json:"roles"`
	Location string `json:"location"`
	Website  string `json:"website"`
	Bio      string `json:"bio"`
}

// Role represents a user role
type Role struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Theme represents a Ghost theme
type Theme struct {
	Name        string            `json:"name"`
	Package     ThemePackage      `json:"package"`
	Active      bool              `json:"active"`
	Templates   []string          `json:"templates"`
	Errors      []ThemeError      `json:"errors"`
	Warnings    []ThemeWarning    `json:"warnings"`
}

// ThemePackage represents theme package.json
type ThemePackage struct {
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Version     string            `json:"version"`
	Engines     map[string]string `json:"engines"`
	Author      interface{}       `json:"author"`
	Keywords    []string          `json:"keywords"`
}

// ThemeError represents theme validation errors
type ThemeError struct {
	Level   string `json:"level"`
	Rule    string `json:"rule"`
	Details string `json:"details"`
	File    string `json:"file"`
}

// ThemeWarning represents theme validation warnings
type ThemeWarning struct {
	Level   string `json:"level"`
	Rule    string `json:"rule"`
	Details string `json:"details"`
	File    string `json:"file"`
}

// NewAdminAPI creates a new Ghost Admin API client
func NewAdminAPI(baseURL string, timeout time.Duration) *AdminAPI {
	client := resty.New()
	client.SetTimeout(timeout)
	client.SetHeader("User-Agent", "GhostScan/1.0")
	client.SetHeader("Accept", "application/json")
	client.SetHeader("Content-Type", "application/json")

	return &AdminAPI{
		client:  client,
		baseURL: strings.TrimSuffix(baseURL, "/"),
	}
}

// SetToken sets the JWT token for authenticated requests
func (a *AdminAPI) SetToken(token string) {
	a.token = token
	a.client.SetHeader("Authorization", fmt.Sprintf("Ghost %s", token))
}

// GetSiteInfo retrieves Ghost site information
func (a *AdminAPI) GetSiteInfo() (*SiteInfo, error) {
	resp, err := a.client.R().
		SetResult(&AdminResponse{}).
		Get(fmt.Sprintf("%s/ghost/api/v4/admin/site/", a.baseURL))

	if err != nil {
		return nil, fmt.Errorf("failed to get site info: %w", err)
	}

	if resp.StatusCode() != http.StatusOK {
		return nil, fmt.Errorf("API request failed with status %d", resp.StatusCode())
	}

	adminResp := resp.Result().(*AdminResponse)
	if len(adminResp.Errors) > 0 {
		return nil, fmt.Errorf("API error: %s", adminResp.Errors[0].Message)
	}

	siteData, err := json.Marshal(adminResp.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal site data: %w", err)
	}

	var siteInfo SiteInfo
	err = json.Unmarshal(siteData, &siteInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal site info: %w", err)
	}

	return &siteInfo, nil
}

// GetUsers retrieves Ghost users
func (a *AdminAPI) GetUsers() ([]User, error) {
	resp, err := a.client.R().
		SetResult(&AdminResponse{}).
		Get(fmt.Sprintf("%s/ghost/api/v4/admin/users/", a.baseURL))

	if err != nil {
		return nil, fmt.Errorf("failed to get users: %w", err)
	}

	if resp.StatusCode() != http.StatusOK {
		return nil, fmt.Errorf("API request failed with status %d", resp.StatusCode())
	}

	adminResp := resp.Result().(*AdminResponse)
	if len(adminResp.Errors) > 0 {
		return nil, fmt.Errorf("API error: %s", adminResp.Errors[0].Message)
	}

	usersData, err := json.Marshal(adminResp.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal users data: %w", err)
	}

	var users []User
	err = json.Unmarshal(usersData, &users)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal users: %w", err)
	}

	return users, nil
}

// GetThemes retrieves Ghost themes
func (a *AdminAPI) GetThemes() ([]Theme, error) {
	resp, err := a.client.R().
		SetResult(&AdminResponse{}).
		Get(fmt.Sprintf("%s/ghost/api/v4/admin/themes/", a.baseURL))

	if err != nil {
		return nil, fmt.Errorf("failed to get themes: %w", err)
	}

	if resp.StatusCode() != http.StatusOK {
		return nil, fmt.Errorf("API request failed with status %d", resp.StatusCode())
	}

	adminResp := resp.Result().(*AdminResponse)
	if len(adminResp.Errors) > 0 {
		return nil, fmt.Errorf("API error: %s", adminResp.Errors[0].Message)
	}

	themesData, err := json.Marshal(adminResp.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal themes data: %w", err)
	}

	var themes []Theme
	err = json.Unmarshal(themesData, &themes)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal themes: %w", err)
	}

	return themes, nil
}

// Login attempts to authenticate with Ghost admin
func (a *AdminAPI) Login(email, password string) error {
	loginData := map[string]interface{}{
		"username": email,
		"password": password,
	}

	resp, err := a.client.R().
		SetBody(loginData).
		SetResult(&AdminResponse{}).
		Post(fmt.Sprintf("%s/ghost/api/v4/admin/session/", a.baseURL))

	if err != nil {
		return fmt.Errorf("failed to login: %w", err)
	}

	if resp.StatusCode() != http.StatusCreated {
		return fmt.Errorf("login failed with status %d", resp.StatusCode())
	}

	adminResp := resp.Result().(*AdminResponse)
	if len(adminResp.Errors) > 0 {
		return fmt.Errorf("login error: %s", adminResp.Errors[0].Message)
	}

	return nil
}

// TestPathTraversal tests for CVE-2023-32235 path traversal vulnerability
func (a *AdminAPI) TestPathTraversal(payload string) (string, error) {
	resp, err := a.client.R().
		Get(fmt.Sprintf("%s/ghost/api/v4/admin/themes/preview/%s", a.baseURL, payload))

	if err != nil {
		return "", fmt.Errorf("path traversal test failed: %w", err)
	}

	return string(resp.Body()), nil
}

// CheckAuthentication verifies if current session is authenticated
func (a *AdminAPI) CheckAuthentication() (bool, error) {
	resp, err := a.client.R().
		Get(fmt.Sprintf("%s/ghost/api/v4/admin/users/me/", a.baseURL))

	if err != nil {
		return false, fmt.Errorf("authentication check failed: %w", err)
	}

	return resp.StatusCode() == http.StatusOK, nil
}