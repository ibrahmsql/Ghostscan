package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-resty/resty/v2"
)

// MembersAPI represents the Ghost Members API client
type MembersAPI struct {
	client  *resty.Client
	baseURL string
	token   string
}

// Member represents a Ghost member
type Member struct {
	ID                    string                 `json:"id"`
	UUID                  string                 `json:"uuid"`
	Email                 string                 `json:"email"`
	Name                  string                 `json:"name"`
	Note                  string                 `json:"note"`
	Geolocation           string                 `json:"geolocation"`
	Status                string                 `json:"status"`
	CreatedAt             time.Time              `json:"created_at"`
	UpdatedAt             time.Time              `json:"updated_at"`
	SigninAt              *time.Time             `json:"signin_at"`
	EmailCount            int                    `json:"email_count"`
	EmailOpenedCount      int                    `json:"email_opened_count"`
	EmailOpenRate         float64                `json:"email_open_rate"`
	Avatar                string                 `json:"avatar"`
	Comped                bool                   `json:"comped"`
	EmailSuppression      EmailSuppression       `json:"email_suppression"`
	Newsletters           []Newsletter           `json:"newsletters"`
	Labels                []Label                `json:"labels"`
	Tiers                 []Tier                 `json:"tiers"`
	Subscriptions         []Subscription         `json:"subscriptions"`
}

// EmailSuppression represents email suppression settings
type EmailSuppression struct {
	Suppressed bool   `json:"suppressed"`
	Info       string `json:"info"`
}

// Newsletter represents a newsletter
type Newsletter struct {
	ID          string `json:"id"`
	UUID        string `json:"uuid"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Slug        string `json:"slug"`
	SenderName  string `json:"sender_name"`
	SenderEmail string `json:"sender_email"`
	Status      string `json:"status"`
	Visibility  string `json:"visibility"`
	SubscribeOnSignup bool `json:"subscribe_on_signup"`
	SortOrder   int    `json:"sort_order"`
	HeaderImage string `json:"header_image"`
	ShowHeaderIcon bool `json:"show_header_icon"`
	ShowHeaderTitle bool `json:"show_header_title"`
	TitleFontCategory string `json:"title_font_category"`
	TitleAlignment string `json:"title_alignment"`
	ShowFeatureImage bool `json:"show_feature_image"`
	BodyFontCategory string `json:"body_font_category"`
	FooterContent string `json:"footer_content"`
	BorderColor   string `json:"border_color"`
	TitleColor    string `json:"title_color"`
}

// Label represents a member label
type Label struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Slug string `json:"slug"`
}

// Tier represents a membership tier
type Tier struct {
	ID                  string    `json:"id"`
	Name                string    `json:"name"`
	Slug                string    `json:"slug"`
	Description         string    `json:"description"`
	Active              bool      `json:"active"`
	Type                string    `json:"type"`
	WelcomePageURL      string    `json:"welcome_page_url"`
	CreatedAt           time.Time `json:"created_at"`
	UpdatedAt           time.Time `json:"updated_at"`
	Visibility          string    `json:"visibility"`
	TrialDays           int       `json:"trial_days"`
	MonthlyPrice        int       `json:"monthly_price"`
	YearlyPrice         int       `json:"yearly_price"`
	Currency            string    `json:"currency"`
	MonthlyPriceID      string    `json:"monthly_price_id"`
	YearlyPriceID       string    `json:"yearly_price_id"`
	Benefits            []string  `json:"benefits"`
}

// Subscription represents a member subscription
type Subscription struct {
	ID                string     `json:"id"`
	CustomerID        string     `json:"customer_id"`
	SubscriptionID    string     `json:"subscription_id"`
	PlanID            string     `json:"plan_id"`
	Status            string     `json:"status"`
	StartDate         time.Time  `json:"start_date"`
	DefaultPaymentCardLast4 string `json:"default_payment_card_last4"`
	CancelAtPeriodEnd bool       `json:"cancel_at_period_end"`
	CanceledAt        *time.Time `json:"canceled_at"`
	CurrentPeriodEnd  time.Time  `json:"current_period_end"`
	Price             Price      `json:"price"`
	Tier              Tier       `json:"tier"`
}

// Price represents subscription pricing
type Price struct {
	ID       string `json:"id"`
	PriceID  string `json:"price_id"`
	Nickname string `json:"nickname"`
	Amount   int    `json:"amount"`
	Interval string `json:"interval"`
	Type     string `json:"type"`
	Currency string `json:"currency"`
}

// MemberStats represents member statistics
type MemberStats struct {
	Total           int                    `json:"total"`
	TotalInRange    int                    `json:"total_in_range"`
	TotalOnDate     map[string]int         `json:"total_on_date"`
	NewToday        int                    `json:"new_today"`
	Data            []MemberStatsData      `json:"data"`
	Resource        string                 `json:"resource"`
	Meta            map[string]interface{} `json:"meta"`
}

// MemberStatsData represents daily member statistics
type MemberStatsData struct {
	Date string `json:"date"`
	Free int    `json:"free"`
	Paid int    `json:"paid"`
	Comped int  `json:"comped"`
}

// NewMembersAPI creates a new Ghost Members API client
func NewMembersAPI(baseURL string, timeout time.Duration) *MembersAPI {
	client := resty.New()
	client.SetTimeout(timeout)
	client.SetHeader("User-Agent", "GhostScan/1.0")
	client.SetHeader("Accept", "application/json")
	client.SetHeader("Content-Type", "application/json")

	return &MembersAPI{
		client:  client,
		baseURL: strings.TrimSuffix(baseURL, "/"),
	}
}

// SetToken sets the JWT token for authenticated requests
func (m *MembersAPI) SetToken(token string) {
	m.token = token
	m.client.SetHeader("Authorization", fmt.Sprintf("Ghost %s", token))
}

// GetMembers retrieves Ghost members
func (m *MembersAPI) GetMembers(limit int, filter string) ([]Member, error) {
	url := fmt.Sprintf("%s/ghost/api/v4/admin/members/", m.baseURL)
	req := m.client.R().SetResult(&AdminResponse{})

	if limit > 0 {
		req.SetQueryParam("limit", fmt.Sprintf("%d", limit))
	}
	if filter != "" {
		req.SetQueryParam("filter", filter)
	}

	resp, err := req.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to get members: %w", err)
	}

	if resp.StatusCode() != http.StatusOK {
		return nil, fmt.Errorf("API request failed with status %d", resp.StatusCode())
	}

	adminResp := resp.Result().(*AdminResponse)
	if len(adminResp.Errors) > 0 {
		return nil, fmt.Errorf("API error: %s", adminResp.Errors[0].Message)
	}

	membersData, err := json.Marshal(adminResp.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal members data: %w", err)
	}

	var members []Member
	err = json.Unmarshal(membersData, &members)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal members: %w", err)
	}

	return members, nil
}

// GetMemberStats retrieves member statistics
func (m *MembersAPI) GetMemberStats(days int) (*MemberStats, error) {
	url := fmt.Sprintf("%s/ghost/api/v4/admin/stats/member_count/", m.baseURL)
	req := m.client.R().SetResult(&MemberStats{})

	if days > 0 {
		req.SetQueryParam("days", fmt.Sprintf("%d", days))
	}

	resp, err := req.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to get member stats: %w", err)
	}

	if resp.StatusCode() != http.StatusOK {
		return nil, fmt.Errorf("API request failed with status %d", resp.StatusCode())
	}

	stats := resp.Result().(*MemberStats)
	return stats, nil
}

// GetNewsletters retrieves available newsletters
func (m *MembersAPI) GetNewsletters() ([]Newsletter, error) {
	resp, err := m.client.R().
		SetResult(&AdminResponse{}).
		Get(fmt.Sprintf("%s/ghost/api/v4/admin/newsletters/", m.baseURL))

	if err != nil {
		return nil, fmt.Errorf("failed to get newsletters: %w", err)
	}

	if resp.StatusCode() != http.StatusOK {
		return nil, fmt.Errorf("API request failed with status %d", resp.StatusCode())
	}

	adminResp := resp.Result().(*AdminResponse)
	if len(adminResp.Errors) > 0 {
		return nil, fmt.Errorf("API error: %s", adminResp.Errors[0].Message)
	}

	newslettersData, err := json.Marshal(adminResp.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal newsletters data: %w", err)
	}

	var newsletters []Newsletter
	err = json.Unmarshal(newslettersData, &newsletters)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal newsletters: %w", err)
	}

	return newsletters, nil
}

// GetTiers retrieves membership tiers
func (m *MembersAPI) GetTiers() ([]Tier, error) {
	resp, err := m.client.R().
		SetResult(&AdminResponse{}).
		Get(fmt.Sprintf("%s/ghost/api/v4/admin/tiers/", m.baseURL))

	if err != nil {
		return nil, fmt.Errorf("failed to get tiers: %w", err)
	}

	if resp.StatusCode() != http.StatusOK {
		return nil, fmt.Errorf("API request failed with status %d", resp.StatusCode())
	}

	adminResp := resp.Result().(*AdminResponse)
	if len(adminResp.Errors) > 0 {
		return nil, fmt.Errorf("API error: %s", adminResp.Errors[0].Message)
	}

	tiersData, err := json.Marshal(adminResp.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal tiers data: %w", err)
	}

	var tiers []Tier
	err = json.Unmarshal(tiersData, &tiers)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal tiers: %w", err)
	}

	return tiers, nil
}

// TestMembersEndpoint tests if the Members API is accessible
func (m *MembersAPI) TestMembersEndpoint() (bool, error) {
	resp, err := m.client.R().
		Get(fmt.Sprintf("%s/members/", m.baseURL))

	if err != nil {
		return false, fmt.Errorf("members endpoint test failed: %w", err)
	}

	// Members endpoint might return 200, 302, or 404 depending on configuration
	return resp.StatusCode() == http.StatusOK || resp.StatusCode() == http.StatusFound, nil
}

// TestSignupEndpoint tests if member signup is enabled
func (m *MembersAPI) TestSignupEndpoint() (bool, error) {
	resp, err := m.client.R().
		Get(fmt.Sprintf("%s/members/api/signup/", m.baseURL))

	if err != nil {
		return false, fmt.Errorf("signup endpoint test failed: %w", err)
	}

	return resp.StatusCode() != http.StatusNotFound, nil
}

// TestSubscriptionEndpoint tests if paid subscriptions are enabled
func (m *MembersAPI) TestSubscriptionEndpoint() (bool, error) {
	resp, err := m.client.R().
		Get(fmt.Sprintf("%s/members/api/subscribe/", m.baseURL))

	if err != nil {
		return false, fmt.Errorf("subscription endpoint test failed: %w", err)
	}

	return resp.StatusCode() != http.StatusNotFound, nil
}

// CheckMembersConfiguration checks if members system is properly configured
func (m *MembersAPI) CheckMembersConfiguration() (map[string]bool, error) {
	config := map[string]bool{
		"members_enabled":      false,
		"signup_enabled":       false,
		"subscriptions_enabled": false,
		"newsletters_enabled":   false,
	}

	// Test members endpoint
	membersEnabled, _ := m.TestMembersEndpoint()
	config["members_enabled"] = membersEnabled

	// Test signup endpoint
	signupEnabled, _ := m.TestSignupEndpoint()
	config["signup_enabled"] = signupEnabled

	// Test subscription endpoint
	subscriptionsEnabled, _ := m.TestSubscriptionEndpoint()
	config["subscriptions_enabled"] = subscriptionsEnabled

	// Test newsletters
	newsletters, err := m.GetNewsletters()
	if err == nil && len(newsletters) > 0 {
		config["newsletters_enabled"] = true
	}

	return config, nil
}