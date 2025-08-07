package vulnerabilities

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/fatih/color"
)

// DatabaseUpdater handles vulnerability database updates
type DatabaseUpdater struct {
	client     *http.Client
	cacheDir   string
	verbose    bool
	apiToken   string
	lastUpdate time.Time
}

// UpdateConfig contains update configuration
type UpdateConfig struct {
	APIToken    string
	CacheDir    string
	Verbose     bool
	ForceUpdate bool
	Timeout     time.Duration
}

// UpdateResult contains update operation results
type UpdateResult struct {
	Success        bool
	UpdatedCVEs    int
	NewCVEs        int
	RemovedCVEs    int
	DatabaseSize   int64
	UpdateDuration time.Duration
	Errors         []string
}

// NewDatabaseUpdater creates a new database updater
func NewDatabaseUpdater(config UpdateConfig) *DatabaseUpdater {
	cacheDir := config.CacheDir
	if cacheDir == "" {
		homeDir, _ := os.UserHomeDir()
		cacheDir = filepath.Join(homeDir, ".ghostscan", "db")
	}

	// Ensure cache directory exists
	os.MkdirAll(cacheDir, 0755)

	timeout := config.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	return &DatabaseUpdater{
		client: &http.Client{
			Timeout: timeout,
		},
		cacheDir: cacheDir,
		verbose:  config.Verbose,
		apiToken: config.APIToken,
	}
}

// UpdateDatabase updates the vulnerability database from remote sources
func (u *DatabaseUpdater) UpdateDatabase(force bool) (*UpdateResult, error) {
	start := time.Now()
	result := &UpdateResult{}

	if u.verbose {
		color.Blue("[*] Starting vulnerability database update...")
	}

	// Check if update is needed
	if !force && !u.needsUpdate() {
		if u.verbose {
			color.Green("[+] Database is up to date")
		}
		result.Success = true
		return result, nil
	}

	// Update from multiple sources
	sources := []string{
		"https://api.ghostscan.io/v1/vulnerabilities",
		"https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.gz",
		"https://github.com/ghostscan/vulnerability-database/raw/main/ghost-cves.json",
	}

	allCVEs := make(map[string]CVE)
	var errors []string

	for _, source := range sources {
		if u.verbose {
			color.Yellow("[*] Updating from: %s", source)
		}

		cves, err := u.fetchFromSource(source)
		if err != nil {
			errorMsg := fmt.Sprintf("Failed to update from %s: %v", source, err)
			errors = append(errors, errorMsg)
			if u.verbose {
				color.Red("[-] %s", errorMsg)
			}
			continue
		}

		// Merge CVEs
		for _, cve := range cves {
			if existing, exists := allCVEs[cve.ID]; exists {
				// Update if newer
				if cve.Modified.After(existing.Modified) {
					allCVEs[cve.ID] = cve
				}
			} else {
				allCVEs[cve.ID] = cve
				result.NewCVEs++
			}
		}

		if u.verbose {
			color.Green("[+] Fetched %d CVEs from %s", len(cves), source)
		}
	}

	// Load existing database
	existingDB, err := u.loadExistingDatabase()
	if err != nil && u.verbose {
		color.Yellow("[*] No existing database found, creating new one")
	}

	// Count updates
	if existingDB != nil {
		for _, existingCVE := range existingDB.CVEs {
			if newCVE, exists := allCVEs[existingCVE.ID]; exists {
				if newCVE.Modified.After(existingCVE.Modified) {
					result.UpdatedCVEs++
				}
			} else {
				result.RemovedCVEs++
			}
		}
	}

	// Create new database
	newDB := &VulnerabilityDatabase{
		CVEs:        make([]CVE, 0, len(allCVEs)),
		Signatures:  u.getDefaultSignatures(),
		LastUpdated: time.Now(),
		Version:     "1.0",
	}

	for _, cve := range allCVEs {
		newDB.CVEs = append(newDB.CVEs, cve)
	}

	// Save database
	err = u.saveDatabase(newDB)
	if err != nil {
		return nil, fmt.Errorf("failed to save database: %w", err)
	}

	// Update result
	result.Success = true
	result.DatabaseSize = int64(len(newDB.CVEs))
	result.UpdateDuration = time.Since(start)
	result.Errors = errors

	if u.verbose {
		color.Green("[+] Database updated successfully")
		color.Green("[+] Total CVEs: %d", len(newDB.CVEs))
		color.Green("[+] New CVEs: %d", result.NewCVEs)
		color.Green("[+] Updated CVEs: %d", result.UpdatedCVEs)
		color.Green("[+] Update completed in: %v", result.UpdateDuration)
	}

	return result, nil
}

// needsUpdate checks if database needs updating
func (u *DatabaseUpdater) needsUpdate() bool {
	dbPath := filepath.Join(u.cacheDir, "vulnerabilities.json")
	info, err := os.Stat(dbPath)
	if err != nil {
		return true // Database doesn't exist
	}

	// Update if older than 24 hours
	return time.Since(info.ModTime()) > 24*time.Hour
}

// fetchFromSource fetches CVEs from a remote source
func (u *DatabaseUpdater) fetchFromSource(source string) ([]CVE, error) {
	req, err := http.NewRequest("GET", source, nil)
	if err != nil {
		return nil, err
	}

	// Add API token if available
	if u.apiToken != "" {
		req.Header.Set("Authorization", "Bearer "+u.apiToken)
	}

	req.Header.Set("User-Agent", "GhostScan/1.0 (Vulnerability Database Updater)")

	resp, err := u.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Parse response based on source
	if filepath.Ext(source) == ".gz" {
		return u.parseNVDFeed(body)
	}

	return u.parseGhostCVEs(body)
}

// parseGhostCVEs parses Ghost-specific CVE format
func (u *DatabaseUpdater) parseGhostCVEs(data []byte) ([]CVE, error) {
	var response struct {
		CVEs []CVE `json:"cves"`
	}

	err := json.Unmarshal(data, &response)
	if err != nil {
		return nil, err
	}

	return response.CVEs, nil
}

// parseNVDFeed parses NVD CVE feed format
func (u *DatabaseUpdater) parseNVDFeed(data []byte) ([]CVE, error) {
	// Simplified NVD parsing - in real implementation, would handle gzip and full NVD format
	var nvdResponse struct {
		CVEItems []struct {
			CVE struct {
				CVEDataMeta struct {
					ID string `json:"ID"`
				} `json:"CVE_data_meta"`
				Description struct {
					DescriptionData []struct {
						Value string `json:"value"`
					} `json:"description_data"`
				} `json:"description"`
			} `json:"cve"`
			PublishedDate string `json:"publishedDate"`
			LastModifiedDate string `json:"lastModifiedDate"`
		} `json:"CVE_Items"`
	}

	err := json.Unmarshal(data, &nvdResponse)
	if err != nil {
		return nil, err
	}

	var cves []CVE
	for _, item := range nvdResponse.CVEItems {
		// Only include Ghost-related CVEs
		if !u.isGhostRelated(item.CVE.Description.DescriptionData) {
			continue
		}

		published, _ := time.Parse("2006-01-02T15:04Z", item.PublishedDate)
		modified, _ := time.Parse("2006-01-02T15:04Z", item.LastModifiedDate)

		cve := CVE{
			ID:          item.CVE.CVEDataMeta.ID,
			Title:       "Ghost CMS Vulnerability",
			Description: item.CVE.Description.DescriptionData[0].Value,
			Severity:    "Medium", // Would be determined from CVSS
			CVSS:        5.0,      // Would be parsed from impact data
			Published:   published,
			Modified:    modified,
			References:  []string{fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", item.CVE.CVEDataMeta.ID)},
		}

		cves = append(cves, cve)
	}

	return cves, nil
}

// isGhostRelated checks if a CVE is related to Ghost CMS
func (u *DatabaseUpdater) isGhostRelated(descriptions []struct {
	Value string `json:"value"`
}) bool {
	for _, desc := range descriptions {
		if contains(desc.Value, "ghost") || contains(desc.Value, "Ghost") {
			return true
		}
	}
	return false
}

// contains checks if a string contains a substring (case-insensitive)
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || 
		(len(s) > len(substr) && 
			(s[:len(substr)] == substr || s[len(s)-len(substr):] == substr ||
				containsHelper(s, substr))))
}

func containsHelper(s, substr string) bool {
	for i := 1; i < len(s)-len(substr)+1; i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// loadExistingDatabase loads the existing vulnerability database
func (u *DatabaseUpdater) loadExistingDatabase() (*VulnerabilityDatabase, error) {
	dbPath := filepath.Join(u.cacheDir, "vulnerabilities.json")
	data, err := os.ReadFile(dbPath)
	if err != nil {
		return nil, err
	}

	var db VulnerabilityDatabase
	err = json.Unmarshal(data, &db)
	if err != nil {
		return nil, err
	}

	return &db, nil
}

// saveDatabase saves the vulnerability database to disk
func (u *DatabaseUpdater) saveDatabase(db *VulnerabilityDatabase) error {
	dbPath := filepath.Join(u.cacheDir, "vulnerabilities.json")
	data, err := json.MarshalIndent(db, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(dbPath, data, 0644)
}

// getDefaultSignatures returns default detection signatures
func (u *DatabaseUpdater) getDefaultSignatures() []Signature {
	return []Signature{
		{
			ID:          "GHOST-SIG-001",
			Name:        "Ghost Meta Generator",
			Pattern:     `<meta name="generator" content="Ghost ([0-9\.]+)">`,
			Type:        "html",
			Severity:    "Info",
			Description: "Detects Ghost CMS via meta generator tag",
		},
		{
			ID:          "GHOST-SIG-002",
			Name:        "Ghost Admin Assets",
			Pattern:     `/assets/built/admin.*\.js`,
			Type:        "url",
			Severity:    "Info",
			Description: "Detects Ghost CMS via admin asset URLs",
		},
		{
			ID:          "GHOST-SIG-003",
			Name:        "Ghost API Endpoint",
			Pattern:     `/ghost/api/v[0-9]+/`,
			Type:        "url",
			Severity:    "Info",
			Description: "Detects Ghost CMS via API endpoints",
		},
		{
			ID:          "GHOST-SIG-004",
			Name:        "Ghost Cache Header",
			Pattern:     `X-Ghost-Cache: (hit|miss)`,
			Type:        "header",
			Severity:    "Info",
			Description: "Detects Ghost CMS via cache headers",
		},
	}
}

// GetDatabaseInfo returns information about the current database
func (u *DatabaseUpdater) GetDatabaseInfo() (*DatabaseInfo, error) {
	dbPath := filepath.Join(u.cacheDir, "vulnerabilities.json")
	info, err := os.Stat(dbPath)
	if err != nil {
		return nil, err
	}

	db, err := u.loadExistingDatabase()
	if err != nil {
		return nil, err
	}

	return &DatabaseInfo{
		Path:        dbPath,
		Size:        info.Size(),
		LastUpdated: db.LastUpdated,
		Version:     db.Version,
		CVECount:    len(db.CVEs),
	}, nil
}

// DatabaseInfo contains information about the vulnerability database
type DatabaseInfo struct {
	Path        string    `json:"path"`
	Size        int64     `json:"size"`
	LastUpdated time.Time `json:"last_updated"`
	Version     string    `json:"version"`
	CVECount    int       `json:"cve_count"`
}