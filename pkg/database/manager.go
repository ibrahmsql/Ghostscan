package database

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// DatabaseManager manages scan results and historical data
type DatabaseManager struct {
	db   *sql.DB
	path string
}

// ScanRecord represents a scan record in the database
type ScanRecord struct {
	ID           int64     `json:"id"`
	Target       string    `json:"target"`
	Timestamp    time.Time `json:"timestamp"`
	ScanDuration int64     `json:"scan_duration_ms"`
	IsGhost      bool      `json:"is_ghost"`
	Confidence   float64   `json:"confidence"`
	Version      string    `json:"version"`
	Theme        string    `json:"theme"`
	ResultsJSON  string    `json:"results_json"`
	Status       string    `json:"status"`
	ErrorMessage string    `json:"error_message"`
}

// VulnerabilityRecord represents a vulnerability record
type VulnerabilityRecord struct {
	ID          int64     `json:"id"`
	ScanID      int64     `json:"scan_id"`
	CVE         string    `json:"cve"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"`
	CVSS        float64   `json:"cvss"`
	Affected    string    `json:"affected"`
	Fixed       string    `json:"fixed"`
	Exploitable bool      `json:"exploitable"`
	Exploited   bool      `json:"exploited"`
	FoundAt     time.Time `json:"found_at"`
}

// EndpointRecord represents an endpoint record
type EndpointRecord struct {
	ID         int64  `json:"id"`
	ScanID     int64  `json:"scan_id"`
	URL        string `json:"url"`
	Method     string `json:"method"`
	StatusCode int    `json:"status_code"`
	Size       int    `json:"size"`
	Type       string `json:"type"`
	Protected  bool   `json:"protected"`
	Accessible bool   `json:"accessible"`
}

// UserRecord represents a user record
type UserRecord struct {
	ID       int64  `json:"id"`
	ScanID   int64  `json:"scan_id"`
	UserID   string `json:"user_id"`
	Name     string `json:"name"`
	Slug     string `json:"slug"`
	Email    string `json:"email"`
	Role     string `json:"role"`
	Status   string `json:"status"`
	Location string `json:"location"`
	Website  string `json:"website"`
	Bio      string `json:"bio"`
}

// ThemeRecord represents a theme record
type ThemeRecord struct {
	ID          int64   `json:"id"`
	ScanID      int64   `json:"scan_id"`
	Name        string  `json:"name"`
	Version     string  `json:"version"`
	Author      string  `json:"author"`
	Description string  `json:"description"`
	Active      bool    `json:"active"`
	Custom      bool    `json:"custom"`
	Vulnerable  bool    `json:"vulnerable"`
	RiskScore   float64 `json:"risk_score"`
	FilesJSON   string  `json:"files_json"`
}

// ScanStatistics represents scan statistics
type ScanStatistics struct {
	TotalScans          int64   `json:"total_scans"`
	GhostSites          int64   `json:"ghost_sites"`
	VulnerableSites     int64   `json:"vulnerable_sites"`
	TotalVulnerabilities int64   `json:"total_vulnerabilities"`
	AverageConfidence   float64 `json:"average_confidence"`
	MostCommonVersion   string  `json:"most_common_version"`
	MostCommonTheme     string  `json:"most_common_theme"`
	LastScanTime        time.Time `json:"last_scan_time"`
}

// NewDatabaseManager creates a new database manager
func NewDatabaseManager(dbPath string) (*DatabaseManager, error) {
	// Ensure directory exists
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create database directory: %w", err)
	}

	// Open database
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Test connection
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	dm := &DatabaseManager{
		db:   db,
		path: dbPath,
	}

	// Initialize schema
	if err := dm.initSchema(); err != nil {
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	return dm, nil
}

// Close closes the database connection
func (dm *DatabaseManager) Close() error {
	return dm.db.Close()
}

// initSchema initializes the database schema
func (dm *DatabaseManager) initSchema() error {
	schemas := []string{
		// Scans table
		`CREATE TABLE IF NOT EXISTS scans (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			target TEXT NOT NULL,
			timestamp DATETIME NOT NULL,
			scan_duration_ms INTEGER NOT NULL,
			is_ghost BOOLEAN NOT NULL,
			confidence REAL NOT NULL,
			version TEXT,
			theme TEXT,
			results_json TEXT,
			status TEXT NOT NULL DEFAULT 'completed',
			error_message TEXT,
			CREATED_AT DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,

		// Vulnerabilities table
		`CREATE TABLE IF NOT EXISTS vulnerabilities (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			scan_id INTEGER NOT NULL,
			cve TEXT NOT NULL,
			title TEXT NOT NULL,
			description TEXT,
			severity TEXT NOT NULL,
			cvss REAL,
			affected TEXT,
			fixed TEXT,
			exploitable BOOLEAN DEFAULT FALSE,
			exploited BOOLEAN DEFAULT FALSE,
			found_at DATETIME NOT NULL,
			FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
		)`,

		// Endpoints table
		`CREATE TABLE IF NOT EXISTS endpoints (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			scan_id INTEGER NOT NULL,
			url TEXT NOT NULL,
			method TEXT NOT NULL,
			status_code INTEGER NOT NULL,
			size INTEGER,
			type TEXT,
			protected BOOLEAN DEFAULT FALSE,
			accessible BOOLEAN DEFAULT TRUE,
			FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
		)`,

		// Users table
		`CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			scan_id INTEGER NOT NULL,
			user_id TEXT,
			name TEXT,
			slug TEXT,
			email TEXT,
			role TEXT,
			status TEXT,
			location TEXT,
			website TEXT,
			bio TEXT,
			FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
		)`,

		// Themes table
		`CREATE TABLE IF NOT EXISTS themes (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			scan_id INTEGER NOT NULL,
			name TEXT NOT NULL,
			version TEXT,
			author TEXT,
			description TEXT,
			active BOOLEAN DEFAULT FALSE,
			custom BOOLEAN DEFAULT FALSE,
			vulnerable BOOLEAN DEFAULT FALSE,
			risk_score REAL DEFAULT 0.0,
			files_json TEXT,
			FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
		)`,
	}

	// Create indexes
	indexes := []string{
		`CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target)`,
		`CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(timestamp)`,
		`CREATE INDEX IF NOT EXISTS idx_scans_is_ghost ON scans(is_ghost)`,
		`CREATE INDEX IF NOT EXISTS idx_vulnerabilities_scan_id ON vulnerabilities(scan_id)`,
		`CREATE INDEX IF NOT EXISTS idx_vulnerabilities_cve ON vulnerabilities(cve)`,
		`CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity ON vulnerabilities(severity)`,
		`CREATE INDEX IF NOT EXISTS idx_endpoints_scan_id ON endpoints(scan_id)`,
		`CREATE INDEX IF NOT EXISTS idx_users_scan_id ON users(scan_id)`,
		`CREATE INDEX IF NOT EXISTS idx_themes_scan_id ON themes(scan_id)`,
	}

	// Execute schema creation
	for _, schema := range schemas {
		if _, err := dm.db.Exec(schema); err != nil {
			return fmt.Errorf("failed to create table: %w", err)
		}
	}

	// Execute index creation
	for _, index := range indexes {
		if _, err := dm.db.Exec(index); err != nil {
			return fmt.Errorf("failed to create index: %w", err)
		}
	}

	return nil
}

// SaveScanResult saves a complete scan result to the database
func (dm *DatabaseManager) SaveScanResult(scanResult interface{}) (int64, error) {
	// Convert scan result to JSON for storage
	resultsJSON, err := json.Marshal(scanResult)
	if err != nil {
		return 0, fmt.Errorf("failed to marshal scan results: %w", err)
	}

	// Extract basic information (this would need to be adapted based on your actual scan result structure)
	// For now, using placeholder values
	target := "unknown"
	timestamp := time.Now()
	scanDuration := int64(0)
	isGhost := false
	confidence := 0.0
	version := ""
	theme := ""
	status := "completed"

	// Insert scan record
	query := `INSERT INTO scans (target, timestamp, scan_duration_ms, is_ghost, confidence, version, theme, results_json, status)
			  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`

	result, err := dm.db.Exec(query, target, timestamp, scanDuration, isGhost, confidence, version, theme, string(resultsJSON), status)
	if err != nil {
		return 0, fmt.Errorf("failed to insert scan record: %w", err)
	}

	scanID, err := result.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("failed to get scan ID: %w", err)
	}

	return scanID, nil
}

// SaveScanResultDetailed saves a detailed scan result with all components
func (dm *DatabaseManager) SaveScanResultDetailed(target string, scanDuration time.Duration, isGhost bool, confidence float64, version, theme string, vulnerabilities []VulnerabilityRecord, endpoints []EndpointRecord, users []UserRecord, themes []ThemeRecord, resultsJSON string) (int64, error) {
	tx, err := dm.db.Begin()
	if err != nil {
		return 0, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Insert scan record
	scanQuery := `INSERT INTO scans (target, timestamp, scan_duration_ms, is_ghost, confidence, version, theme, results_json, status)
				  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`

	result, err := tx.Exec(scanQuery, target, time.Now(), scanDuration.Milliseconds(), isGhost, confidence, version, theme, resultsJSON, "completed")
	if err != nil {
		return 0, fmt.Errorf("failed to insert scan record: %w", err)
	}

	scanID, err := result.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("failed to get scan ID: %w", err)
	}

	// Insert vulnerabilities
	for _, vuln := range vulnerabilities {
		vulnQuery := `INSERT INTO vulnerabilities (scan_id, cve, title, description, severity, cvss, affected, fixed, exploitable, exploited, found_at)
					  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
		_, err := tx.Exec(vulnQuery, scanID, vuln.CVE, vuln.Title, vuln.Description, vuln.Severity, vuln.CVSS, vuln.Affected, vuln.Fixed, vuln.Exploitable, vuln.Exploited, vuln.FoundAt)
		if err != nil {
			return 0, fmt.Errorf("failed to insert vulnerability: %w", err)
		}
	}

	// Insert endpoints
	for _, endpoint := range endpoints {
		endpointQuery := `INSERT INTO endpoints (scan_id, url, method, status_code, size, type, protected, accessible)
						  VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
		_, err := tx.Exec(endpointQuery, scanID, endpoint.URL, endpoint.Method, endpoint.StatusCode, endpoint.Size, endpoint.Type, endpoint.Protected, endpoint.Accessible)
		if err != nil {
			return 0, fmt.Errorf("failed to insert endpoint: %w", err)
		}
	}

	// Insert users
	for _, user := range users {
		userQuery := `INSERT INTO users (scan_id, user_id, name, slug, email, role, status, location, website, bio)
					  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
		_, err := tx.Exec(userQuery, scanID, user.UserID, user.Name, user.Slug, user.Email, user.Role, user.Status, user.Location, user.Website, user.Bio)
		if err != nil {
			return 0, fmt.Errorf("failed to insert user: %w", err)
		}
	}

	// Insert themes
	for _, themeRec := range themes {
		themeQuery := `INSERT INTO themes (scan_id, name, version, author, description, active, custom, vulnerable, risk_score, files_json)
					   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
		_, err := tx.Exec(themeQuery, scanID, themeRec.Name, themeRec.Version, themeRec.Author, themeRec.Description, themeRec.Active, themeRec.Custom, themeRec.Vulnerable, themeRec.RiskScore, themeRec.FilesJSON)
		if err != nil {
			return 0, fmt.Errorf("failed to insert theme: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("failed to commit transaction: %w", err)
	}

	return scanID, nil
}

// GetScanByID retrieves a scan record by ID
func (dm *DatabaseManager) GetScanByID(id int64) (*ScanRecord, error) {
	query := `SELECT id, target, timestamp, scan_duration_ms, is_ghost, confidence, version, theme, results_json, status, error_message
			  FROM scans WHERE id = ?`

	row := dm.db.QueryRow(query, id)

	var scan ScanRecord
	err := row.Scan(&scan.ID, &scan.Target, &scan.Timestamp, &scan.ScanDuration, &scan.IsGhost, &scan.Confidence, &scan.Version, &scan.Theme, &scan.ResultsJSON, &scan.Status, &scan.ErrorMessage)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("scan not found")
		}
		return nil, fmt.Errorf("failed to get scan: %w", err)
	}

	return &scan, nil
}

// GetScansByTarget retrieves scan records by target
func (dm *DatabaseManager) GetScansByTarget(target string, limit int) ([]*ScanRecord, error) {
	query := `SELECT id, target, timestamp, scan_duration_ms, is_ghost, confidence, version, theme, results_json, status, error_message
			  FROM scans WHERE target = ? ORDER BY timestamp DESC LIMIT ?`

	rows, err := dm.db.Query(query, target, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query scans: %w", err)
	}
	defer rows.Close()

	var scans []*ScanRecord
	for rows.Next() {
		var scan ScanRecord
		err := rows.Scan(&scan.ID, &scan.Target, &scan.Timestamp, &scan.ScanDuration, &scan.IsGhost, &scan.Confidence, &scan.Version, &scan.Theme, &scan.ResultsJSON, &scan.Status, &scan.ErrorMessage)
		if err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}
		scans = append(scans, &scan)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("row iteration error: %w", err)
	}

	return scans, nil
}

// GetRecentScans retrieves recent scan records
func (dm *DatabaseManager) GetRecentScans(limit int) ([]*ScanRecord, error) {
	query := `SELECT id, target, timestamp, scan_duration_ms, is_ghost, confidence, version, theme, results_json, status, error_message
			  FROM scans ORDER BY timestamp DESC LIMIT ?`

	rows, err := dm.db.Query(query, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query recent scans: %w", err)
	}
	defer rows.Close()

	var scans []*ScanRecord
	for rows.Next() {
		var scan ScanRecord
		err := rows.Scan(&scan.ID, &scan.Target, &scan.Timestamp, &scan.ScanDuration, &scan.IsGhost, &scan.Confidence, &scan.Version, &scan.Theme, &scan.ResultsJSON, &scan.Status, &scan.ErrorMessage)
		if err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}
		scans = append(scans, &scan)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("row iteration error: %w", err)
	}

	return scans, nil
}

// GetVulnerabilitiesByScanID retrieves vulnerabilities for a scan
func (dm *DatabaseManager) GetVulnerabilitiesByScanID(scanID int64) ([]*VulnerabilityRecord, error) {
	query := `SELECT id, scan_id, cve, title, description, severity, cvss, affected, fixed, exploitable, exploited, found_at
			  FROM vulnerabilities WHERE scan_id = ? ORDER BY cvss DESC`

	rows, err := dm.db.Query(query, scanID)
	if err != nil {
		return nil, fmt.Errorf("failed to query vulnerabilities: %w", err)
	}
	defer rows.Close()

	var vulnerabilities []*VulnerabilityRecord
	for rows.Next() {
		var vuln VulnerabilityRecord
		err := rows.Scan(&vuln.ID, &vuln.ScanID, &vuln.CVE, &vuln.Title, &vuln.Description, &vuln.Severity, &vuln.CVSS, &vuln.Affected, &vuln.Fixed, &vuln.Exploitable, &vuln.Exploited, &vuln.FoundAt)
		if err != nil {
			return nil, fmt.Errorf("failed to scan vulnerability row: %w", err)
		}
		vulnerabilities = append(vulnerabilities, &vuln)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("vulnerability row iteration error: %w", err)
	}

	return vulnerabilities, nil
}

// GetEndpointsByScanID retrieves endpoints for a scan
func (dm *DatabaseManager) GetEndpointsByScanID(scanID int64) ([]*EndpointRecord, error) {
	query := `SELECT id, scan_id, url, method, status_code, size, type, protected, accessible
			  FROM endpoints WHERE scan_id = ? ORDER BY url`

	rows, err := dm.db.Query(query, scanID)
	if err != nil {
		return nil, fmt.Errorf("failed to query endpoints: %w", err)
	}
	defer rows.Close()

	var endpoints []*EndpointRecord
	for rows.Next() {
		var endpoint EndpointRecord
		err := rows.Scan(&endpoint.ID, &endpoint.ScanID, &endpoint.URL, &endpoint.Method, &endpoint.StatusCode, &endpoint.Size, &endpoint.Type, &endpoint.Protected, &endpoint.Accessible)
		if err != nil {
			return nil, fmt.Errorf("failed to scan endpoint row: %w", err)
		}
		endpoints = append(endpoints, &endpoint)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("endpoint row iteration error: %w", err)
	}

	return endpoints, nil
}

// GetUsersByScanID retrieves users for a scan
func (dm *DatabaseManager) GetUsersByScanID(scanID int64) ([]*UserRecord, error) {
	query := `SELECT id, scan_id, user_id, name, slug, email, role, status, location, website, bio
			  FROM users WHERE scan_id = ? ORDER BY name`

	rows, err := dm.db.Query(query, scanID)
	if err != nil {
		return nil, fmt.Errorf("failed to query users: %w", err)
	}
	defer rows.Close()

	var users []*UserRecord
	for rows.Next() {
		var user UserRecord
		err := rows.Scan(&user.ID, &user.ScanID, &user.UserID, &user.Name, &user.Slug, &user.Email, &user.Role, &user.Status, &user.Location, &user.Website, &user.Bio)
		if err != nil {
			return nil, fmt.Errorf("failed to scan user row: %w", err)
		}
		users = append(users, &user)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("user row iteration error: %w", err)
	}

	return users, nil
}

// GetThemesByScanID retrieves themes for a scan
func (dm *DatabaseManager) GetThemesByScanID(scanID int64) ([]*ThemeRecord, error) {
	query := `SELECT id, scan_id, name, version, author, description, active, custom, vulnerable, risk_score, files_json
			  FROM themes WHERE scan_id = ? ORDER BY name`

	rows, err := dm.db.Query(query, scanID)
	if err != nil {
		return nil, fmt.Errorf("failed to query themes: %w", err)
	}
	defer rows.Close()

	var themes []*ThemeRecord
	for rows.Next() {
		var theme ThemeRecord
		err := rows.Scan(&theme.ID, &theme.ScanID, &theme.Name, &theme.Version, &theme.Author, &theme.Description, &theme.Active, &theme.Custom, &theme.Vulnerable, &theme.RiskScore, &theme.FilesJSON)
		if err != nil {
			return nil, fmt.Errorf("failed to scan theme row: %w", err)
		}
		themes = append(themes, &theme)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("theme row iteration error: %w", err)
	}

	return themes, nil
}

// GetStatistics retrieves scan statistics
func (dm *DatabaseManager) GetStatistics() (*ScanStatistics, error) {
	stats := &ScanStatistics{}

	// Total scans
	err := dm.db.QueryRow("SELECT COUNT(*) FROM scans").Scan(&stats.TotalScans)
	if err != nil {
		return nil, fmt.Errorf("failed to get total scans: %w", err)
	}

	// Ghost sites
	err = dm.db.QueryRow("SELECT COUNT(*) FROM scans WHERE is_ghost = 1").Scan(&stats.GhostSites)
	if err != nil {
		return nil, fmt.Errorf("failed to get ghost sites count: %w", err)
	}

	// Vulnerable sites
	err = dm.db.QueryRow("SELECT COUNT(DISTINCT scan_id) FROM vulnerabilities").Scan(&stats.VulnerableSites)
	if err != nil {
		return nil, fmt.Errorf("failed to get vulnerable sites count: %w", err)
	}

	// Total vulnerabilities
	err = dm.db.QueryRow("SELECT COUNT(*) FROM vulnerabilities").Scan(&stats.TotalVulnerabilities)
	if err != nil {
		return nil, fmt.Errorf("failed to get total vulnerabilities: %w", err)
	}

	// Average confidence
	err = dm.db.QueryRow("SELECT AVG(confidence) FROM scans WHERE is_ghost = 1").Scan(&stats.AverageConfidence)
	if err != nil {
		stats.AverageConfidence = 0
	}

	// Most common version
	err = dm.db.QueryRow("SELECT version FROM scans WHERE version != '' GROUP BY version ORDER BY COUNT(*) DESC LIMIT 1").Scan(&stats.MostCommonVersion)
	if err != nil {
		stats.MostCommonVersion = "Unknown"
	}

	// Most common theme
	err = dm.db.QueryRow("SELECT theme FROM scans WHERE theme != '' GROUP BY theme ORDER BY COUNT(*) DESC LIMIT 1").Scan(&stats.MostCommonTheme)
	if err != nil {
		stats.MostCommonTheme = "Unknown"
	}

	// Last scan time
	err = dm.db.QueryRow("SELECT MAX(timestamp) FROM scans").Scan(&stats.LastScanTime)
	if err != nil {
		stats.LastScanTime = time.Time{}
	}

	return stats, nil
}

// DeleteScan deletes a scan and all related records
func (dm *DatabaseManager) DeleteScan(scanID int64) error {
	// Due to foreign key constraints with CASCADE, deleting the scan will delete all related records
	query := "DELETE FROM scans WHERE id = ?"
	result, err := dm.db.Exec(query, scanID)
	if err != nil {
		return fmt.Errorf("failed to delete scan: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("scan not found")
	}

	return nil
}

// DeleteOldScans deletes scans older than the specified duration
func (dm *DatabaseManager) DeleteOldScans(olderThan time.Duration) (int64, error) {
	cutoff := time.Now().Add(-olderThan)
	query := "DELETE FROM scans WHERE timestamp < ?"
	result, err := dm.db.Exec(query, cutoff)
	if err != nil {
		return 0, fmt.Errorf("failed to delete old scans: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to get rows affected: %w", err)
	}

	return rowsAffected, nil
}

// ExportScans exports scan data to JSON
func (dm *DatabaseManager) ExportScans(target string, limit int) ([]byte, error) {
	var scans []*ScanRecord
	var err error

	if target != "" {
		scans, err = dm.GetScansByTarget(target, limit)
	} else {
		scans, err = dm.GetRecentScans(limit)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to get scans for export: %w", err)
	}

	// For each scan, get related data
	type ExportScan struct {
		*ScanRecord
		Vulnerabilities []*VulnerabilityRecord `json:"vulnerabilities"`
		Endpoints       []*EndpointRecord      `json:"endpoints"`
		Users           []*UserRecord          `json:"users"`
		Themes          []*ThemeRecord         `json:"themes"`
	}

	var exportData []ExportScan
	for _, scan := range scans {
		exportScan := ExportScan{ScanRecord: scan}

		// Get vulnerabilities
		exportScan.Vulnerabilities, _ = dm.GetVulnerabilitiesByScanID(scan.ID)

		// Get endpoints
		exportScan.Endpoints, _ = dm.GetEndpointsByScanID(scan.ID)

		// Get users
		exportScan.Users, _ = dm.GetUsersByScanID(scan.ID)

		// Get themes
		exportScan.Themes, _ = dm.GetThemesByScanID(scan.ID)

		exportData = append(exportData, exportScan)
	}

	return json.MarshalIndent(exportData, "", "  ")
}

// GetDatabasePath returns the database file path
func (dm *DatabaseManager) GetDatabasePath() string {
	return dm.path
}

// GetDatabaseSize returns the database file size in bytes
func (dm *DatabaseManager) GetDatabaseSize() (int64, error) {
	info, err := os.Stat(dm.path)
	if err != nil {
		return 0, fmt.Errorf("failed to get database file info: %w", err)
	}
	return info.Size(), nil
}

// Vacuum optimizes the database
func (dm *DatabaseManager) Vacuum() error {
	_, err := dm.db.Exec("VACUUM")
	if err != nil {
		return fmt.Errorf("failed to vacuum database: %w", err)
	}
	return nil
}