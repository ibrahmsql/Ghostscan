package monitoring

import (
	"context"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics holds all Prometheus metrics for GhostScan
type Metrics struct {
	// Scan metrics
	ScansTotal        *prometheus.CounterVec
	ScanDuration      *prometheus.HistogramVec
	ScanErrors        *prometheus.CounterVec
	ActiveScans       prometheus.Gauge
	GhostDetections   *prometheus.CounterVec

	// Target metrics
	TargetsScanned    prometheus.Counter
	VersionsDetected  *prometheus.CounterVec
	ThemesDetected    *prometheus.CounterVec

	// Vulnerability metrics
	VulnerabilitiesFound *prometheus.CounterVec
	CVEsDetected         *prometheus.CounterVec
	MisconfigsFound      *prometheus.CounterVec

	// Performance metrics
	RequestsTotal     *prometheus.CounterVec
	RequestDuration   *prometheus.HistogramVec
	ResponseSize      *prometheus.HistogramVec
	ConcurrentScans   prometheus.Gauge

	// System metrics
	MemoryUsage       prometheus.Gauge
	CPUUsage          prometheus.Gauge
	Goroutines        prometheus.Gauge
	Uptime            prometheus.Gauge

	// Worker pool metrics
	WorkerPoolSize    prometheus.Gauge
	QueuedTasks       prometheus.Gauge
	CompletedTasks    prometheus.Counter
	FailedTasks       prometheus.Counter

	// Cache metrics
	CacheHits         prometheus.Counter
	CacheMisses       prometheus.Counter
	CacheSize         prometheus.Gauge
	CacheEvictions    prometheus.Counter

	startTime time.Time
	registry  *prometheus.Registry
	mu        sync.RWMutex
}

// NewMetrics creates a new Metrics instance
func NewMetrics() *Metrics {
	m := &Metrics{
		startTime: time.Now(),
		registry:  prometheus.NewRegistry(),
	}

	m.initMetrics()
	m.registerMetrics()

	return m
}

// initMetrics initializes all Prometheus metrics
func (m *Metrics) initMetrics() {
	// Scan metrics
	m.ScansTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ghostscan_scans_total",
			Help: "Total number of scans performed",
		},
		[]string{"status", "target_type"},
	)

	m.ScanDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "ghostscan_scan_duration_seconds",
			Help:    "Duration of scans in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"target_type", "scan_type"},
	)

	m.ScanErrors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ghostscan_scan_errors_total",
			Help: "Total number of scan errors",
		},
		[]string{"error_type", "target"},
	)

	m.ActiveScans = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "ghostscan_active_scans",
			Help: "Number of currently active scans",
		},
	)

	m.GhostDetections = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ghostscan_ghost_detections_total",
			Help: "Total number of Ghost CMS detections",
		},
		[]string{"version", "confidence"},
	)

	// Target metrics
	m.TargetsScanned = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "ghostscan_targets_scanned_total",
			Help: "Total number of targets scanned",
		},
	)

	m.VersionsDetected = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ghostscan_versions_detected_total",
			Help: "Total number of Ghost versions detected",
		},
		[]string{"version", "source"},
	)

	m.ThemesDetected = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ghostscan_themes_detected_total",
			Help: "Total number of themes detected",
		},
		[]string{"theme", "version"},
	)

	// Vulnerability metrics
	m.VulnerabilitiesFound = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ghostscan_vulnerabilities_found_total",
			Help: "Total number of vulnerabilities found",
		},
		[]string{"severity", "type"},
	)

	m.CVEsDetected = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ghostscan_cves_detected_total",
			Help: "Total number of CVEs detected",
		},
		[]string{"cve", "severity"},
	)

	m.MisconfigsFound = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ghostscan_misconfigs_found_total",
			Help: "Total number of misconfigurations found",
		},
		[]string{"type", "severity"},
	)

	// Performance metrics
	m.RequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ghostscan_http_requests_total",
			Help: "Total number of HTTP requests made",
		},
		[]string{"method", "status_code", "endpoint"},
	)

	m.RequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "ghostscan_http_request_duration_seconds",
			Help:    "Duration of HTTP requests in seconds",
			Buckets: []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10},
		},
		[]string{"method", "endpoint"},
	)

	m.ResponseSize = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "ghostscan_http_response_size_bytes",
			Help:    "Size of HTTP responses in bytes",
			Buckets: prometheus.ExponentialBuckets(100, 10, 8),
		},
		[]string{"method", "endpoint"},
	)

	m.ConcurrentScans = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "ghostscan_concurrent_scans",
			Help: "Number of concurrent scans running",
		},
	)

	// System metrics
	m.MemoryUsage = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "ghostscan_memory_usage_bytes",
			Help: "Current memory usage in bytes",
		},
	)

	m.CPUUsage = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "ghostscan_cpu_usage_percent",
			Help: "Current CPU usage percentage",
		},
	)

	m.Goroutines = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "ghostscan_goroutines",
			Help: "Number of goroutines",
		},
	)

	m.Uptime = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "ghostscan_uptime_seconds",
			Help: "Uptime in seconds",
		},
	)

	// Worker pool metrics
	m.WorkerPoolSize = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "ghostscan_worker_pool_size",
			Help: "Size of the worker pool",
		},
	)

	m.QueuedTasks = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "ghostscan_queued_tasks",
			Help: "Number of queued tasks",
		},
	)

	m.CompletedTasks = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "ghostscan_completed_tasks_total",
			Help: "Total number of completed tasks",
		},
	)

	m.FailedTasks = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "ghostscan_failed_tasks_total",
			Help: "Total number of failed tasks",
		},
	)

	// Cache metrics
	m.CacheHits = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "ghostscan_cache_hits_total",
			Help: "Total number of cache hits",
		},
	)

	m.CacheMisses = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "ghostscan_cache_misses_total",
			Help: "Total number of cache misses",
		},
	)

	m.CacheSize = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "ghostscan_cache_size",
			Help: "Current cache size",
		},
	)

	m.CacheEvictions = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "ghostscan_cache_evictions_total",
			Help: "Total number of cache evictions",
		},
	)
}

// registerMetrics registers all metrics with the registry
func (m *Metrics) registerMetrics() {
	m.registry.MustRegister(
		m.ScansTotal,
		m.ScanDuration,
		m.ScanErrors,
		m.ActiveScans,
		m.GhostDetections,
		m.TargetsScanned,
		m.VersionsDetected,
		m.ThemesDetected,
		m.VulnerabilitiesFound,
		m.CVEsDetected,
		m.MisconfigsFound,
		m.RequestsTotal,
		m.RequestDuration,
		m.ResponseSize,
		m.ConcurrentScans,
		m.MemoryUsage,
		m.CPUUsage,
		m.Goroutines,
		m.Uptime,
		m.WorkerPoolSize,
		m.QueuedTasks,
		m.CompletedTasks,
		m.FailedTasks,
		m.CacheHits,
		m.CacheMisses,
		m.CacheSize,
		m.CacheEvictions,
	)
}

// RecordScan records a scan completion
func (m *Metrics) RecordScan(status, targetType string, duration time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.ScansTotal.WithLabelValues(status, targetType).Inc()
	m.ScanDuration.WithLabelValues(targetType, "full").Observe(duration.Seconds())
	m.TargetsScanned.Inc()
}

// RecordScanError records a scan error
func (m *Metrics) RecordScanError(errorType, target string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.ScanErrors.WithLabelValues(errorType, target).Inc()
}

// RecordGhostDetection records a Ghost CMS detection
func (m *Metrics) RecordGhostDetection(version string, confidence int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	confidenceStr := strconv.Itoa(confidence)
	m.GhostDetections.WithLabelValues(version, confidenceStr).Inc()
}

// RecordVersionDetection records a version detection
func (m *Metrics) RecordVersionDetection(version, source string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.VersionsDetected.WithLabelValues(version, source).Inc()
}

// RecordThemeDetection records a theme detection
func (m *Metrics) RecordThemeDetection(theme, version string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.ThemesDetected.WithLabelValues(theme, version).Inc()
}

// RecordVulnerability records a vulnerability finding
func (m *Metrics) RecordVulnerability(severity, vulnType string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.VulnerabilitiesFound.WithLabelValues(severity, vulnType).Inc()
}

// RecordCVE records a CVE detection
func (m *Metrics) RecordCVE(cve, severity string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.CVEsDetected.WithLabelValues(cve, severity).Inc()
}

// RecordMisconfiguration records a misconfiguration finding
func (m *Metrics) RecordMisconfiguration(configType, severity string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.MisconfigsFound.WithLabelValues(configType, severity).Inc()
}

// RecordHTTPRequest records an HTTP request
func (m *Metrics) RecordHTTPRequest(method, statusCode, endpoint string, duration time.Duration, responseSize int64) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.RequestsTotal.WithLabelValues(method, statusCode, endpoint).Inc()
	m.RequestDuration.WithLabelValues(method, endpoint).Observe(duration.Seconds())
	m.ResponseSize.WithLabelValues(method, endpoint).Observe(float64(responseSize))
}

// SetActiveScans sets the number of active scans
func (m *Metrics) SetActiveScans(count int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.ActiveScans.Set(float64(count))
}

// SetConcurrentScans sets the number of concurrent scans
func (m *Metrics) SetConcurrentScans(count int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.ConcurrentScans.Set(float64(count))
}

// UpdateSystemMetrics updates system-level metrics
func (m *Metrics) UpdateSystemMetrics(memoryUsage, cpuUsage float64, goroutines int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.MemoryUsage.Set(memoryUsage)
	m.CPUUsage.Set(cpuUsage)
	m.Goroutines.Set(float64(goroutines))
	m.Uptime.Set(time.Since(m.startTime).Seconds())
}

// UpdateWorkerPoolMetrics updates worker pool metrics
func (m *Metrics) UpdateWorkerPoolMetrics(poolSize, queuedTasks int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.WorkerPoolSize.Set(float64(poolSize))
	m.QueuedTasks.Set(float64(queuedTasks))
}

// RecordTaskCompletion records a task completion
func (m *Metrics) RecordTaskCompletion(success bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if success {
		m.CompletedTasks.Inc()
	} else {
		m.FailedTasks.Inc()
	}
}

// UpdateCacheMetrics updates cache metrics
func (m *Metrics) UpdateCacheMetrics(hits, misses, size, evictions int64) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.CacheHits.Add(float64(hits))
	m.CacheMisses.Add(float64(misses))
	m.CacheSize.Set(float64(size))
	m.CacheEvictions.Add(float64(evictions))
}

// GetRegistry returns the Prometheus registry
func (m *Metrics) GetRegistry() *prometheus.Registry {
	return m.registry
}

// Handler returns an HTTP handler for metrics endpoint
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{
		EnableOpenMetrics: true,
	})
}

// StartMetricsServer starts the metrics HTTP server
func (m *Metrics) StartMetricsServer(ctx context.Context, addr string) error {
	mux := http.NewServeMux()
	mux.Handle("/metrics", m.Handler())
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	server := &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	go func() {
		<-ctx.Done()
		server.Shutdown(context.Background())
	}()

	return server.ListenAndServe()
}

// Reset resets all metrics (useful for testing)
func (m *Metrics) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Create new registry and re-register metrics
	m.registry = prometheus.NewRegistry()
	m.registerMetrics()
	m.startTime = time.Now()
}