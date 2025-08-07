package performance

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// PerformanceMonitor monitors application performance
type PerformanceMonitor struct {
	metrics     *PerformanceMetrics
	sampler     *ResourceSampler
	profiler    *Profiler
	alerts      *AlertManager
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	interval    time.Duration
	enabled     bool
	mu          sync.RWMutex
}

// PerformanceMetrics holds performance-related metrics
type PerformanceMetrics struct {
	// CPU metrics
	CPUUsage       prometheus.Gauge
	CPUCores       prometheus.Gauge
	Goroutines     prometheus.Gauge

	// Memory metrics
	MemoryUsage    prometheus.Gauge
	MemoryAlloc    prometheus.Gauge
	MemoryTotal    prometheus.Gauge
	MemorySystem   prometheus.Gauge
	GCPauses       prometheus.Histogram
	GCRuns         prometheus.Counter

	// Request metrics
	RequestDuration *prometheus.HistogramVec
	RequestCount    *prometheus.CounterVec
	RequestErrors   *prometheus.CounterVec
	ActiveRequests  prometheus.Gauge

	// Scanner metrics
	ScanDuration    *prometheus.HistogramVec
	ScanCount       *prometheus.CounterVec
	ScanErrors      *prometheus.CounterVec
	ActivScans      prometheus.Gauge

	// Database metrics
	DBConnections   prometheus.Gauge
	DBQueries       *prometheus.CounterVec
	DBQueryDuration *prometheus.HistogramVec

	// Network metrics
	NetworkRequests *prometheus.CounterVec
	NetworkLatency  *prometheus.HistogramVec
	NetworkErrors   *prometheus.CounterVec

	// Cache metrics
	CacheHits       *prometheus.CounterVec
	CacheMisses     *prometheus.CounterVec
	CacheSize       prometheus.Gauge
}

// ResourceSampler samples system resources
type ResourceSampler struct {
	lastCPUTime    time.Time
	memStats       runtime.MemStats
	mu             sync.Mutex
}

// Profiler handles performance profiling
type Profiler struct {
	profileDir     string
}

// AlertManager manages performance alerts
type AlertManager struct {
	alerts         []Alert
	thresholds     map[string]float64
	notifiers      []Notifier
	mu             sync.RWMutex
}

// Alert represents a performance alert
type Alert struct {
	ID          string
	Type        AlertType
	Severity    AlertSeverity
	Message     string
	Timestamp   time.Time
	Value       float64
	Threshold   float64
	Resolved    bool
	ResolvedAt  time.Time
}

// AlertType represents the type of alert
type AlertType string

const (
	AlertTypeCPU        AlertType = "cpu"
	AlertTypeMemory     AlertType = "memory"
	AlertTypeGoroutines AlertType = "goroutines"
	AlertTypeLatency    AlertType = "latency"
	AlertTypeErrors     AlertType = "errors"
	AlertTypeDisk       AlertType = "disk"
	AlertTypeNetwork    AlertType = "network"
)

// AlertSeverity represents the severity of an alert
type AlertSeverity string

const (
	AlertSeverityLow      AlertSeverity = "low"
	AlertSeverityMedium   AlertSeverity = "medium"
	AlertSeverityHigh     AlertSeverity = "high"
	AlertSeverityCritical AlertSeverity = "critical"
)

// Notifier sends alert notifications
type Notifier interface {
	Notify(alert Alert) error
}

// NewPerformanceMonitor creates a new performance monitor
func NewPerformanceMonitor(interval time.Duration) *PerformanceMonitor {
	ctx, cancel := context.WithCancel(context.Background())

	monitor := &PerformanceMonitor{
		metrics:  newPerformanceMetrics(),
		sampler:  newResourceSampler(),
		profiler: newProfiler(),
		alerts:   newAlertManager(),
		ctx:      ctx,
		cancel:   cancel,
		interval: interval,
		enabled:  true,
	}

	return monitor
}

// newPerformanceMetrics creates performance metrics
func newPerformanceMetrics() *PerformanceMetrics {
	return &PerformanceMetrics{
		// CPU metrics
		CPUUsage: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "ghostscan_cpu_usage_percent",
			Help: "Current CPU usage percentage",
		}),
		CPUCores: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "ghostscan_cpu_cores",
			Help: "Number of CPU cores",
		}),
		Goroutines: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "ghostscan_goroutines",
			Help: "Number of goroutines",
		}),

		// Memory metrics
		MemoryUsage: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "ghostscan_memory_usage_bytes",
			Help: "Current memory usage in bytes",
		}),
		MemoryAlloc: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "ghostscan_memory_alloc_bytes",
			Help: "Allocated memory in bytes",
		}),
		MemoryTotal: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "ghostscan_memory_total_bytes",
			Help: "Total memory in bytes",
		}),
		MemorySystem: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "ghostscan_memory_system_bytes",
			Help: "System memory in bytes",
		}),
		GCPauses: promauto.NewHistogram(prometheus.HistogramOpts{
			Name:    "ghostscan_gc_pause_duration_seconds",
			Help:    "GC pause duration in seconds",
			Buckets: prometheus.DefBuckets,
		}),
		GCRuns: promauto.NewCounter(prometheus.CounterOpts{
			Name: "ghostscan_gc_runs_total",
			Help: "Total number of GC runs",
		}),

		// Request metrics
		RequestDuration: promauto.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "ghostscan_request_duration_seconds",
			Help:    "Request duration in seconds",
			Buckets: prometheus.DefBuckets,
		}, []string{"method", "endpoint", "status"}),
		RequestCount: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "ghostscan_requests_total",
			Help: "Total number of requests",
		}, []string{"method", "endpoint", "status"}),
		RequestErrors: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "ghostscan_request_errors_total",
			Help: "Total number of request errors",
		}, []string{"method", "endpoint", "error_type"}),
		ActiveRequests: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "ghostscan_active_requests",
			Help: "Number of active requests",
		}),

		// Scanner metrics
		ScanDuration: promauto.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "ghostscan_scan_duration_seconds",
			Help:    "Scan duration in seconds",
			Buckets: []float64{1, 5, 10, 30, 60, 300, 600, 1800, 3600},
		}, []string{"scan_type", "target"}),
		ScanCount: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "ghostscan_scans_total",
			Help: "Total number of scans",
		}, []string{"scan_type", "target", "status"}),
		ScanErrors: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "ghostscan_scan_errors_total",
			Help: "Total number of scan errors",
		}, []string{"scan_type", "error_type"}),
		ActivScans: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "ghostscan_active_scans",
			Help: "Number of active scans",
		}),

		// Database metrics
		DBConnections: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "ghostscan_db_connections",
			Help: "Number of database connections",
		}),
		DBQueries: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "ghostscan_db_queries_total",
			Help: "Total number of database queries",
		}, []string{"query_type", "status"}),
		DBQueryDuration: promauto.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "ghostscan_db_query_duration_seconds",
			Help:    "Database query duration in seconds",
			Buckets: prometheus.DefBuckets,
		}, []string{"query_type"}),

		// Network metrics
		NetworkRequests: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "ghostscan_network_requests_total",
			Help: "Total number of network requests",
		}, []string{"protocol", "status"}),
		NetworkLatency: promauto.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "ghostscan_network_latency_seconds",
			Help:    "Network latency in seconds",
			Buckets: []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 5},
		}, []string{"protocol", "endpoint"}),
		NetworkErrors: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "ghostscan_network_errors_total",
			Help: "Total number of network errors",
		}, []string{"protocol", "error_type"}),

		// Cache metrics
		CacheHits: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "ghostscan_cache_hits_total",
			Help: "Total number of cache hits",
		}, []string{"cache_type"}),
		CacheMisses: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "ghostscan_cache_misses_total",
			Help: "Total number of cache misses",
		}, []string{"cache_type"}),
		CacheSize: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "ghostscan_cache_size_bytes",
			Help: "Cache size in bytes",
		}),
	}
}

// newResourceSampler creates a new resource sampler
func newResourceSampler() *ResourceSampler {
	return &ResourceSampler{
		lastCPUTime: time.Now(),
	}
}

// newProfiler creates a new profiler
func newProfiler() *Profiler {
	return &Profiler{
		profileDir: "/tmp/ghostscan-profiles",
	}
}

// newAlertManager creates a new alert manager
func newAlertManager() *AlertManager {
	return &AlertManager{
		thresholds: map[string]float64{
			"cpu_usage":    80.0,  // 80%
			"memory_usage": 85.0,  // 85%
			"goroutines":   10000, // 10k goroutines
			"latency":      5.0,   // 5 seconds
			"error_rate":   10.0,  // 10%
		},
	}
}

// Start starts the performance monitor
func (pm *PerformanceMonitor) Start() {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if !pm.enabled {
		return
	}

	// Start monitoring goroutine
	pm.wg.Add(1)
	go pm.monitor()

	// Start alert checking goroutine
	pm.wg.Add(1)
	go pm.checkAlerts()
}

// Stop stops the performance monitor
func (pm *PerformanceMonitor) Stop() {
	pm.cancel()
	pm.wg.Wait()
}

// monitor runs the main monitoring loop
func (pm *PerformanceMonitor) monitor() {
	defer pm.wg.Done()

	ticker := time.NewTicker(pm.interval)
	defer ticker.Stop()

	for {
		select {
		case <-pm.ctx.Done():
			return
		case <-ticker.C:
			pm.collectMetrics()
		}
	}
}

// collectMetrics collects performance metrics
func (pm *PerformanceMonitor) collectMetrics() {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	if !pm.enabled {
		return
	}

	// Collect CPU metrics
	pm.collectCPUMetrics()

	// Collect memory metrics
	pm.collectMemoryMetrics()

	// Collect goroutine metrics
	pm.collectGoroutineMetrics()
}

// collectCPUMetrics collects CPU-related metrics
func (pm *PerformanceMonitor) collectCPUMetrics() {
	// Set CPU cores
	pm.metrics.CPUCores.Set(float64(runtime.NumCPU()))

	// Note: CPU usage calculation would require platform-specific code
	// For now, we'll use a placeholder
	pm.metrics.CPUUsage.Set(0) // Placeholder
}

// collectMemoryMetrics collects memory-related metrics
func (pm *PerformanceMonitor) collectMemoryMetrics() {
	pm.sampler.mu.Lock()
	defer pm.sampler.mu.Unlock()

	runtime.ReadMemStats(&pm.sampler.memStats)

	pm.metrics.MemoryAlloc.Set(float64(pm.sampler.memStats.Alloc))
	pm.metrics.MemoryTotal.Set(float64(pm.sampler.memStats.TotalAlloc))
	pm.metrics.MemorySystem.Set(float64(pm.sampler.memStats.Sys))

	// GC metrics
	pm.metrics.GCRuns.Add(float64(pm.sampler.memStats.NumGC))
	if len(pm.sampler.memStats.PauseNs) > 0 {
		lastPause := pm.sampler.memStats.PauseNs[(pm.sampler.memStats.NumGC+255)%256]
		pm.metrics.GCPauses.Observe(float64(lastPause) / 1e9) // Convert to seconds
	}
}

// collectGoroutineMetrics collects goroutine-related metrics
func (pm *PerformanceMonitor) collectGoroutineMetrics() {
	pm.metrics.Goroutines.Set(float64(runtime.NumGoroutine()))
}

// checkAlerts checks for performance alerts
func (pm *PerformanceMonitor) checkAlerts() {
	defer pm.wg.Done()

	ticker := time.NewTicker(pm.interval * 2) // Check alerts less frequently
	defer ticker.Stop()

	for {
		select {
		case <-pm.ctx.Done():
			return
		case <-ticker.C:
			pm.evaluateAlerts()
		}
	}
}

// evaluateAlerts evaluates performance thresholds and triggers alerts
func (pm *PerformanceMonitor) evaluateAlerts() {
	pm.alerts.mu.Lock()
	defer pm.alerts.mu.Unlock()

	// Check goroutine count
	goroutineCount := float64(runtime.NumGoroutine())
	if threshold, exists := pm.alerts.thresholds["goroutines"]; exists {
		if goroutineCount > threshold {
			alert := Alert{
				ID:        fmt.Sprintf("goroutines-%d", time.Now().Unix()),
				Type:      AlertTypeGoroutines,
				Severity:  pm.getSeverity(goroutineCount, threshold),
				Message:   fmt.Sprintf("High goroutine count: %.0f (threshold: %.0f)", goroutineCount, threshold),
				Timestamp: time.Now(),
				Value:     goroutineCount,
				Threshold: threshold,
			}
			pm.triggerAlert(alert)
		}
	}

	// Check memory usage
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	memoryUsage := float64(memStats.Alloc)
	if threshold, exists := pm.alerts.thresholds["memory_usage"]; exists {
		memoryPercent := (memoryUsage / float64(memStats.Sys)) * 100
		if memoryPercent > threshold {
			alert := Alert{
				ID:        fmt.Sprintf("memory-%d", time.Now().Unix()),
				Type:      AlertTypeMemory,
				Severity:  pm.getSeverity(memoryPercent, threshold),
				Message:   fmt.Sprintf("High memory usage: %.2f%% (threshold: %.2f%%)", memoryPercent, threshold),
				Timestamp: time.Now(),
				Value:     memoryPercent,
				Threshold: threshold,
			}
			pm.triggerAlert(alert)
		}
	}
}

// getSeverity determines alert severity based on value and threshold
func (pm *PerformanceMonitor) getSeverity(value, threshold float64) AlertSeverity {
	ratio := value / threshold
	switch {
	case ratio >= 2.0:
		return AlertSeverityCritical
	case ratio >= 1.5:
		return AlertSeverityHigh
	case ratio >= 1.2:
		return AlertSeverityMedium
	default:
		return AlertSeverityLow
	}
}

// triggerAlert triggers an alert
func (pm *PerformanceMonitor) triggerAlert(alert Alert) {
	// Check if alert already exists
	for i, existingAlert := range pm.alerts.alerts {
		if existingAlert.Type == alert.Type && !existingAlert.Resolved {
			// Update existing alert
			pm.alerts.alerts[i] = alert
			return
		}
	}

	// Add new alert
	pm.alerts.alerts = append(pm.alerts.alerts, alert)

	// Notify
	for _, notifier := range pm.alerts.notifiers {
		go func(n Notifier) {
			if err := n.Notify(alert); err != nil {
				// Log error (would need logger)
			}
		}(notifier)
	}
}

// RecordRequest records request metrics
func (pm *PerformanceMonitor) RecordRequest(method, endpoint, status string, duration time.Duration) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	if !pm.enabled {
		return
	}

	pm.metrics.RequestDuration.WithLabelValues(method, endpoint, status).Observe(duration.Seconds())
	pm.metrics.RequestCount.WithLabelValues(method, endpoint, status).Inc()
}

// RecordRequestError records request error metrics
func (pm *PerformanceMonitor) RecordRequestError(method, endpoint, errorType string) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	if !pm.enabled {
		return
	}

	pm.metrics.RequestErrors.WithLabelValues(method, endpoint, errorType).Inc()
}

// RecordScan records scan metrics
func (pm *PerformanceMonitor) RecordScan(scanType, target, status string, duration time.Duration) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	if !pm.enabled {
		return
	}

	pm.metrics.ScanDuration.WithLabelValues(scanType, target).Observe(duration.Seconds())
	pm.metrics.ScanCount.WithLabelValues(scanType, target, status).Inc()
}

// RecordScanError records scan error metrics
func (pm *PerformanceMonitor) RecordScanError(scanType, errorType string) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	if !pm.enabled {
		return
	}

	pm.metrics.ScanErrors.WithLabelValues(scanType, errorType).Inc()
}

// RecordDBQuery records database query metrics
func (pm *PerformanceMonitor) RecordDBQuery(queryType, status string, duration time.Duration) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	if !pm.enabled {
		return
	}

	pm.metrics.DBQueryDuration.WithLabelValues(queryType).Observe(duration.Seconds())
	pm.metrics.DBQueries.WithLabelValues(queryType, status).Inc()
}

// RecordNetworkRequest records network request metrics
func (pm *PerformanceMonitor) RecordNetworkRequest(protocol, status string, latency time.Duration) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	if !pm.enabled {
		return
	}

	pm.metrics.NetworkRequests.WithLabelValues(protocol, status).Inc()
	pm.metrics.NetworkLatency.WithLabelValues(protocol, "").Observe(latency.Seconds())
}

// RecordCacheHit records cache hit metrics
func (pm *PerformanceMonitor) RecordCacheHit(cacheType string) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	if !pm.enabled {
		return
	}

	pm.metrics.CacheHits.WithLabelValues(cacheType).Inc()
}

// RecordCacheMiss records cache miss metrics
func (pm *PerformanceMonitor) RecordCacheMiss(cacheType string) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	if !pm.enabled {
		return
	}

	pm.metrics.CacheMisses.WithLabelValues(cacheType).Inc()
}

// SetActiveRequests sets the number of active requests
func (pm *PerformanceMonitor) SetActiveRequests(count int) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	if !pm.enabled {
		return
	}

	pm.metrics.ActiveRequests.Set(float64(count))
}

// SetActiveScans sets the number of active scans
func (pm *PerformanceMonitor) SetActiveScans(count int) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	if !pm.enabled {
		return
	}

	pm.metrics.ActivScans.Set(float64(count))
}

// SetDBConnections sets the number of database connections
func (pm *PerformanceMonitor) SetDBConnections(count int) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	if !pm.enabled {
		return
	}

	pm.metrics.DBConnections.Set(float64(count))
}

// SetCacheSize sets the cache size
func (pm *PerformanceMonitor) SetCacheSize(size int64) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	if !pm.enabled {
		return
	}

	pm.metrics.CacheSize.Set(float64(size))
}

// Enable enables performance monitoring
func (pm *PerformanceMonitor) Enable() {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.enabled = true
}

// Disable disables performance monitoring
func (pm *PerformanceMonitor) Disable() {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.enabled = false
}

// IsEnabled returns whether monitoring is enabled
func (pm *PerformanceMonitor) IsEnabled() bool {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.enabled
}

// GetMetrics returns the performance metrics
func (pm *PerformanceMonitor) GetMetrics() *PerformanceMetrics {
	return pm.metrics
}

// GetAlerts returns current alerts
func (pm *PerformanceMonitor) GetAlerts() []Alert {
	pm.alerts.mu.RLock()
	defer pm.alerts.mu.RUnlock()

	alerts := make([]Alert, len(pm.alerts.alerts))
	copy(alerts, pm.alerts.alerts)
	return alerts
}

// AddNotifier adds an alert notifier
func (pm *PerformanceMonitor) AddNotifier(notifier Notifier) {
	pm.alerts.mu.Lock()
	defer pm.alerts.mu.Unlock()
	pm.alerts.notifiers = append(pm.alerts.notifiers, notifier)
}

// SetThreshold sets an alert threshold
func (pm *PerformanceMonitor) SetThreshold(metric string, threshold float64) {
	pm.alerts.mu.Lock()
	defer pm.alerts.mu.Unlock()
	pm.alerts.thresholds[metric] = threshold
}

// RequestTracker tracks individual requests
type RequestTracker struct {
	monitor   *PerformanceMonitor
	method    string
	endpoint  string
	startTime time.Time
	active    int64
}

// NewRequestTracker creates a new request tracker
func (pm *PerformanceMonitor) NewRequestTracker(method, endpoint string) *RequestTracker {
	tracker := &RequestTracker{
		monitor:   pm,
		method:    method,
		endpoint:  endpoint,
		startTime: time.Now(),
	}

	// Increment active requests
	active := atomic.AddInt64(&tracker.active, 1)
	pm.SetActiveRequests(int(active))

	return tracker
}

// Finish finishes tracking the request
func (rt *RequestTracker) Finish(status string) {
	duration := time.Since(rt.startTime)
	rt.monitor.RecordRequest(rt.method, rt.endpoint, status, duration)

	// Decrement active requests
	active := atomic.AddInt64(&rt.active, -1)
	rt.monitor.SetActiveRequests(int(active))
}

// FinishWithError finishes tracking the request with an error
func (rt *RequestTracker) FinishWithError(status, errorType string) {
	duration := time.Since(rt.startTime)
	rt.monitor.RecordRequest(rt.method, rt.endpoint, status, duration)
	rt.monitor.RecordRequestError(rt.method, rt.endpoint, errorType)

	// Decrement active requests
	active := atomic.AddInt64(&rt.active, -1)
	rt.monitor.SetActiveRequests(int(active))
}

// ScanTracker tracks individual scans
type ScanTracker struct {
	monitor   *PerformanceMonitor
	scanType  string
	target    string
	startTime time.Time
	active    int64
}

// NewScanTracker creates a new scan tracker
func (pm *PerformanceMonitor) NewScanTracker(scanType, target string) *ScanTracker {
	tracker := &ScanTracker{
		monitor:   pm,
		scanType:  scanType,
		target:    target,
		startTime: time.Now(),
	}

	// Increment active scans
	active := atomic.AddInt64(&tracker.active, 1)
	pm.SetActiveScans(int(active))

	return tracker
}

// Finish finishes tracking the scan
func (st *ScanTracker) Finish(status string) {
	duration := time.Since(st.startTime)
	st.monitor.RecordScan(st.scanType, st.target, status, duration)

	// Decrement active scans
	active := atomic.AddInt64(&st.active, -1)
	st.monitor.SetActiveScans(int(active))
}

// FinishWithError finishes tracking the scan with an error
func (st *ScanTracker) FinishWithError(status, errorType string) {
	duration := time.Since(st.startTime)
	st.monitor.RecordScan(st.scanType, st.target, status, duration)
	st.monitor.RecordScanError(st.scanType, errorType)

	// Decrement active scans
	active := atomic.AddInt64(&st.active, -1)
	st.monitor.SetActiveScans(int(active))
}