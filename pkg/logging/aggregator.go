package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// LogLevel represents the severity of a log entry
type LogLevel string

const (
	LevelDebug LogLevel = "debug"
	LevelInfo  LogLevel = "info"
	LevelWarn  LogLevel = "warn"
	LevelError LogLevel = "error"
	LevelFatal LogLevel = "fatal"
)

// LogEntry represents a structured log entry
type LogEntry struct {
	Timestamp   time.Time              `json:"timestamp"`
	Level       LogLevel               `json:"level"`
	Message     string                 `json:"message"`
	Fields      map[string]interface{} `json:"fields,omitempty"`
	Source      string                 `json:"source,omitempty"`
	RequestID   string                 `json:"request_id,omitempty"`
	UserID      string                 `json:"user_id,omitempty"`
	SessionID   string                 `json:"session_id,omitempty"`
	Component   string                 `json:"component,omitempty"`
	Operation   string                 `json:"operation,omitempty"`
	Duration    time.Duration          `json:"duration,omitempty"`
	Error       string                 `json:"error,omitempty"`
	StackTrace  string                 `json:"stack_trace,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// LogOutput represents a log output destination
type LogOutput interface {
	Write(entry *LogEntry) error
	Close() error
}

// FileOutput writes logs to a file
type FileOutput struct {
	file   *os.File
	mu     sync.Mutex
	format string
}

// NewFileOutput creates a new file output
func NewFileOutput(filename, format string) (*FileOutput, error) {
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file: %w", err)
	}

	return &FileOutput{
		file:   file,
		format: format,
	}, nil
}

// Write writes a log entry to the file
func (f *FileOutput) Write(entry *LogEntry) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	var data []byte
	var err error

	switch f.format {
	case "json":
		data, err = json.Marshal(entry)
		if err != nil {
			return fmt.Errorf("failed to marshal log entry: %w", err)
		}
		data = append(data, '\n')
	case "text":
		text := fmt.Sprintf("[%s] %s %s",
			entry.Timestamp.Format(time.RFC3339),
			entry.Level,
			entry.Message)
		if entry.Error != "" {
			text += fmt.Sprintf(" error=%s", entry.Error)
		}
		text += "\n"
		data = []byte(text)
	default:
		return fmt.Errorf("unsupported format: %s", f.format)
	}

	_, err = f.file.Write(data)
	return err
}

// Close closes the file output
func (f *FileOutput) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.file.Close()
}

// HTTPOutput sends logs to an HTTP endpoint
type HTTPOutput struct {
	client   *http.Client
	url      string
	headers  map[string]string
	buffer   []*LogEntry
	bufferMu sync.Mutex
	batchSize int
	flushInterval time.Duration
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
}

// NewHTTPOutput creates a new HTTP output
func NewHTTPOutput(url string, headers map[string]string, batchSize int, flushInterval time.Duration) *HTTPOutput {
	ctx, cancel := context.WithCancel(context.Background())

	output := &HTTPOutput{
		client:        &http.Client{Timeout: 30 * time.Second},
		url:           url,
		headers:       headers,
		batchSize:     batchSize,
		flushInterval: flushInterval,
		ctx:           ctx,
		cancel:        cancel,
	}

	// Start background flusher
	output.wg.Add(1)
	go output.backgroundFlusher()

	return output
}

// Write adds a log entry to the buffer
func (h *HTTPOutput) Write(entry *LogEntry) error {
	h.bufferMu.Lock()
	h.buffer = append(h.buffer, entry)
	shouldFlush := len(h.buffer) >= h.batchSize
	h.bufferMu.Unlock()

	if shouldFlush {
		return h.flush()
	}

	return nil
}

// flush sends buffered entries to the HTTP endpoint
func (h *HTTPOutput) flush() error {
	h.bufferMu.Lock()
	if len(h.buffer) == 0 {
		h.bufferMu.Unlock()
		return nil
	}

	entries := make([]*LogEntry, len(h.buffer))
	copy(entries, h.buffer)
	h.buffer = h.buffer[:0] // Clear buffer
	h.bufferMu.Unlock()

	// Prepare request
	data, err := json.Marshal(map[string]interface{}{
		"entries": entries,
	})
	if err != nil {
		return fmt.Errorf("failed to marshal log entries: %w", err)
	}

	req, err := http.NewRequestWithContext(h.ctx, "POST", h.url, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	for key, value := range h.headers {
		req.Header.Set(key, value)
	}

	resp, err := h.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send logs: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HTTP error %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// backgroundFlusher periodically flushes the buffer
func (h *HTTPOutput) backgroundFlusher() {
	defer h.wg.Done()

	ticker := time.NewTicker(h.flushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-h.ctx.Done():
			// Final flush before shutdown
			h.flush()
			return
		case <-ticker.C:
			h.flush()
		}
	}
}

// Close closes the HTTP output
func (h *HTTPOutput) Close() error {
	h.cancel()
	h.wg.Wait()
	return h.flush() // Final flush
}

// ConsoleOutput writes logs to console with colors
type ConsoleOutput struct {
	writer io.Writer
	colors bool
}

// NewConsoleOutput creates a new console output
func NewConsoleOutput(writer io.Writer, colors bool) *ConsoleOutput {
	return &ConsoleOutput{
		writer: writer,
		colors: colors,
	}
}

// Write writes a log entry to console
func (c *ConsoleOutput) Write(entry *LogEntry) error {
	var color string
	var reset string

	if c.colors {
		reset = "\033[0m"
		switch entry.Level {
		case LevelDebug:
			color = "\033[36m" // Cyan
		case LevelInfo:
			color = "\033[32m" // Green
		case LevelWarn:
			color = "\033[33m" // Yellow
		case LevelError:
			color = "\033[31m" // Red
		case LevelFatal:
			color = "\033[35m" // Magenta
		default:
			color = ""
		}
	}

	text := fmt.Sprintf("%s[%s] %s %s%s",
		color,
		entry.Timestamp.Format("15:04:05"),
		entry.Level,
		entry.Message,
		reset)

	if entry.Error != "" {
		text += fmt.Sprintf(" %serror=%s%s", color, entry.Error, reset)
	}

	if len(entry.Fields) > 0 {
		for key, value := range entry.Fields {
			text += fmt.Sprintf(" %s=%v", key, value)
		}
	}

	text += "\n"

	_, err := c.writer.Write([]byte(text))
	return err
}

// Close closes the console output
func (c *ConsoleOutput) Close() error {
	return nil
}

// LogAggregator aggregates logs from multiple sources
type LogAggregator struct {
	outputs   []LogOutput
	mu        sync.RWMutex
	buffer    chan *LogEntry
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	logger    *logrus.Logger
	filters   []LogFilter
	enrichers []LogEnricher
}

// LogFilter filters log entries
type LogFilter interface {
	ShouldLog(entry *LogEntry) bool
}

// LogEnricher enriches log entries with additional data
type LogEnricher interface {
	Enrich(entry *LogEntry) *LogEntry
}

// LevelFilter filters logs by level
type LevelFilter struct {
	MinLevel LogLevel
}

// ShouldLog checks if the entry should be logged
func (f *LevelFilter) ShouldLog(entry *LogEntry) bool {
	levelOrder := map[LogLevel]int{
		LevelDebug: 0,
		LevelInfo:  1,
		LevelWarn:  2,
		LevelError: 3,
		LevelFatal: 4,
	}

	return levelOrder[entry.Level] >= levelOrder[f.MinLevel]
}

// ComponentFilter filters logs by component
type ComponentFilter struct {
	AllowedComponents []string
}

// ShouldLog checks if the entry should be logged
func (f *ComponentFilter) ShouldLog(entry *LogEntry) bool {
	if len(f.AllowedComponents) == 0 {
		return true
	}

	for _, component := range f.AllowedComponents {
		if entry.Component == component {
			return true
		}
	}

	return false
}

// TimestampEnricher adds timestamp to log entries
type TimestampEnricher struct{}

// Enrich adds timestamp if not present
func (e *TimestampEnricher) Enrich(entry *LogEntry) *LogEntry {
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now()
	}
	return entry
}

// HostnameEnricher adds hostname to log entries
type HostnameEnricher struct {
	hostname string
}

// NewHostnameEnricher creates a new hostname enricher
func NewHostnameEnricher() *HostnameEnricher {
	hostname, _ := os.Hostname()
	return &HostnameEnricher{hostname: hostname}
}

// Enrich adds hostname to metadata
func (e *HostnameEnricher) Enrich(entry *LogEntry) *LogEntry {
	if entry.Metadata == nil {
		entry.Metadata = make(map[string]interface{})
	}
	entry.Metadata["hostname"] = e.hostname
	return entry
}

// NewLogAggregator creates a new log aggregator
func NewLogAggregator(bufferSize int) *LogAggregator {
	ctx, cancel := context.WithCancel(context.Background())

	aggregator := &LogAggregator{
		buffer: make(chan *LogEntry, bufferSize),
		ctx:    ctx,
		cancel: cancel,
		logger: logrus.New(),
	}

	// Start worker
	aggregator.wg.Add(1)
	go aggregator.worker()

	return aggregator
}

// AddOutput adds a log output
func (a *LogAggregator) AddOutput(output LogOutput) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.outputs = append(a.outputs, output)
}

// AddFilter adds a log filter
func (a *LogAggregator) AddFilter(filter LogFilter) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.filters = append(a.filters, filter)
}

// AddEnricher adds a log enricher
func (a *LogAggregator) AddEnricher(enricher LogEnricher) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.enrichers = append(a.enrichers, enricher)
}

// Log logs an entry
func (a *LogAggregator) Log(entry *LogEntry) {
	select {
	case a.buffer <- entry:
	case <-a.ctx.Done():
		// Aggregator is shutting down
	default:
		// Buffer is full, drop the log entry
		a.logger.Warn("Log buffer is full, dropping entry")
	}
}

// worker processes log entries
func (a *LogAggregator) worker() {
	defer a.wg.Done()

	for {
		select {
		case <-a.ctx.Done():
			// Process remaining entries
			for {
				select {
				case entry := <-a.buffer:
					a.processEntry(entry)
				default:
					return
				}
			}
		case entry := <-a.buffer:
			a.processEntry(entry)
		}
	}
}

// processEntry processes a single log entry
func (a *LogAggregator) processEntry(entry *LogEntry) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	// Apply enrichers
	for _, enricher := range a.enrichers {
		entry = enricher.Enrich(entry)
	}

	// Apply filters
	for _, filter := range a.filters {
		if !filter.ShouldLog(entry) {
			return
		}
	}

	// Send to all outputs
	for _, output := range a.outputs {
		if err := output.Write(entry); err != nil {
			a.logger.WithError(err).Error("Failed to write log entry")
		}
	}
}

// Close closes the log aggregator
func (a *LogAggregator) Close() error {
	a.cancel()
	a.wg.Wait()

	a.mu.Lock()
	defer a.mu.Unlock()

	for _, output := range a.outputs {
		if err := output.Close(); err != nil {
			a.logger.WithError(err).Error("Failed to close log output")
		}
	}

	return nil
}

// Helper functions for creating log entries

// Debug creates a debug log entry
func Debug(message string) *LogEntry {
	return &LogEntry{
		Timestamp: time.Now(),
		Level:     LevelDebug,
		Message:   message,
	}
}

// Info creates an info log entry
func Info(message string) *LogEntry {
	return &LogEntry{
		Timestamp: time.Now(),
		Level:     LevelInfo,
		Message:   message,
	}
}

// Warn creates a warning log entry
func Warn(message string) *LogEntry {
	return &LogEntry{
		Timestamp: time.Now(),
		Level:     LevelWarn,
		Message:   message,
	}
}

// Error creates an error log entry
func Error(message string, err error) *LogEntry {
	entry := &LogEntry{
		Timestamp: time.Now(),
		Level:     LevelError,
		Message:   message,
	}

	if err != nil {
		entry.Error = err.Error()
	}

	return entry
}

// Fatal creates a fatal log entry
func Fatal(message string, err error) *LogEntry {
	entry := &LogEntry{
		Timestamp: time.Now(),
		Level:     LevelFatal,
		Message:   message,
	}

	if err != nil {
		entry.Error = err.Error()
	}

	return entry
}

// WithFields adds fields to a log entry
func (e *LogEntry) WithFields(fields map[string]interface{}) *LogEntry {
	if e.Fields == nil {
		e.Fields = make(map[string]interface{})
	}

	for key, value := range fields {
		e.Fields[key] = value
	}

	return e
}

// WithField adds a single field to a log entry
func (e *LogEntry) WithField(key string, value interface{}) *LogEntry {
	if e.Fields == nil {
		e.Fields = make(map[string]interface{})
	}

	e.Fields[key] = value
	return e
}

// WithComponent sets the component for a log entry
func (e *LogEntry) WithComponent(component string) *LogEntry {
	e.Component = component
	return e
}

// WithOperation sets the operation for a log entry
func (e *LogEntry) WithOperation(operation string) *LogEntry {
	e.Operation = operation
	return e
}

// WithRequestID sets the request ID for a log entry
func (e *LogEntry) WithRequestID(requestID string) *LogEntry {
	e.RequestID = requestID
	return e
}

// WithDuration sets the duration for a log entry
func (e *LogEntry) WithDuration(duration time.Duration) *LogEntry {
	e.Duration = duration
	return e
}