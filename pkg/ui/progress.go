package ui

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
)

// ProgressBar represents a customizable progress bar
type ProgressBar struct {
	total       int64
	current     int64
	width       int
	label       string
	showPercent bool
	showSpeed   bool
	showETA     bool
	colored     bool
	writer      io.Writer
	startTime   time.Time
	lastUpdate  time.Time
	mu          sync.RWMutex
	finished    bool
	template    string
}

// ProgressBarOptions holds configuration for progress bar
type ProgressBarOptions struct {
	Total       int64
	Width       int
	Label       string
	ShowPercent bool
	ShowSpeed   bool
	ShowETA     bool
	Colored     bool
	Writer      io.Writer
	Template    string
}

// NewProgressBar creates a new progress bar
func NewProgressBar(options ProgressBarOptions) *ProgressBar {
	if options.Width == 0 {
		options.Width = 40
	}
	if options.Writer == nil {
		options.Writer = os.Stderr
	}
	if options.Template == "" {
		options.Template = "[{bar}] {percent}% {current}/{total} {label} {speed} {eta}"
	}

	return &ProgressBar{
		total:       options.Total,
		width:       options.Width,
		label:       options.Label,
		showPercent: options.ShowPercent,
		showSpeed:   options.ShowSpeed,
		showETA:     options.ShowETA,
		colored:     options.Colored,
		writer:      options.Writer,
		startTime:   time.Now(),
		lastUpdate:  time.Now(),
		template:    options.Template,
	}
}

// DefaultProgressBar creates a progress bar with default settings
func DefaultProgressBar(total int64, label string) *ProgressBar {
	return NewProgressBar(ProgressBarOptions{
		Total:       total,
		Label:       label,
		ShowPercent: true,
		ShowSpeed:   true,
		ShowETA:     true,
		Colored:     true,
	})
}

// Set updates the current progress
func (pb *ProgressBar) Set(current int64) {
	pb.mu.Lock()
	defer pb.mu.Unlock()

	pb.current = current
	pb.lastUpdate = time.Now()
	pb.render()
}

// Add increments the current progress
func (pb *ProgressBar) Add(delta int64) {
	pb.mu.Lock()
	defer pb.mu.Unlock()

	pb.current += delta
	if pb.current > pb.total {
		pb.current = pb.total
	}
	pb.lastUpdate = time.Now()
	pb.render()
}

// Increment increments the progress by 1
func (pb *ProgressBar) Increment() {
	pb.Add(1)
}

// Finish marks the progress bar as complete
func (pb *ProgressBar) Finish() {
	pb.mu.Lock()
	defer pb.mu.Unlock()

	pb.current = pb.total
	pb.finished = true
	pb.render()
	fmt.Fprintln(pb.writer) // New line after completion
}

// SetLabel updates the progress bar label
func (pb *ProgressBar) SetLabel(label string) {
	pb.mu.Lock()
	defer pb.mu.Unlock()

	pb.label = label
	pb.render()
}

// GetCurrent returns the current progress
func (pb *ProgressBar) GetCurrent() int64 {
	pb.mu.RLock()
	defer pb.mu.RUnlock()
	return pb.current
}

// GetTotal returns the total progress
func (pb *ProgressBar) GetTotal() int64 {
	pb.mu.RLock()
	defer pb.mu.RUnlock()
	return pb.total
}

// IsFinished returns whether the progress bar is finished
func (pb *ProgressBar) IsFinished() bool {
	pb.mu.RLock()
	defer pb.mu.RUnlock()
	return pb.finished
}

// render draws the progress bar
func (pb *ProgressBar) render() {
	if pb.finished {
		return
	}

	percent := float64(pb.current) / float64(pb.total) * 100
	filledWidth := int(float64(pb.width) * float64(pb.current) / float64(pb.total))

	// Create the bar
	bar := pb.createBar(filledWidth)

	// Build the output string
	output := pb.template
	output = strings.ReplaceAll(output, "{bar}", bar)
	output = strings.ReplaceAll(output, "{percent}", fmt.Sprintf("%.1f", percent))
	output = strings.ReplaceAll(output, "{current}", fmt.Sprintf("%d", pb.current))
	output = strings.ReplaceAll(output, "{total}", fmt.Sprintf("%d", pb.total))
	output = strings.ReplaceAll(output, "{label}", pb.label)

	if pb.showSpeed {
		speed := pb.calculateSpeed()
		output = strings.ReplaceAll(output, "{speed}", speed)
	} else {
		output = strings.ReplaceAll(output, "{speed}", "")
	}

	if pb.showETA {
		eta := pb.calculateETA()
		output = strings.ReplaceAll(output, "{eta}", eta)
	} else {
		output = strings.ReplaceAll(output, "{eta}", "")
	}

	// Clean up extra spaces
	output = strings.Join(strings.Fields(output), " ")

	// Write to output
	fmt.Fprintf(pb.writer, "\r%s", output)
}

// createBar creates the visual bar representation
func (pb *ProgressBar) createBar(filledWidth int) string {
	var bar strings.Builder

	if pb.colored {
		// Colored bar
		green := color.New(color.FgGreen).SprintFunc()
		gray := color.New(color.FgHiBlack).SprintFunc()

		for i := 0; i < pb.width; i++ {
			if i < filledWidth {
				bar.WriteString(green("█"))
			} else {
				bar.WriteString(gray("░"))
			}
		}
	} else {
		// Simple ASCII bar
		for i := 0; i < pb.width; i++ {
			if i < filledWidth {
				bar.WriteString("=")
			} else {
				bar.WriteString("-")
			}
		}
	}

	return bar.String()
}

// calculateSpeed calculates the current speed
func (pb *ProgressBar) calculateSpeed() string {
	elapsed := time.Since(pb.startTime).Seconds()
	if elapsed == 0 {
		return "0/s"
	}

	speed := float64(pb.current) / elapsed
	return fmt.Sprintf("%.1f/s", speed)
}

// calculateETA calculates the estimated time of arrival
func (pb *ProgressBar) calculateETA() string {
	if pb.current == 0 {
		return "--:--"
	}

	elapsed := time.Since(pb.startTime).Seconds()
	speed := float64(pb.current) / elapsed
	remaining := float64(pb.total-pb.current) / speed

	if remaining < 0 {
		return "00:00"
	}

	minutes := int(remaining) / 60
	seconds := int(remaining) % 60

	return fmt.Sprintf("%02d:%02d", minutes, seconds)
}

// MultiProgressBar manages multiple progress bars
type MultiProgressBar struct {
	bars   []*ProgressBar
	writer io.Writer
	mu     sync.RWMutex
}

// NewMultiProgressBar creates a new multi-progress bar manager
func NewMultiProgressBar(writer io.Writer) *MultiProgressBar {
	if writer == nil {
		writer = os.Stderr
	}

	return &MultiProgressBar{
		writer: writer,
	}
}

// AddBar adds a new progress bar
func (mpb *MultiProgressBar) AddBar(options ProgressBarOptions) *ProgressBar {
	mpb.mu.Lock()
	defer mpb.mu.Unlock()

	options.Writer = mpb.writer
	bar := NewProgressBar(options)
	mpb.bars = append(mpb.bars, bar)

	return bar
}

// Render renders all progress bars
func (mpb *MultiProgressBar) Render() {
	mpb.mu.RLock()
	defer mpb.mu.RUnlock()

	// Clear previous output
	fmt.Fprintf(mpb.writer, "\033[%dA", len(mpb.bars))

	for _, bar := range mpb.bars {
		bar.render()
		fmt.Fprintln(mpb.writer)
	}
}

// Spinner represents a loading spinner
type Spinner struct {
	chars    []string
	index    int
	label    string
	colored  bool
	writer   io.Writer
	running  bool
	mu       sync.RWMutex
	stopChan chan bool
}

// NewSpinner creates a new spinner
func NewSpinner(label string, colored bool, writer io.Writer) *Spinner {
	if writer == nil {
		writer = os.Stderr
	}

	return &Spinner{
		chars:    []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"},
		label:    label,
		colored:  colored,
		writer:   writer,
		stopChan: make(chan bool),
	}
}

// Start starts the spinner animation
func (s *Spinner) Start() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return
	}

	s.running = true
	go s.animate()
}

// Stop stops the spinner animation
func (s *Spinner) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return
	}

	s.running = false
	s.stopChan <- true
	fmt.Fprintf(s.writer, "\r%s\r", strings.Repeat(" ", len(s.label)+10))
}

// SetLabel updates the spinner label
func (s *Spinner) SetLabel(label string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.label = label
}

// animate runs the spinner animation
func (s *Spinner) animate() {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopChan:
			return
		case <-ticker.C:
			s.render()
		}
	}
}

// render draws the spinner
func (s *Spinner) render() {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if !s.running {
		return
	}

	char := s.chars[s.index]
	s.index = (s.index + 1) % len(s.chars)

	if s.colored {
		cyan := color.New(color.FgCyan).SprintFunc()
		fmt.Fprintf(s.writer, "\r%s %s", cyan(char), s.label)
	} else {
		fmt.Fprintf(s.writer, "\r%s %s", char, s.label)
	}
}

// StatusDisplay shows status messages with colors
type StatusDisplay struct {
	colored bool
	writer  io.Writer
}

// NewStatusDisplay creates a new status display
func NewStatusDisplay(colored bool, writer io.Writer) *StatusDisplay {
	if writer == nil {
		writer = os.Stdout
	}

	return &StatusDisplay{
		colored: colored,
		writer:  writer,
	}
}

// Success displays a success message
func (sd *StatusDisplay) Success(message string) {
	if sd.colored {
		green := color.New(color.FgGreen, color.Bold).SprintFunc()
		fmt.Fprintf(sd.writer, "%s %s\n", green("✓"), message)
	} else {
		fmt.Fprintf(sd.writer, "[OK] %s\n", message)
	}
}

// Error displays an error message
func (sd *StatusDisplay) Error(message string) {
	if sd.colored {
		red := color.New(color.FgRed, color.Bold).SprintFunc()
		fmt.Fprintf(sd.writer, "%s %s\n", red("✗"), message)
	} else {
		fmt.Fprintf(sd.writer, "[ERROR] %s\n", message)
	}
}

// Warning displays a warning message
func (sd *StatusDisplay) Warning(message string) {
	if sd.colored {
		yellow := color.New(color.FgYellow, color.Bold).SprintFunc()
		fmt.Fprintf(sd.writer, "%s %s\n", yellow("⚠"), message)
	} else {
		fmt.Fprintf(sd.writer, "[WARNING] %s\n", message)
	}
}

// Info displays an info message
func (sd *StatusDisplay) Info(message string) {
	if sd.colored {
		blue := color.New(color.FgBlue, color.Bold).SprintFunc()
		fmt.Fprintf(sd.writer, "%s %s\n", blue("ℹ"), message)
	} else {
		fmt.Fprintf(sd.writer, "[INFO] %s\n", message)
	}
}

// Debug displays a debug message
func (sd *StatusDisplay) Debug(message string) {
	if sd.colored {
		gray := color.New(color.FgHiBlack).SprintFunc()
		fmt.Fprintf(sd.writer, "%s %s\n", gray("🐛"), message)
	} else {
		fmt.Fprintf(sd.writer, "[DEBUG] %s\n", message)
	}
}