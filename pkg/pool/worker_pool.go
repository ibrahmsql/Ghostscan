package pool

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"time"
)

// Task represents a unit of work
type Task struct {
	ID       string
	Function func(ctx context.Context) error
	Timeout  time.Duration
	Retries  int
}

// Result represents the result of a task execution
type Result struct {
	TaskID    string
	Error     error
	Duration  time.Duration
	StartTime time.Time
	EndTime   time.Time
	Retries   int
}

// WorkerPool manages a pool of goroutines for concurrent task execution
type WorkerPool struct {
	workerCount int
	taskQueue   chan Task
	resultQueue chan Result
	wg          sync.WaitGroup
	ctx         context.Context
	cancel      context.CancelFunc
	metrics     *PoolMetrics
	mu          sync.RWMutex
	running     bool
}

// PoolMetrics tracks pool performance metrics
type PoolMetrics struct {
	TasksSubmitted   int64
	TasksCompleted   int64
	TasksFailed      int64
	TasksRetried     int64
	AverageExecTime  time.Duration
	TotalExecTime    time.Duration
	ActiveWorkers    int32
	QueueSize        int32
	PeakQueueSize    int32
	StartTime        time.Time
	mu               sync.RWMutex
}

// NewWorkerPool creates a new worker pool
func NewWorkerPool(workerCount int, queueSize int) *WorkerPool {
	if workerCount <= 0 {
		workerCount = runtime.NumCPU()
	}
	if queueSize <= 0 {
		queueSize = workerCount * 2
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &WorkerPool{
		workerCount: workerCount,
		taskQueue:   make(chan Task, queueSize),
		resultQueue: make(chan Result, queueSize),
		ctx:         ctx,
		cancel:      cancel,
		metrics: &PoolMetrics{
			StartTime: time.Now(),
		},
	}
}

// Start initializes and starts the worker pool
func (wp *WorkerPool) Start() {
	wp.mu.Lock()
	defer wp.mu.Unlock()

	if wp.running {
		return
	}

	wp.running = true

	// Start workers
	for i := 0; i < wp.workerCount; i++ {
		wp.wg.Add(1)
		go wp.worker(i)
	}

	// Start metrics updater
	go wp.updateMetrics()
}

// Stop gracefully shuts down the worker pool
func (wp *WorkerPool) Stop() {
	wp.mu.Lock()
	defer wp.mu.Unlock()

	if !wp.running {
		return
	}

	wp.running = false
	close(wp.taskQueue)
	wp.cancel()
	wp.wg.Wait()
	close(wp.resultQueue)
}

// Submit adds a task to the pool
func (wp *WorkerPool) Submit(task Task) error {
	wp.mu.RLock()
	running := wp.running
	wp.mu.RUnlock()

	if !running {
		return ErrPoolNotRunning
	}

	select {
	case wp.taskQueue <- task:
		wp.metrics.mu.Lock()
		wp.metrics.TasksSubmitted++
		currentQueueSize := int32(len(wp.taskQueue))
		if currentQueueSize > wp.metrics.PeakQueueSize {
			wp.metrics.PeakQueueSize = currentQueueSize
		}
		wp.metrics.mu.Unlock()
		return nil
	case <-wp.ctx.Done():
		return ErrPoolShutdown
	default:
		return ErrQueueFull
	}
}

// Results returns the result channel
func (wp *WorkerPool) Results() <-chan Result {
	return wp.resultQueue
}

// GetMetrics returns current pool metrics
func (wp *WorkerPool) GetMetrics() PoolMetrics {
	wp.metrics.mu.RLock()
	defer wp.metrics.mu.RUnlock()
	return *wp.metrics
}

// worker is the main worker goroutine
func (wp *WorkerPool) worker(id int) {
	defer wp.wg.Done()

	for {
		select {
		case task, ok := <-wp.taskQueue:
			if !ok {
				return
			}
			wp.executeTask(task)
		case <-wp.ctx.Done():
			return
		}
	}
}

// executeTask executes a single task with retry logic
func (wp *WorkerPool) executeTask(task Task) {
	startTime := time.Now()
	var err error
	retries := 0

	// Create task context with timeout
	taskCtx := wp.ctx
	if task.Timeout > 0 {
		var cancel context.CancelFunc
		taskCtx, cancel = context.WithTimeout(wp.ctx, task.Timeout)
		defer cancel()
	}

	// Execute with retry logic
	for retries <= task.Retries {
		err = task.Function(taskCtx)
		if err == nil {
			break
		}
		retries++
		if retries <= task.Retries {
			// Exponential backoff
			backoff := time.Duration(retries) * 100 * time.Millisecond
			select {
			case <-time.After(backoff):
			case <-taskCtx.Done():
				err = taskCtx.Err()
				break
			}
		}
	}

	endTime := time.Now()
	duration := endTime.Sub(startTime)

	// Create result
	result := Result{
		TaskID:    task.ID,
		Error:     err,
		Duration:  duration,
		StartTime: startTime,
		EndTime:   endTime,
		Retries:   retries,
	}

	// Update metrics
	wp.updateTaskMetrics(result)

	// Send result
	select {
	case wp.resultQueue <- result:
	case <-wp.ctx.Done():
		return
	}
}

// updateTaskMetrics updates metrics after task completion
func (wp *WorkerPool) updateTaskMetrics(result Result) {
	wp.metrics.mu.Lock()
	defer wp.metrics.mu.Unlock()

	wp.metrics.TasksCompleted++
	if result.Error != nil {
		wp.metrics.TasksFailed++
	}
	if result.Retries > 0 {
		wp.metrics.TasksRetried++
	}

	// Update average execution time
	wp.metrics.TotalExecTime += result.Duration
	wp.metrics.AverageExecTime = wp.metrics.TotalExecTime / time.Duration(wp.metrics.TasksCompleted)
}

// updateMetrics periodically updates pool metrics
func (wp *WorkerPool) updateMetrics() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			wp.metrics.mu.Lock()
			wp.metrics.QueueSize = int32(len(wp.taskQueue))
			wp.metrics.mu.Unlock()
		case <-wp.ctx.Done():
			return
		}
	}
}

// Errors
var (
	ErrPoolNotRunning = fmt.Errorf("worker pool is not running")
	ErrPoolShutdown   = fmt.Errorf("worker pool is shutting down")
	ErrQueueFull      = fmt.Errorf("task queue is full")
)

// Helper functions

// NewTask creates a new task with default settings
func NewTask(id string, fn func(ctx context.Context) error) Task {
	return Task{
		ID:       id,
		Function: fn,
		Timeout:  30 * time.Second,
		Retries:  3,
	}
}

// NewTaskWithOptions creates a new task with custom options
func NewTaskWithOptions(id string, fn func(ctx context.Context) error, timeout time.Duration, retries int) Task {
	return Task{
		ID:       id,
		Function: fn,
		Timeout:  timeout,
		Retries:  retries,
	}
}