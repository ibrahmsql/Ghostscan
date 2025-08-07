package cache

import (
	"fmt"
	"sync"
	"time"
)

// CacheItem represents a cached item with metadata
type CacheItem struct {
	Key        string
	Value      interface{}
	Expiration time.Time
	CreatedAt  time.Time
	AccessedAt time.Time
	HitCount   int64
	Size       int64
}

// IsExpired checks if the cache item has expired
func (ci *CacheItem) IsExpired() bool {
	return !ci.Expiration.IsZero() && time.Now().After(ci.Expiration)
}

// MemoryCache represents an in-memory cache with TTL and size limits
type MemoryCache struct {
	items       map[string]*CacheItem
	mu          sync.RWMutex
	maxSize     int64
	currentSize int64
	defaultTTL  time.Duration
	cleanupTick time.Duration
	stopCleanup chan struct{}
	metrics     *CacheMetrics
}

// CacheMetrics tracks cache performance
type CacheMetrics struct {
	Hits        int64
	Misses      int64
	Evictions   int64
	Expirations int64
	Sets        int64
	Deletes     int64
	mu          sync.RWMutex
}

// CacheOptions configures the cache behavior
type CacheOptions struct {
	MaxSize     int64         // Maximum cache size in bytes
	DefaultTTL  time.Duration // Default time-to-live
	CleanupTick time.Duration // Cleanup interval
}

// DefaultCacheOptions returns sensible default options
func DefaultCacheOptions() CacheOptions {
	return CacheOptions{
		MaxSize:     100 * 1024 * 1024, // 100MB
		DefaultTTL:  1 * time.Hour,
		CleanupTick: 5 * time.Minute,
	}
}

// NewMemoryCache creates a new memory cache
func NewMemoryCache(options CacheOptions) *MemoryCache {
	if options.MaxSize <= 0 {
		options.MaxSize = 100 * 1024 * 1024 // 100MB default
	}
	if options.DefaultTTL <= 0 {
		options.DefaultTTL = 1 * time.Hour
	}
	if options.CleanupTick <= 0 {
		options.CleanupTick = 5 * time.Minute
	}

	cache := &MemoryCache{
		items:       make(map[string]*CacheItem),
		maxSize:     options.MaxSize,
		defaultTTL:  options.DefaultTTL,
		cleanupTick: options.CleanupTick,
		stopCleanup: make(chan struct{}),
		metrics:     &CacheMetrics{},
	}

	// Start cleanup goroutine
	go cache.cleanup()

	return cache
}

// Set stores a value in the cache with default TTL
func (mc *MemoryCache) Set(key string, value interface{}) error {
	return mc.SetWithTTL(key, value, mc.defaultTTL)
}

// SetWithTTL stores a value in the cache with custom TTL
func (mc *MemoryCache) SetWithTTL(key string, value interface{}, ttl time.Duration) error {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	// Calculate item size (rough estimation)
	itemSize := mc.estimateSize(value)

	// Check if we need to evict items
	if mc.currentSize+itemSize > mc.maxSize {
		if err := mc.evictLRU(itemSize); err != nil {
			return fmt.Errorf("failed to evict items: %v", err)
		}
	}

	// Remove existing item if present
	if existing, exists := mc.items[key]; exists {
		mc.currentSize -= existing.Size
	}

	// Create new item
	expiration := time.Time{}
	if ttl > 0 {
		expiration = time.Now().Add(ttl)
	}

	item := &CacheItem{
		Key:        key,
		Value:      value,
		Expiration: expiration,
		CreatedAt:  time.Now(),
		AccessedAt: time.Now(),
		HitCount:   0,
		Size:       itemSize,
	}

	mc.items[key] = item
	mc.currentSize += itemSize

	// Update metrics
	mc.metrics.mu.Lock()
	mc.metrics.Sets++
	mc.metrics.mu.Unlock()

	return nil
}

// Get retrieves a value from the cache
func (mc *MemoryCache) Get(key string) (interface{}, bool) {
	mc.mu.RLock()
	item, exists := mc.items[key]
	mc.mu.RUnlock()

	if !exists {
		mc.metrics.mu.Lock()
		mc.metrics.Misses++
		mc.metrics.mu.Unlock()
		return nil, false
	}

	// Check expiration
	if item.IsExpired() {
		mc.Delete(key)
		mc.metrics.mu.Lock()
		mc.metrics.Misses++
		mc.metrics.Expirations++
		mc.metrics.mu.Unlock()
		return nil, false
	}

	// Update access time and hit count
	mc.mu.Lock()
	item.AccessedAt = time.Now()
	item.HitCount++
	mc.mu.Unlock()

	// Update metrics
	mc.metrics.mu.Lock()
	mc.metrics.Hits++
	mc.metrics.mu.Unlock()

	return item.Value, true
}

// Delete removes an item from the cache
func (mc *MemoryCache) Delete(key string) bool {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	item, exists := mc.items[key]
	if !exists {
		return false
	}

	delete(mc.items, key)
	mc.currentSize -= item.Size

	// Update metrics
	mc.metrics.mu.Lock()
	mc.metrics.Deletes++
	mc.metrics.mu.Unlock()

	return true
}

// Clear removes all items from the cache
func (mc *MemoryCache) Clear() {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	mc.items = make(map[string]*CacheItem)
	mc.currentSize = 0
}

// Size returns the current cache size in bytes
func (mc *MemoryCache) Size() int64 {
	mc.mu.RLock()
	defer mc.mu.RUnlock()
	return mc.currentSize
}

// Count returns the number of items in the cache
func (mc *MemoryCache) Count() int {
	mc.mu.RLock()
	defer mc.mu.RUnlock()
	return len(mc.items)
}

// GetMetrics returns cache performance metrics
func (mc *MemoryCache) GetMetrics() CacheMetrics {
	mc.metrics.mu.RLock()
	defer mc.metrics.mu.RUnlock()
	return *mc.metrics
}

// HitRate returns the cache hit rate as a percentage
func (mc *MemoryCache) HitRate() float64 {
	mc.metrics.mu.RLock()
	defer mc.metrics.mu.RUnlock()

	total := mc.metrics.Hits + mc.metrics.Misses
	if total == 0 {
		return 0
	}
	return float64(mc.metrics.Hits) / float64(total) * 100
}

// Keys returns all cache keys
func (mc *MemoryCache) Keys() []string {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	keys := make([]string, 0, len(mc.items))
	for key := range mc.items {
		keys = append(keys, key)
	}
	return keys
}

// Close stops the cache cleanup goroutine
func (mc *MemoryCache) Close() {
	close(mc.stopCleanup)
}

// cleanup periodically removes expired items
func (mc *MemoryCache) cleanup() {
	ticker := time.NewTicker(mc.cleanupTick)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			mc.removeExpired()
		case <-mc.stopCleanup:
			return
		}
	}
}

// removeExpired removes all expired items
func (mc *MemoryCache) removeExpired() {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	expiredKeys := make([]string, 0)
	for key, item := range mc.items {
		if item.IsExpired() {
			expiredKeys = append(expiredKeys, key)
		}
	}

	for _, key := range expiredKeys {
		item := mc.items[key]
		delete(mc.items, key)
		mc.currentSize -= item.Size
		mc.metrics.Expirations++
	}
}

// evictLRU evicts least recently used items to make space
func (mc *MemoryCache) evictLRU(neededSpace int64) error {
	if neededSpace > mc.maxSize {
		return fmt.Errorf("item size exceeds maximum cache size")
	}

	// Create slice of items sorted by access time
	items := make([]*CacheItem, 0, len(mc.items))
	for _, item := range mc.items {
		items = append(items, item)
	}

	// Sort by access time (oldest first)
	for i := 0; i < len(items)-1; i++ {
		for j := i + 1; j < len(items); j++ {
			if items[i].AccessedAt.After(items[j].AccessedAt) {
				items[i], items[j] = items[j], items[i]
			}
		}
	}

	// Evict items until we have enough space
	freedSpace := int64(0)
	for _, item := range items {
		if mc.currentSize-freedSpace+neededSpace <= mc.maxSize {
			break
		}

		delete(mc.items, item.Key)
		freedSpace += item.Size
		mc.metrics.Evictions++
	}

	mc.currentSize -= freedSpace
	return nil
}

// estimateSize estimates the memory size of a value
func (mc *MemoryCache) estimateSize(value interface{}) int64 {
	switch v := value.(type) {
	case string:
		return int64(len(v))
	case []byte:
		return int64(len(v))
	case int, int32, int64, float32, float64, bool:
		return 8
	default:
		// Rough estimation for complex types
		return 64
	}
}

// Cache interface for different cache implementations
type Cache interface {
	Set(key string, value interface{}) error
	SetWithTTL(key string, value interface{}, ttl time.Duration) error
	Get(key string) (interface{}, bool)
	Delete(key string) bool
	Clear()
	Size() int64
	Count() int
	Keys() []string
	Close()
}

// Ensure MemoryCache implements Cache interface
var _ Cache = (*MemoryCache)(nil)

// CacheManager manages multiple cache instances
type CacheManager struct {
	caches map[string]Cache
	mu     sync.RWMutex
}

// NewCacheManager creates a new cache manager
func NewCacheManager() *CacheManager {
	return &CacheManager{
		caches: make(map[string]Cache),
	}
}

// AddCache adds a cache instance with a name
func (cm *CacheManager) AddCache(name string, cache Cache) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.caches[name] = cache
}

// GetCache retrieves a cache instance by name
func (cm *CacheManager) GetCache(name string) (Cache, bool) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	cache, exists := cm.caches[name]
	return cache, exists
}

// RemoveCache removes a cache instance
func (cm *CacheManager) RemoveCache(name string) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	if cache, exists := cm.caches[name]; exists {
		cache.Close()
		delete(cm.caches, name)
	}
}

// CloseAll closes all cache instances
func (cm *CacheManager) CloseAll() {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	for _, cache := range cm.caches {
		cache.Close()
	}
	cm.caches = make(map[string]Cache)
}