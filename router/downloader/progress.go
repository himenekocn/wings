package downloader

import (
	"context"
	"sync"
	"time"

	"github.com/apex/log"
	"github.com/google/uuid"
)

// ProgressEvent represents a progress update event
type ProgressEvent struct {
	ID        string  `json:"id"`
	FileName  string  `json:"file_name"`
	Progress  float64 `json:"progress"`
	Bytes     int64   `json:"bytes"`
	Total     int64   `json:"total"`
	Speed     int64   `json:"speed"`
	Status    string  `json:"status"`
	Timestamp int64   `json:"timestamp"`
}

// ProgressTracker tracks download progress and broadcasts to listeners
type ProgressTracker struct {
	mu        sync.RWMutex
	listeners map[string][]chan *ProgressEvent
	downloads map[string]*ProgressEvent
}

var progressTracker = &ProgressTracker{
	listeners: make(map[string][]chan *ProgressEvent),
	downloads: make(map[string]*ProgressEvent),
}

// Subscribe subscribes to progress updates for a specific download
func (pt *ProgressTracker) Subscribe(downloadID string) chan *ProgressEvent {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	ch := make(chan *ProgressEvent, 100)
	pt.listeners[downloadID] = append(pt.listeners[downloadID], ch)
	return ch
}

// Unsubscribe unsubscribes from progress updates
func (pt *ProgressTracker) Unsubscribe(downloadID string, ch chan *ProgressEvent) {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	if listeners, ok := pt.listeners[downloadID]; ok {
		for i, listener := range listeners {
			if listener == ch {
				pt.listeners[downloadID] = append(listeners[:i], listeners[i+1:]...)
				close(listener)
				break
			}
		}
	}
}

// Broadcast broadcasts a progress event to all listeners
func (pt *ProgressTracker) Broadcast(event *ProgressEvent) {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	pt.downloads[event.ID] = event

	if listeners, ok := pt.listeners[event.ID]; ok {
		for _, ch := range listeners {
			select {
			case ch <- event:
			default:
				// Channel is full, skip this update
				log.WithField("download_id", event.ID).Debug("progress channel full, skipping update")
			}
		}
	}
}

// GetProgress returns the current progress for a download
func (pt *ProgressTracker) GetProgress(downloadID string) *ProgressEvent {
	pt.mu.RLock()
	defer pt.mu.RUnlock()
	return pt.downloads[downloadID]
}

// Remove removes a download from tracking
func (pt *ProgressTracker) Remove(downloadID string) {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	delete(pt.downloads, downloadID)
	if listeners, ok := pt.listeners[downloadID]; ok {
		for _, ch := range listeners {
			close(ch)
		}
		delete(pt.listeners, downloadID)
	}
}

// ProgressWriter wraps an io.Writer to track write progress
type ProgressWriter struct {
	total      int64
	written    int64
	startTime  time.Time
	lastUpdate time.Time
	lastBytes  int64
	speed      int64
	onProgress func(bytes, total int64, speed int64)
	mu         sync.Mutex
}

// NewProgressWriter creates a new progress writer
func NewProgressWriter(total int64, onProgress func(bytes, total int64, speed int64)) *ProgressWriter {
	return &ProgressWriter{
		total:      total,
		startTime:  time.Now(),
		lastUpdate: time.Now(),
		onProgress: onProgress,
	}
}

// Write implements io.Writer
func (pw *ProgressWriter) Write(p []byte) (int, error) {
	n := len(p)
	pw.mu.Lock()
	defer pw.mu.Unlock()

	pw.written += int64(n)

	// Calculate speed (bytes per second)
	now := time.Now()
	if now.Sub(pw.lastUpdate) >= time.Second {
		duration := now.Sub(pw.lastUpdate).Seconds()
		bytesDiff := pw.written - pw.lastBytes
		pw.speed = int64(float64(bytesDiff) / duration)
		pw.lastUpdate = now
		pw.lastBytes = pw.written
	}

	// Call progress callback
	if pw.onProgress != nil {
		pw.onProgress(pw.written, pw.total, pw.speed)
	}

	return n, nil
}

// Progress returns the current progress (0-1)
func (pw *ProgressWriter) Progress() float64 {
	pw.mu.Lock()
	defer pw.mu.Unlock()

	if pw.total <= 0 {
		return 0
	}
	return float64(pw.written) / float64(pw.total)
}

// GenerateSessionID generates a unique session ID for tracking
func GenerateSessionID() string {
	return uuid.New().String()
}

// CleanupStaleSessions periodically cleans up stale progress sessions
func CleanupStaleSessions(ctx context.Context, timeout time.Duration) {
	ticker := time.NewTicker(timeout)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			progressTracker.mu.Lock()
			for id, event := range progressTracker.downloads {
				if time.Since(time.Unix(event.Timestamp, 0)) > timeout {
					progressTracker.Remove(id)
					log.WithField("download_id", id).Debug("cleaned up stale progress session")
				}
			}
			progressTracker.mu.Unlock()
		}
	}
}
