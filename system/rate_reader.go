package system

import (
	"io"
	"time"
)

// RateLimitReader wraps a io.Reader and limits its read rate to n MiB/s
type RateLimitReader struct {
	reader    io.Reader
	readerAt  io.ReaderAt  // Store ReaderAt if provided
	limiter   *Rate
	chunkSize int64
}

const MiB = 1024 * 1024 // 1 MiB in bytes
const chunkTime = 10    // Time window for rate limiting in milliseconds

// NewRateLimitReader creates a new rate limited reader with target speed in MiB/s
func NewRateLimitReader(r io.Reader, targetMBps int) *RateLimitReader {
	if targetMBps <= 0 {
		// No rate limit, return original reader directly
		return &RateLimitReader{
			reader:    r,
			limiter:   nil,
			chunkSize: 0,
		}
	}

	// For target speed of X MiB/s:
	// 1. We want to send X MiB per second
	// 2. We split it into (1000/chunkTime) chunks per second
	// 3. Each chunk should contain (X * MiB)/(1000/chunkTime) bytes

	chunksPerSecond := uint64(1000 / chunkTime)
	bytesPerSecond := int64(targetMBps * MiB)
	chunkSize := bytesPerSecond / int64(chunksPerSecond)

	return &RateLimitReader{
		reader:    r,
		limiter:   NewRate(chunksPerSecond, time.Second),
		chunkSize: chunkSize,
	}
}

// NewRateLimitReaderAt creates a new rate limited reader for a ReaderAt with target speed in MiB/s
func NewRateLimitReaderAt(r io.ReaderAt, targetMBps int) *RateLimitReader {
	if targetMBps <= 0 {
		// No rate limit, return original reader directly
		return &RateLimitReader{
			readerAt:  r,
			limiter:   nil,
			chunkSize: 0,
		}
	}

	// For target speed of X MiB/s:
	// 1. We want to send X MiB per second
	// 2. We split it into (1000/chunkTime) chunks per second
	// 3. Each chunk should contain (X * MiB)/(1000/chunkTime) bytes

	chunksPerSecond := uint64(1000 / chunkTime)
	bytesPerSecond := int64(targetMBps * MiB)
	chunkSize := bytesPerSecond / int64(chunksPerSecond)

	return &RateLimitReader{
		readerAt:  r,
		limiter:   NewRate(chunksPerSecond, time.Second),
		chunkSize: chunkSize,
	}
}

func (r *RateLimitReader) Read(p []byte) (n int, err error) {
	if r.limiter == nil {
		// No rate limiting, use the appropriate reader
		if r.readerAt != nil {
			// For ReaderAt, we can't use Read method directly, so we need to read from position 0
			return r.readerAt.ReadAt(p, 0)
		}
		return r.reader.Read(p)
	}

	// Limit read size to chunk size
	if int64(len(p)) > r.chunkSize {
		p = p[0:r.chunkSize]
	}

	// Wait for rate limit
	for !r.limiter.Try() {
		time.Sleep(time.Duration(chunkTime) * time.Millisecond)
	}

	// Use the appropriate reader
	if r.readerAt != nil {
		// For ReaderAt, we can't use Read method directly, so we need to read from position 0
		return r.readerAt.ReadAt(p, 0)
	}
	return r.reader.Read(p)
}

// ReadAt implements io.ReaderAt for rate limited reading with random access
func (r *RateLimitReader) ReadAt(p []byte, off int64) (n int, err error) {
	// Use the stored ReaderAt if available
	if r.readerAt != nil {
		if r.limiter == nil {
			// No rate limiting, delegate directly
			return r.readerAt.ReadAt(p, off)
		}

		// Limit read size to chunk size
		if int64(len(p)) > r.chunkSize {
			p = p[0:r.chunkSize]
		}

		// Wait for rate limit
		for !r.limiter.Try() {
			time.Sleep(time.Duration(chunkTime) * time.Millisecond)
		}

		return r.readerAt.ReadAt(p, off)
	}

	// Fallback: If the underlying reader doesn't support ReaderAt, check if it's a ReaderAt interface
	if ra, ok := r.reader.(io.ReaderAt); ok {
		if r.limiter == nil {
			// No rate limiting, delegate directly
			return ra.ReadAt(p, off)
		}

		// Limit read size to chunk size
		if int64(len(p)) > r.chunkSize {
			p = p[0:r.chunkSize]
		}

		// Wait for rate limit
		for !r.limiter.Try() {
			time.Sleep(time.Duration(chunkTime) * time.Millisecond)
		}

		return ra.ReadAt(p, off)
	}

	// Fallback: If the underlying reader doesn't support ReadAt, we can't support it
	// We can't seek a regular reader to a specific offset and then read
	return 0, io.ErrNoProgress
}