package system

import (
	"io"
	"time"
)

// RateLimitReader wraps a io.Reader and limits its read rate to n MiB/s
type RateLimitReader struct {
	reader    io.Reader
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

func (r *RateLimitReader) Read(p []byte) (n int, err error) {
	if r.limiter == nil {
		// No rate limiting
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

	return r.reader.Read(p)
}