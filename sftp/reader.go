package sftp

import (
	"io"
	"sync"
)

// sftpReaderAt wraps an io.Reader to implement io.ReaderAt and io.Closer
// with thread safety and improved error handling
type sftpReaderAt struct {
	mu     sync.RWMutex
	reader io.Reader
	closer io.Closer
	closed bool
}

func NewSFTPReaderAt(r io.Reader) *sftpReaderAt {
	var closer io.Closer
	if c, ok := r.(io.Closer); ok {
		closer = c
	}
	return &sftpReaderAt{
		reader: r,
		closer: closer,
	}
}

func (r *sftpReaderAt) ReadAt(p []byte, off int64) (n int, err error) {
	r.mu.RLock()
	if r.closed {
		r.mu.RUnlock()
		return 0, io.ErrClosedPipe
	}
	
	reader := r.reader
	r.mu.RUnlock()
	
	// If the underlying reader is already an io.ReaderAt (like RateLimitReader with ReadAt support), use it directly
	// This is the most efficient path and should be taken in most cases
	if ra, ok := reader.(io.ReaderAt); ok {
		return ra.ReadAt(p, off)
	}
	
	// For other readers, we need to seek to the correct offset first
	// This is a fallback implementation, though for our use case the above path should be taken
	if seeker, ok := reader.(io.Seeker); ok {
		_, err = seeker.Seek(off, io.SeekStart)
		if err != nil {
			return 0, err
		}
		return reader.Read(p)
	}
	
	// If the reader doesn't support seeking, we can't support ReadAt properly
	return 0, io.ErrNoProgress
}

// Close closes the underlying reader if it implements io.Closer
func (r *sftpReaderAt) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	
	if r.closed {
		return nil
	}
	
	r.closed = true
	if r.closer != nil {
		return r.closer.Close()
	}
	return nil
}
