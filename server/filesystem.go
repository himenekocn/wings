package server

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/gabriel-vasile/mimetype"
	"github.com/mholt/archiver/v3"
	"github.com/pkg/errors"
	"github.com/pterodactyl/wings/config"
	"github.com/pterodactyl/wings/server/backup"
	ignore "github.com/sabhiram/go-gitignore"
	"golang.org/x/sync/errgroup"
	"io"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Error returned when there is a bad path provided to one of the FS calls.
var InvalidPathResolution = errors.New("invalid path resolution")

type Filesystem struct {
	// The server object associated with this Filesystem.
	Server *Server

	Configuration *config.SystemConfiguration
}

// Returns the root path that contains all of a server's data.
func (fs *Filesystem) Path() string {
	return filepath.Join(fs.Configuration.Data, fs.Server.Uuid)
}

// Normalizes a directory being passed in to ensure the user is not able to escape
// from their data directory. After normalization if the directory is still within their home
// path it is returned. If they managed to "escape" an error will be returned.
//
// This logic is actually copied over from the SFTP server code. Ideally that eventually
// either gets ported into this application, or is able to make use of this package.
func (fs *Filesystem) SafePath(p string) (string, error) {
	var nonExistentPathResolution string

	// Calling filpath.Clean on the joined directory will resolve it to the absolute path,
	// removing any ../ type of resolution arguments, and leaving us with a direct path link.
	//
	// This will also trim the existing root path off the beginning of the path passed to
	// the function since that can get a bit messy.
	r := filepath.Clean(filepath.Join(fs.Path(), strings.TrimPrefix(p, fs.Path())))

	// At the same time, evaluate the symlink status and determine where this file or folder
	// is truly pointing to.
	p, err := filepath.EvalSymlinks(r)
	if err != nil && !os.IsNotExist(err) {
		return "", err
	} else if os.IsNotExist(err) {
		// The requested directory doesn't exist, so at this point we need to iterate up the
		// path chain until we hit a directory that _does_ exist and can be validated.
		parts := strings.Split(filepath.Dir(r), "/")

		var try string
		// Range over all of the path parts and form directory pathings from the end
		// moving up until we have a valid resolution or we run out of paths to try.
		for k := range parts {
			try = strings.Join(parts[:(len(parts)-k)], "/")

			if !strings.HasPrefix(try, fs.Path()) {
				break
			}

			t, err := filepath.EvalSymlinks(try)
			if err == nil {
				nonExistentPathResolution = t
				break
			}
		}
	}

	// If the new path doesn't start with their root directory there is clearly an escape
	// attempt going on, and we should NOT resolve this path for them.
	if nonExistentPathResolution != "" {
		if !strings.HasPrefix(nonExistentPathResolution, fs.Path()) {
			return "", InvalidPathResolution
		}

		// If the nonExistentPathResolution variable is not empty then the initial path requested
		// did not exist and we looped through the pathway until we found a match. At this point
		// we've confirmed the first matched pathway exists in the root server directory, so we
		// can go ahead and just return the path that was requested initially.
		return r, nil
	}

	// If the requested directory from EvalSymlinks begins with the server root directory go
	// ahead and return it. If not we'll return an error which will block any further action
	// on the file.
	if strings.HasPrefix(p, fs.Path()) {
		return p, nil
	}

	return "", InvalidPathResolution
}

// Executes the fs.SafePath function in parallel against an array of paths. If any of the calls
// fails an error will be returned.
func (fs *Filesystem) ParallelSafePath(paths []string) ([]string, error) {
	var cleaned []string

	// Simple locker function to avoid racy appends to the array of cleaned paths.
	var m = new(sync.Mutex)
	var push = func(c string) {
		m.Lock()
		cleaned = append(cleaned, c)
		m.Unlock()
	}

	// Create an error group that we can use to run processes in parallel while retaining
	// the ability to cancel the entire process immediately should any of it fail.
	g, ctx := errgroup.WithContext(context.Background())

	// Iterate over all of the paths and generate a cleaned path, if there is an error for any
	// of the files, abort the process.
	for _, p := range paths {
		// Create copy so we can use it within the goroutine correctly.
		pi := p

		// Recursively call this function to continue digging through the directory tree within
		// a seperate goroutine. If the context is canceled abort this process.
		g.Go(func() error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				// If the callback returns true, go ahead and keep walking deeper. This allows
				// us to programatically continue deeper into directories, or stop digging
				// if that pathway knows it needs nothing else.
				if c, err := fs.SafePath(pi); err != nil {
					return err
				} else {
					push(c)
				}

				return nil
			}
		})
	}

	// Block until all of the routines finish and have returned a value.
	return cleaned, g.Wait()
}

// Determines if the directory a file is trying to be added to has enough space available
// for the file to be written to.
//
// Because determining the amount of space being used by a server is a taxing operation we
// will load it all up into a cache and pull from that as long as the key is not expired.
func (fs *Filesystem) HasSpaceAvailable() bool {
	space := fs.Server.Build.DiskSpace

	// If we have a match in the cache, use that value in the return. No need to perform an expensive
	// disk operation, even if this is an empty value.
	if x, exists := fs.Server.Cache.Get("disk_used"); exists {
		fs.Server.Resources.Disk = x.(int64)

		// This check is here to ensure that true is always returned if the server has unlimited disk space.
		// See the end of this method for more information (the other `if space <= 0`).
		if space <= 0 {
			return true
		}

		return (x.(int64) / 1000.0 / 1000.0) <= space
	}

	// If there is no size its either because there is no data (in which case running this function
	// will have effectively no impact), or there is nothing in the cache, in which case we need to
	// grab the size of their data directory. This is a taxing operation, so we want to store it in
	// the cache once we've gotten it.
	size, err := fs.DirectorySize("/")
	if err != nil {
		fs.Server.Log().WithField("error", err).Warn("failed to determine root server directory size")
	}

	// Always cache the size, even if there is an error. We want to always return that value
	// so that we don't cause an endless loop of determining the disk size if there is a temporary
	// error encountered.
	fs.Server.Cache.Set("disk_used", size, time.Second*60)

	// Determine if their folder size, in bytes, is smaller than the amount of space they've
	// been allocated.
	fs.Server.Resources.Disk = size

	// If space is -1 or 0 just return true, means they're allowed unlimited.
	//
	// Technically we could skip disk space calculation because we don't need to check if the server exceeds it's limit
	// but because this method caches the disk usage it would be best to calculate the disk usage and always
	// return true.
	if space <= 0 {
		return true
	}

	return (size / 1000.0 / 1000.0) <= space
}

// Determines the directory size of a given location by running parallel tasks to iterate
// through all of the folders. Returns the size in bytes. This can be a fairly taxing operation
// on locations with tons of files, so it is recommended that you cache the output.
func (fs *Filesystem) DirectorySize(dir string) (int64, error) {
	w := fs.NewWalker()
	ctx := context.Background()

	var size int64
	err := w.Walk(dir, ctx, func(f os.FileInfo, _ string) bool {
		// Only increment the size when we're dealing with a file specifically, otherwise
		// just continue digging deeper until there are no more directories to iterate over.
		if !f.IsDir() {
			atomic.AddInt64(&size, f.Size())
		}
		return true
	})

	return size, err
}

// Reads a file on the system and returns it as a byte representation in a file
// reader. This is not the most memory efficient usage since it will be reading the
// entirety of the file into memory.
func (fs *Filesystem) Readfile(p string) (io.Reader, error) {
	cleaned, err := fs.SafePath(p)
	if err != nil {
		return nil, err
	}

	b, err := ioutil.ReadFile(cleaned)
	if err != nil {
		return nil, err
	}

	return bytes.NewReader(b), nil
}

// Writes a file to the system. If the file does not already exist one will be created.
//
// @todo should probably have a write lock here so we don't write twice at once.
func (fs *Filesystem) Writefile(p string, r io.Reader) error {
	cleaned, err := fs.SafePath(p)
	if err != nil {
		return errors.WithStack(err)
	}

	// If the file does not exist on the system already go ahead and create the pathway
	// to it and an empty file. We'll then write to it later on after this completes.
	if stat, err := os.Stat(cleaned); err != nil && os.IsNotExist(err) {
		if err := os.MkdirAll(filepath.Dir(cleaned), 0755); err != nil {
			return errors.WithStack(err)
		}

		if err := fs.Chown(filepath.Dir(cleaned)); err != nil {
			return errors.WithStack(err)
		}
	} else if err != nil {
		return errors.WithStack(err)
	} else if stat.IsDir() {
		return errors.New("cannot use a directory as a file for writing")
	}

	// This will either create the file if it does not already exist, or open and
	// truncate the existing file.
	file, err := os.OpenFile(cleaned, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return errors.WithStack(err)
	}
	defer file.Close()

	// Create a new buffered writer that will write to the file we just opened
	// and stream in the contents from the reader.
	w := bufio.NewWriter(file)

	buf := make([]byte, 1024)
	for {
		n, err := r.Read(buf)
		if err != nil && err != io.EOF {
			return errors.WithStack(err)
		}

		if n == 0 {
			break
		}

		if _, err := w.Write(buf[:n]); err != nil {
			return errors.WithStack(err)
		}
	}

	if err := w.Flush(); err != nil {
		return errors.WithStack(err)
	}

	// Finally, chown the file to ensure the permissions don't end up out-of-whack
	// if we had just created it.
	return fs.Chown(p)
}

// Defines the stat struct object.
type Stat struct {
	Info     os.FileInfo
	Mimetype string
}

func (s *Stat) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Name      string `json:"name"`
		Created   string `json:"created"`
		Modified  string `json:"modified"`
		Mode      string `json:"mode"`
		Size      int64  `json:"size"`
		Directory bool   `json:"directory"`
		File      bool   `json:"file"`
		Symlink   bool   `json:"symlink"`
		Mime      string `json:"mime"`
	}{
		Name:      s.Info.Name(),
		Created:   s.CTime().Format(time.RFC3339),
		Modified:  s.Info.ModTime().Format(time.RFC3339),
		Mode:      s.Info.Mode().String(),
		Size:      s.Info.Size(),
		Directory: s.Info.IsDir(),
		File:      !s.Info.IsDir(),
		Symlink:   s.Info.Mode().Perm()&os.ModeSymlink != 0,
		Mime:      s.Mimetype,
	})
}

// Stats a file or folder and returns the base stat object from go along with the
// MIME data that can be used for editing files.
func (fs *Filesystem) Stat(p string) (*Stat, error) {
	cleaned, err := fs.SafePath(p)
	if err != nil {
		return nil, err
	}

	return fs.unsafeStat(cleaned)
}

func (fs *Filesystem) unsafeStat(p string) (*Stat, error) {
	s, err := os.Stat(p)
	if err != nil {
		return nil, err
	}

	var m = "inode/directory"
	if !s.IsDir() {
		m, _, err = mimetype.DetectFile(p)
		if err != nil {
			return nil, err
		}
	}

	st := &Stat{
		Info:     s,
		Mimetype: m,
	}

	return st, nil
}

// Creates a new directory (name) at a specificied path (p) for the server.
func (fs *Filesystem) CreateDirectory(name string, p string) error {
	cleaned, err := fs.SafePath(path.Join(p, name))
	if err != nil {
		return errors.WithStack(err)
	}

	return os.MkdirAll(cleaned, 0755)
}

// Moves (or renames) a file or directory.
func (fs *Filesystem) Rename(from string, to string) error {
	cleanedFrom, err := fs.SafePath(from)
	if err != nil {
		return errors.WithStack(err)
	}

	cleanedTo, err := fs.SafePath(to)
	if err != nil {
		return errors.WithStack(err)
	}

	if f, err := os.Stat(cleanedFrom); err != nil {
		return errors.WithStack(err)
	} else {
		d := cleanedTo
		if !f.IsDir() {
			d = strings.TrimSuffix(d, path.Base(cleanedTo))
		}

		// Ensure that the directory we're moving into exists correctly on the system.
		if mkerr := os.MkdirAll(d, 0644); mkerr != nil {
			return errors.WithStack(mkerr)
		}
	}

	return os.Rename(cleanedFrom, cleanedTo)
}

// Recursively iterates over a directory and sets the permissions on all of the
// underlying files.
func (fs *Filesystem) Chown(path string) error {
	cleaned, err := fs.SafePath(path)
	if err != nil {
		return errors.WithStack(err)
	}

	if s, err := os.Stat(cleaned); err != nil {
		return errors.WithStack(err)
	} else if !s.IsDir() {
		return os.Chown(cleaned, fs.Configuration.User.Uid, fs.Configuration.User.Gid)
	}

	return fs.chownDirectory(cleaned)
}

// Iterate over all of the files and directories. If it is a file just go ahead and perform
// the chown operation. Otherwise dig deeper into the directory until we've run out of
// directories to dig into.
func (fs *Filesystem) chownDirectory(path string) error {
	var wg sync.WaitGroup

	cleaned, err := fs.SafePath(path)
	if err != nil {
		return errors.WithStack(err)
	}

	// Chown the directory itself.
	os.Chown(cleaned, config.Get().System.User.Uid, config.Get().System.User.Gid)

	files, err := ioutil.ReadDir(cleaned)
	if err != nil {
		return errors.WithStack(err)
	}

	for _, f := range files {
		if f.IsDir() {
			wg.Add(1)

			go func(p string) {
				defer wg.Done()
				fs.chownDirectory(p)
			}(filepath.Join(cleaned, f.Name()))
		} else {
			// Chown the file.
			os.Chown(filepath.Join(cleaned, f.Name()), fs.Configuration.User.Uid, fs.Configuration.User.Gid)
		}
	}

	wg.Wait()

	return nil
}

// Copies a given file to the same location and appends a suffix to the file to indicate that
// it has been copied.
//
// @todo need to get an exclusive lock on the file.
func (fs *Filesystem) Copy(p string) error {
	cleaned, err := fs.SafePath(p)
	if err != nil {
		return errors.WithStack(err)
	}

	if s, err := os.Stat(cleaned); err != nil {
		return err
	} else if s.IsDir() || !s.Mode().IsRegular() {
		// If this is a directory or not a regular file, just throw a not-exist error
		// since anything calling this function should understand what that means.
		return os.ErrNotExist
	}

	base := filepath.Base(cleaned)
	relative := strings.TrimSuffix(strings.TrimPrefix(cleaned, fs.Path()), base)
	extension := filepath.Ext(base)
	name := strings.TrimSuffix(base, filepath.Ext(base))

	// Begin looping up to 50 times to try and create a unique copy file name. This will take
	// an input of "file.txt" and generate "file copy.txt". If that name is already taken, it will
	// then try to write "file copy 2.txt" and so on, until reaching 50 loops. At that point we
	// won't waste anymore time, just use the current timestamp and make that copy.
	//
	// Could probably make this more efficient by checking if there are any files matching the copy
	// pattern, and trying to find the highest number and then incrementing it by one rather than
	// looping endlessly.
	var i int
	copySuffix := " copy"
	for i = 0; i < 51; i++ {
		if i > 0 {
			copySuffix = " copy " + strconv.Itoa(i)
		}

		tryName := fmt.Sprintf("%s%s%s", name, copySuffix, extension)
		tryLocation, err := fs.SafePath(path.Join(relative, tryName))
		if err != nil {
			return errors.WithStack(err)
		}

		// If the file exists, continue to the next loop, otherwise we're good to start a copy.
		if _, err := os.Stat(tryLocation); err != nil && !os.IsNotExist(err) {
			return errors.WithStack(err)
		} else if os.IsNotExist(err) {
			break
		}

		if i == 50 {
			copySuffix = "." + time.Now().Format(time.RFC3339)
		}
	}

	finalPath, err := fs.SafePath(path.Join(relative, fmt.Sprintf("%s%s%s", name, copySuffix, extension)))
	if err != nil {
		return errors.WithStack(err)
	}

	source, err := os.Open(cleaned)
	if err != nil {
		return errors.WithStack(err)
	}
	defer source.Close()

	dest, err := os.Create(finalPath)
	if err != nil {
		return errors.WithStack(err)
	}
	defer dest.Close()

	if _, err := io.Copy(dest, source); err != nil {
		return errors.WithStack(err)
	}

	return nil
}

// Deletes a file or folder from the system. Prevents the user from accidentally
// (or maliciously) removing their root server data directory.
func (fs *Filesystem) Delete(p string) error {
	cleaned, err := fs.SafePath(p)
	if err != nil {
		return errors.WithStack(err)
	}

	// Block any whoopsies.
	if cleaned == fs.Path() {
		return errors.New("cannot delete root server directory")
	}

	return os.RemoveAll(cleaned)
}

// Lists the contents of a given directory and returns stat information about each
// file and folder within it.
func (fs *Filesystem) ListDirectory(p string) ([]*Stat, error) {
	cleaned, err := fs.SafePath(p)
	if err != nil {
		return nil, err
	}

	files, err := ioutil.ReadDir(cleaned)
	if err != nil {
		return nil, err
	}

	var wg sync.WaitGroup

	// You must initialize the output of this directory as a non-nil value otherwise
	// when it is marshaled into a JSON object you'll just get 'null' back, which will
	// break the panel badly.
	out := make([]*Stat, len(files))

	// Iterate over all of the files and directories returned and perform an async process
	// to get the mime-type for them all.
	for i, file := range files {
		wg.Add(1)

		go func(idx int, f os.FileInfo) {
			defer wg.Done()

			var m = "inode/directory"
			if !f.IsDir() {
				m, _, _ = mimetype.DetectFile(filepath.Join(cleaned, f.Name()))
			}

			out[idx] = &Stat{
				Info:     f,
				Mimetype: m,
			}
		}(i, file)
	}

	wg.Wait()

	// Sort the output alphabetically to begin with since we've run the output
	// through an asynchronous process and the order is gonna be very random.
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Info.Name() == out[j].Info.Name() || out[i].Info.Name() > out[j].Info.Name() {
			return true
		}

		return false
	})

	// Then, sort it so that directories are listed first in the output. Everything
	// will continue to be alphabetized at this point.
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].Info.IsDir()
	})

	return out, nil
}

// Ensures that the data directory for the server instance exists.
func (fs *Filesystem) EnsureDataDirectory() error {
	if _, err := os.Stat(fs.Path()); err != nil && !os.IsNotExist(err) {
		return errors.WithStack(err)
	} else if err != nil {
		// Create the server data directory because it does not currently exist
		// on the system.
		if err := os.MkdirAll(fs.Path(), 0700); err != nil {
			return errors.WithStack(err)
		}
	}

	return nil
}

// Given a directory, iterate through all of the files and folders within it and determine
// if they should be included in the output based on an array of ignored matches. This uses
// standard .gitignore formatting to make that determination.
//
// If no ignored files are passed through you'll get the entire directory listing.
func (fs *Filesystem) GetIncludedFiles(dir string, ignored []string) (*backup.IncludedFiles, error) {
	cleaned, err := fs.SafePath(dir)
	if err != nil {
		return nil, err
	}

	w := fs.NewWalker()
	ctx := context.Background()

	i, err := ignore.CompileIgnoreLines(ignored...)
	if err != nil {
		return nil, err
	}

	// Walk through all of the files and directories on a server. This callback only returns
	// files found, and will keep walking deeper and deeper into directories.
	inc := new(backup.IncludedFiles)
	if err := w.Walk(cleaned, ctx, func(f os.FileInfo, p string) bool {
		// Avoid unnecessary parsing if there are no ignored files, nothing will match anyways
		// so no reason to call the function.
		if len(ignored) == 0 || !i.MatchesPath(strings.TrimPrefix(p, fs.Path()+"/")) {
			inc.Push(&f, p)
		}

		// We can't just abort if the path is technically ignored. It is possible there is a nested
		// file or folder that should not be excluded, so in this case we need to just keep going
		// until we get to a final state.
		return true
	}); err != nil {
		return nil, err
	}

	return inc, nil
}

// Compresses all of the files matching the given paths in the specified directory. This function
// also supports passing nested paths to only compress certain files and folders when working in
// a larger directory. This effectively creates a local backup, but rather than ignoring specific
// files and folders, it takes an allow-list of files and folders.
//
// All paths are relative to the dir that is passed in as the first argument, and the compressed
// file will be placed at that location named `archive-{date}.tar.gz`.
func (fs *Filesystem) CompressFiles(dir string, paths []string) (os.FileInfo, error) {
	cleanedRootDir, err := fs.SafePath(dir)
	if err != nil {
		return nil, err
	}

	// Take all of the paths passed in and merge them together with the root directory we've gotten.
	for i, p := range paths {
		paths[i] = filepath.Join(cleanedRootDir, p)
	}

	cleaned, err := fs.ParallelSafePath(paths)
	if err != nil {
		return nil, err
	}

	w := fs.NewWalker()
	wg := new(sync.WaitGroup)

	inc := new(backup.IncludedFiles)
	// Iterate over all of the cleaned paths and merge them into a large object of final file
	// paths to pass into the archiver. As directories are encountered this will drop into them
	// and look for all of the files.
	for _, p := range cleaned {
		wg.Add(1)

		go func(pa string) {
			defer wg.Done()

			f, err := os.Stat(pa)
			if err != nil {
				fs.Server.Log().WithField("error", err).WithField("path", pa).Warn("failed to stat file or directory for compression")
				return
			}

			if f.IsDir() {
				// Recursively drop into directory and get all of the additional files and directories within
				// it that should be included in this backup.
				w.Walk(pa, context.Background(), func(info os.FileInfo, s string) bool {
					if !info.IsDir() {
						inc.Push(&info, s)
					}

					return true
				})
			} else {
				inc.Push(&f, pa)
			}
		}(p)
	}

	wg.Wait()

	a := &backup.Archive{TrimPrefix: fs.Path(), Files: inc}

	d := path.Join(cleanedRootDir, fmt.Sprintf("archive-%s.tar.gz", strings.ReplaceAll(time.Now().Format(time.RFC3339), ":", "")))

	return a.Create(d, context.Background())
}

// DecompressFile decompresses an archive.
func (fs *Filesystem) DecompressFile(dir, file string) error {
	// Clean the directory path where the contents of archive will be extracted to.
	safeBasePath, err := fs.SafePath(dir)
	if err != nil {
		return err
	}

	// Clean the full path to the archive which will be unarchived.
	safeArchivePath, err := fs.SafePath(filepath.Join(safeBasePath, file))
	if err != nil {
		return err
	}

	// Decompress the archive using it's extension to determine the algorithm.
	if err := archiver.Unarchive(safeArchivePath, safeBasePath); err != nil {
		return err
	}

	return nil
}
