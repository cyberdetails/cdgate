package scan

// A root filesystem read the way `trivy rootfs` reads it (trivy 00b7394
// pkg/commands/artifact/run.go ScanRootfs: image analyzers, lock files off;
// pkg/fanal/walker/fs.go): every regular file under the root, symbolic links
// never followed, "**/.git" and the top-level proc, sys and dev skipped, a
// directory that cannot be read for lack of permission skipped (any other
// walk error fails). Files are selected and read with the image reader's
// rules and limits (internal/image); the OS packages are read through
// rootFiles, the same as `cdgate scan` of a root filesystem.

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/cyberdetails/cdgate/internal/langpkg"
	"github.com/cyberdetails/cdgate/internal/ospkg"
)

// Limits, the image reader's.
const (
	MaxRootFSEntries = 4_000_000
	MaxRootFSKept    = 512 << 20
	MaxRootFSBinary  = 256 << 20
	MaxRootFSJar     = 256 << 20
)

// RootFS is a langpkg.Source over a directory.
type RootFS struct {
	Root    string
	files   map[string][]byte
	bins    map[string]*langpkg.GoBinary
	jars    map[string]*langpkg.Jar
	rust    map[string]*langpkg.RustBinary
	kept    int
	Skipped []string
	os      rootFiles
}

func (r *RootFS) Metadata() map[string][]byte                  { return r.files }
func (r *RootFS) GoBinaries() map[string]*langpkg.GoBinary     { return r.bins }
func (r *RootFS) Jars() map[string]*langpkg.Jar                { return r.jars }
func (r *RootFS) RustBinaries() map[string]*langpkg.RustBinary { return r.rust }

// OSFiles is the tree for the OS package readers.
func (r *RootFS) OSFiles() ospkg.Files { return r.os }

// trivySkipDir: walker defaultSkipDirs ("**/.git", "proc", "sys", "dev").
func trivySkipDir(rel string) bool {
	return rel == "proc" || rel == "sys" || rel == "dev" || filepath.Base(rel) == ".git"
}

// OpenRootFS walks root.
func OpenRootFS(root string) (*RootFS, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	st, err := os.Lstat(abs)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", root)
	}
	r := &RootFS{Root: abs, files: map[string][]byte{}, bins: map[string]*langpkg.GoBinary{},
		jars: map[string]*langpkg.Jar{}, rust: map[string]*langpkg.RustBinary{},
		os: rootFiles{siblings{root: abs, dir: abs}}}
	entries := 0
	var scratch []byte
	err = filepath.WalkDir(abs, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if p != abs && errors.Is(err, fs.ErrPermission) {
				return nil // Trivy onError: permission errors are skipped
			}
			return err
		}
		entries++
		if entries > MaxRootFSEntries {
			return errors.New("too many files in the root filesystem")
		}
		rel, err := filepath.Rel(abs, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if p != abs && trivySkipDir(rel) {
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil // links are never followed; devices, sockets, pipes ignored
		}
		info, err := d.Info()
		if err != nil {
			if errors.Is(err, fs.ErrPermission) {
				return nil
			}
			return err
		}
		return r.add(p, rel, info, &scratch)
	})
	if err != nil {
		return nil, err
	}
	return r, nil
}

func (r *RootFS) add(p, rel string, info fs.FileInfo, scratch *[]byte) error {
	size := info.Size()
	if langpkg.IsJar(rel) {
		if size > MaxRootFSJar {
			r.jars[rel] = &langpkg.Jar{TooLarge: true}
			return nil
		}
		b, err := readRootFSFile(p, size)
		if err != nil {
			return skipPermission(err)
		}
		r.jars[rel] = langpkg.ReadJar(b, rel)
		return nil
	}
	kinds := langpkg.Classify(rel, int64(info.Mode().Perm()))
	if kinds&langpkg.Metadata != 0 {
		if size > ospkg.MaxFileBytes { // the image reader's limit for one kept file
			return fmt.Errorf("%s is larger than %d MiB", rel, ospkg.MaxFileBytes>>20)
		}
		b, err := readRootFSFile(p, size)
		if err != nil {
			return skipPermission(err)
		}
		r.kept += len(b)
		if r.kept > MaxRootFSKept {
			return errors.New("package metadata in the root filesystem is too large")
		}
		r.files[rel] = b
		if kinds&langpkg.GoExe != 0 {
			r.readExe(rel, b)
		}
		return nil
	}
	if kinds&langpkg.GoExe == 0 {
		return nil
	}
	f, err := os.Open(p)
	if err != nil {
		return skipPermission(err)
	}
	defer f.Close()
	var ident [16]byte
	n, err := io.ReadFull(f, ident[:])
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return err
	}
	if !langpkg.GoExeCandidate(ident[:n]) && !langpkg.RustExeCandidate(ident[:n]) {
		return nil
	}
	if size > MaxRootFSBinary {
		r.Skipped = append(r.Skipped, fmt.Sprintf("%s: executable larger than %d MiB, Go and Rust build information not read", rel, MaxRootFSBinary>>20))
		return nil
	}
	if cap(*scratch) < int(size) {
		*scratch = make([]byte, 0, size)
	}
	buf := bytes.NewBuffer(append((*scratch)[:0], ident[:n]...))
	if _, err := io.Copy(buf, io.LimitReader(f, MaxRootFSBinary)); err != nil {
		return err
	}
	*scratch = buf.Bytes()[:0]
	r.readExe(rel, buf.Bytes())
	return nil
}

func (r *RootFS) readExe(rel string, b []byte) {
	if langpkg.GoExeCandidate(b) {
		if bi := langpkg.ReadGoBinary(b); bi != nil {
			r.bins[rel] = bi
		}
	}
	if langpkg.RustExeCandidate(b) {
		if rb := langpkg.ReadRustBinary(b); rb != nil {
			r.rust[rel] = rb
		}
	}
}

// readRootFSFile reads at most size+1 bytes (a file that grew is refused).
func readRootFSFile(p string, size int64) ([]byte, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, size+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > size {
		return nil, fmt.Errorf("%s changed while it was read", p)
	}
	return b, nil
}

func skipPermission(err error) error {
	if errors.Is(err, fs.ErrPermission) {
		return nil
	}
	return err
}
