// Package scan walks a directory and reads every supported lockfile in it.
//
// Safety rules (the scanned tree is untrusted, e.g. a pull request):
//   - symbolic links are never followed (neither directories nor files);
//   - nothing outside the given root is read;
//   - every file is read through a size limit, and the walk stops after a
//     fixed number of entries;
//   - a recognised file that cannot be read, or a manifest we do not support
//     yet, is reported — never skipped silently.
package scan

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ferhatcil/cdgate/internal/buildinfo"
	"github.com/ferhatcil/cdgate/internal/model"
	"github.com/ferhatcil/cdgate/internal/ospkg"
	"github.com/ferhatcil/cdgate/internal/parse"
)

const (
	MaxFileBytes     = 64 << 20 // 64 MiB per lockfile
	MaxManifestBytes = 8 << 20  // 8 MiB per sibling manifest (package.json, pyproject.toml)
	MaxGlobMatches   = 2000     // workspace directories per lockfile
	MaxEntries       = 500_000  // directory entries visited
	MaxDepth         = 40
)

// Directories that hold installed dependencies or VCS data, not manifests of
// this project. Their lockfiles describe other projects.
var skipDirs = map[string]bool{
	".git": true, ".hg": true, ".svn": true, "node_modules": true, "vendor": true,
	".venv": true, "venv": true, "__pycache__": true, ".tox": true, ".gradle": true,
	"bower_components": true, ".terraform": true,
}

// File is the result for one recognised file.
type File struct {
	Path      string `json:"path"`
	Kind      string `json:"kind"`
	Ecosystem string `json:"ecosystem,omitempty"`
	Packages  int    `json:"packages"`
	Error     string `json:"error,omitempty"`
}

// Result of a scan.
type Result struct {
	Root        string          `json:"-"`
	OS          *ospkg.OS       `json:"os,omitempty"`
	Image       string          `json:"image,omitempty"` // image tag(s) when the input was an image archive
	Packages    []model.Package `json:"packages"`
	Files       []File          `json:"files"`
	Unsupported []File          `json:"unsupported"`
	// Unchecked are packages found in an ecosystem the API has no advisories
	// for yet (RPM-based distributions): listed, never reported as clean.
	Unchecked []model.Package `json:"unchecked_packages,omitempty"`
	Truncated bool            `json:"truncated"`
	// LocalNotSent counts the application's own projects whose names were
	// not sent (see parse.Options.LocalProjects).
	LocalNotSent int `json:"local_not_sent,omitempty"`
	// SBOM is set when the input was one SBOM document (cdgate sbom).
	SBOM bool `json:"-"`
	// RootFS is set for cdgate rootfs.
	RootFS bool `json:"-"`
}

// Dir scans root. The returned error is only for an unusable root; per-file
// problems are recorded in Result.Files.
func Dir(root string, opt parse.Options) (*Result, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	st, err := os.Lstat(abs)
	if err != nil {
		return nil, err
	}
	res := &Result{Root: abs}
	if st.Mode().IsRegular() { // a single file was given
		scanFile(res, filepath.Dir(abs), abs, opt)
		return res, nil
	}
	if !st.IsDir() {
		return nil, fmt.Errorf("%s is neither a directory nor a regular file", root)
	}
	// A root filesystem (extracted image, chroot): read its OS package database.
	if rf := (rootFiles{siblings{root: abs, dir: abs}}); ospkg.HasOS(rf) {
		r, err := ospkg.Analyze(rf)
		if err != nil {
			res.Files = append(res.Files, File{Path: "/", Kind: "os", Error: err.Error()})
		} else {
			res.OS = &r.OS
			for _, p := range r.Files {
				res.Files = append(res.Files, File{Path: p, Kind: "os-packages", Ecosystem: r.Ecosystem, Packages: len(r.Packages)})
			}
			if r.Queryable {
				res.Packages = append(res.Packages, r.Packages...)
			} else {
				res.Unchecked = append(res.Unchecked, r.Packages...)
			}
			res.Unchecked = append(res.Unchecked, r.Unchecked...)
		}
	}
	entries := 0
	walkErr := filepath.WalkDir(abs, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if p == abs {
				return err
			}
			return nil // unreadable subdirectory: skip it, keep scanning
		}
		entries++
		if entries > MaxEntries {
			res.Truncated = true
			return fs.SkipAll
		}
		rel, _ := filepath.Rel(abs, p)
		if d.IsDir() {
			if p != abs && (skipDirs[d.Name()] || strings.Count(rel, string(filepath.Separator)) >= MaxDepth) {
				return fs.SkipDir
			}
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 || !d.Type().IsRegular() {
			return nil // never follow links, ignore devices/sockets
		}
		scanFile(res, abs, p, opt)
		return nil
	})
	if walkErr != nil && !errors.Is(walkErr, fs.SkipAll) {
		return nil, walkErr
	}
	sort.Slice(res.Packages, func(i, j int) bool {
		a, b := res.Packages[i], res.Packages[j]
		if a.Ecosystem != b.Ecosystem {
			return a.Ecosystem < b.Ecosystem
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.Version < b.Version
	})
	return res, nil
}

func scanFile(res *Result, root, p string, opt parse.Options) {
	rel, err := filepath.Rel(root, p)
	if err != nil || strings.HasPrefix(rel, "..") {
		return // outside the root: never read
	}
	rel = filepath.ToSlash(rel)
	name := filepath.Base(p)
	kind, ok := parse.Lookup(name)
	if !ok {
		if reason, un := parse.Unsupported(name); un {
			res.Unsupported = append(res.Unsupported, File{Path: rel, Kind: name, Error: reason})
		}
		return
	}
	f := File{Path: rel, Kind: kind.Name, Ecosystem: kind.Ecosystem}
	opt.Files = siblings{root: root, dir: filepath.Dir(p)}
	local := 0
	opt.LocalProjects = &local
	pkgs, err := readFile(p, kind, opt)
	res.LocalNotSent += local
	if err != nil {
		f.Error = err.Error()
	}
	for i := range pkgs {
		pkgs[i].Ecosystem = kind.Ecosystem
		pkgs[i].Source = rel
	}
	f.Packages = len(pkgs)
	res.Files = append(res.Files, f)
	res.Packages = append(res.Packages, pkgs...)
}

func readFile(p string, kind parse.Kind, opt parse.Options) ([]model.Package, error) {
	fh, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	st, err := fh.Stat()
	if err != nil {
		return nil, err
	}
	if st.Size() > MaxFileBytes {
		return nil, fmt.Errorf("file is larger than %d MiB; not read", MaxFileBytes>>20)
	}
	lr := &io.LimitedReader{R: fh, N: MaxFileBytes + 1}
	pkgs, err := kind.Parse(lr, opt)
	if lr.N <= 0 {
		return nil, fmt.Errorf("file grew past %d MiB while reading; not used", MaxFileBytes>>20)
	}
	return pkgs, err
}

// siblings implements parse.Files for one lockfile: everything stays inside
// the scan root, no path component may be a symbolic link, sizes are capped.
type siblings struct{ root, dir string }

var errOutside = errors.New("path is outside the scanned tree")

func (s siblings) resolve(rel string) (string, error) {
	if strings.Contains(rel, "\x00") {
		return "", errOutside
	}
	p := filepath.Join(s.dir, filepath.FromSlash(rel))
	r, err := filepath.Rel(s.root, p)
	if err != nil || r == ".." || strings.HasPrefix(r, ".."+string(filepath.Separator)) || filepath.IsAbs(r) {
		return "", errOutside
	}
	// Every component from the root down must be a real directory or file.
	cur := s.root
	for _, part := range strings.Split(r, string(filepath.Separator)) {
		if part == "." || part == "" {
			continue
		}
		cur = filepath.Join(cur, part)
		fi, err := os.Lstat(cur)
		if err != nil {
			return "", err
		}
		if fi.Mode()&fs.ModeSymlink != 0 {
			return "", fmt.Errorf("%s is a symbolic link; not followed", filepath.ToSlash(r))
		}
	}
	return p, nil
}

func (s siblings) Read(rel string) ([]byte, error) { return s.readLimit(rel, MaxManifestBytes) }

func (s siblings) readLimit(rel string, limit int64) ([]byte, error) {
	p, err := s.resolve(rel)
	if err != nil {
		return nil, err
	}
	fi, err := os.Lstat(p)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", rel)
	}
	if fi.Size() > limit {
		return nil, fmt.Errorf("%s is larger than %d MiB; not read", rel, limit>>20)
	}
	fh, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	data, err := io.ReadAll(io.LimitReader(fh, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s grew past %d MiB while reading", rel, limit>>20)
	}
	return data, nil
}

func (s siblings) Glob(pattern string) ([]string, error) {
	if _, err := filepath.Match(pattern, ""); err != nil {
		return nil, err
	}
	matches, err := filepath.Glob(filepath.Join(s.dir, filepath.FromSlash(pattern)))
	if err != nil {
		return nil, err
	}
	var out []string
	for _, m := range matches {
		rel, err := filepath.Rel(s.dir, m)
		if err != nil {
			continue
		}
		rel = filepath.ToSlash(rel)
		p, err := s.resolve(rel)
		if err != nil {
			continue // outside the root or through a symbolic link
		}
		if fi, err := os.Lstat(p); err != nil || !fi.IsDir() {
			continue
		}
		out = append(out, rel)
		if len(out) >= MaxGlobMatches {
			break
		}
	}
	sort.Strings(out)
	return out, nil
}

// rootFiles adapts siblings to ospkg.Files (same root boundary, no links).
type rootFiles struct{ s siblings }

// RPMBuildInfo: a root filesystem is one layer for Trivy, so every package's
// build information is that of the tree itself (lookupBuildInfo(0) with a
// single layer).
func (r rootFiles) RPMBuildInfo(_, _, _ string) (*model.BuildInfo, bool) {
	var files []buildinfo.File
	for _, dir := range []string{"root/buildinfo/content_manifests/", "usr/share/buildinfo/", "root/buildinfo/"} {
		for _, p := range r.List(dir) {
			if !buildinfo.IsContentManifest(p) && !buildinfo.IsDockerfile(p) {
				continue
			}
			b, err := r.s.Read(p)
			if err != nil || len(b) > buildinfo.MaxFileBytes {
				// Unread build information is unknown, not absent.
				files = append(files, buildinfo.File{Path: p, TooLarge: true})
				continue
			}
			files = append(files, buildinfo.File{Path: p, B: b})
		}
	}
	return buildinfo.Merge(files)
}

// Get reads an OS package file with the same limits as an image layer
// (ospkg.FileLimit), not the lockfile sibling limit: a real rpm database is
// larger than 8 MiB (ubi9: 14.6 MB).
func (r rootFiles) Get(p string) ([]byte, bool) {
	b, err := r.s.readLimit(p, ospkg.FileLimit(p))
	return b, err == nil
}

func (r rootFiles) List(dir string) []string {
	p, err := r.s.resolve(strings.TrimSuffix(dir, "/"))
	if err != nil {
		return nil
	}
	es, err := os.ReadDir(p)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range es {
		if e.Type().IsRegular() {
			out = append(out, dir+e.Name())
		}
		if len(out) >= MaxGlobMatches {
			break
		}
	}
	return out
}
