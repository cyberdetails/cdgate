// Package image reads the files the OS and installed-package analyzers need
// from a `docker save` archive, without unpacking it.
//
// Layers are applied in manifest order with OCI/Docker whiteouts
// (".wh.<name>" deletes a path, ".wh..wh..opq" empties a directory). Only the
// files the analyzers ask for are kept, in memory, under fixed caps: the OS
// paths in ospkg.Paths, dpkg's status.d and info/*.md5sums, and the
// language package metadata langpkg.Classify selects. Executables are read
// only when their first bytes are an executable format Go's debug/buildinfo
// understands, and only their Go build information is kept. Nothing is
// written to disk, links are never followed and paths that climb out of the
// root are rejected.
package image

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strings"

	"github.com/cyberdetails/cdgate/internal/buildinfo"
	"github.com/cyberdetails/cdgate/internal/langpkg"
	"github.com/cyberdetails/cdgate/internal/model"
	"github.com/cyberdetails/cdgate/internal/ospkg"
	"github.com/cyberdetails/cdgate/internal/rpmdb"
)

const (
	MaxFileBytes    = ospkg.MaxFileBytes  // one kept file (dpkg status is a few MB)
	MaxRPMDBBytes   = ospkg.MaxRPMDBBytes // one rpm package database (BDB Packages can be large)
	MaxKeptBytes    = 512 << 20           // all files kept at one time
	MaxBinaryBytes  = 256 << 20           // one executable read for Go build information
	MaxJarBytes     = 256 << 20           // one Java archive (parsed, not kept)
	MaxEntries      = 4_000_000           // tar entries across all layers
	MaxManifest     = 4 << 20
	maxOuterEntries = 100_000
)

// Image is a parsed archive: implements ospkg.Files and langpkg.Source.
type Image struct {
	files  map[string][]byte
	bins   map[string]*langpkg.GoBinary
	jars   map[string]*langpkg.Jar
	rust   map[string]*langpkg.RustBinary
	under  map[string]int // directory → number of kept paths below it
	Tags   []string
	Layers int
	// Skipped lists executables that were not inspected, with the reason.
	Skipped []string
	scratch []byte
	// execRead counts executables read in full (only executable formats are).
	execRead int
	// keptBytes is the size of the files kept now: a file replaced by a later
	// layer (an rpm database rewritten by every "dnf install") counts once.
	keptBytes int
	// Per layer, for Red Hat build information (Trivy applier
	// lookupOriginLayerForPkg/lookupBuildInfo): the packages in the rpm
	// databases written by that layer, its build information, and whether
	// its Dockerfile could not be read (the build information is unknown).
	layerPkgs      []map[rpmKey]bool
	layerBI        []*model.BuildInfo
	layerBIUnknown []bool
	pendingBI      []buildinfo.File
}

type rpmKey struct{ name, version, release string }

func (im *Image) Get(p string) ([]byte, bool) {
	b, ok := im.files[p]
	return b, ok
}

func (im *Image) List(dir string) []string {
	var out []string
	for p := range im.files {
		if strings.HasPrefix(p, dir) && !strings.Contains(p[len(dir):], "/") && p != dir {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

func (im *Image) Metadata() map[string][]byte                  { return im.files }
func (im *Image) GoBinaries() map[string]*langpkg.GoBinary     { return im.bins }
func (im *Image) Jars() map[string]*langpkg.Jar                { return im.jars }
func (im *Image) RustBinaries() map[string]*langpkg.RustBinary { return im.rust }

// ancestors calls fn for every parent directory of p ("a/b/c" → "a/b", "a").
func ancestors(p string, fn func(string)) {
	for {
		i := strings.LastIndexByte(p, '/')
		if i < 0 {
			return
		}
		p = p[:i]
		fn(p)
	}
}

func (im *Image) has(p string) bool {
	_, f := im.files[p]
	_, b := im.bins[p]
	_, j := im.jars[p]
	_, r := im.rust[p]
	return f || b || j || r
}

func (im *Image) track(p string, delta int) {
	ancestors(p, func(d string) {
		if im.under[d] += delta; im.under[d] <= 0 {
			delete(im.under, d)
		}
	})
}

// dropExact removes the entry at p itself.
func (im *Image) dropExact(p string) {
	if im.has(p) {
		im.keptBytes -= len(im.files[p])
		delete(im.files, p)
		delete(im.bins, p)
		delete(im.jars, p)
		delete(im.rust, p)
		im.track(p, -1)
	}
}

// dropBelow removes every entry under directory d.
func (im *Image) dropBelow(d string) {
	if im.under[d] == 0 {
		return
	}
	pre := d + "/"
	if d == "" || d == "." {
		pre = ""
	}
	for _, m := range []string{"files", "bins", "jars", "rust"} {
		var keys []string
		switch m {
		case "files":
			for k := range im.files {
				if strings.HasPrefix(k, pre) {
					keys = append(keys, k)
				}
			}
		case "bins":
			for k := range im.bins {
				if strings.HasPrefix(k, pre) {
					keys = append(keys, k)
				}
			}
		case "jars":
			for k := range im.jars {
				if strings.HasPrefix(k, pre) {
					keys = append(keys, k)
				}
			}
		default:
			for k := range im.rust {
				if strings.HasPrefix(k, pre) {
					keys = append(keys, k)
				}
			}
		}
		for _, k := range keys {
			im.dropExact(k)
		}
	}
}

func (im *Image) putFile(p string, b []byte) error {
	if !im.has(p) {
		im.track(p, 1)
	}
	im.keptBytes += len(b) - len(im.files[p])
	im.files[p] = b
	if im.keptBytes > MaxKeptBytes {
		return errors.New("package metadata in the image is too large")
	}
	return nil
}

func (im *Image) putJar(p string, j *langpkg.Jar) {
	if !im.has(p) {
		im.track(p, 1)
	}
	im.jars[p] = j
}

func (im *Image) putRust(p string, rb *langpkg.RustBinary) {
	if !im.has(p) {
		im.track(p, 1)
	}
	im.rust[p] = rb
}

// readExe records what Go's and cargo-auditable's readers find in an
// executable (Trivy runs both analyzers on every executable).
func (im *Image) readExe(p string, b []byte) {
	if langpkg.GoExeCandidate(b) {
		if bi := langpkg.ReadGoBinary(b); bi != nil {
			im.putBin(p, bi)
		}
	}
	if langpkg.RustExeCandidate(b) {
		if rb := langpkg.ReadRustBinary(b); rb != nil {
			im.putRust(p, rb)
		}
	}
}

func (im *Image) putBin(p string, bi *langpkg.GoBinary) {
	if !im.has(p) {
		im.track(p, 1)
	}
	im.bins[p] = bi
}

// maxJarBytes is MaxJarBytes; a variable so tests can lower it.
var maxJarBytes int64 = MaxJarBytes

// countingReader tracks the offset tar.Reader has consumed, so each outer
// entry can later be re-read with an io.SectionReader.
type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

type span struct{ off, size int64 }

// clean normalises a tar path; ok=false for a path that leaves the root.
func clean(name string) (string, bool) {
	name = strings.TrimPrefix(name, "./")
	name = strings.TrimLeft(name, "/")
	if name == "" {
		return "", false
	}
	c := path.Clean(name)
	if c == ".." || strings.HasPrefix(c, "../") || strings.Contains(c, "\x00") {
		return "", false
	}
	return c, true
}

var isRPMDB = func() map[string]bool {
	m := map[string]bool{}
	for _, p := range rpmdb.Paths {
		m[p] = true
	}
	return m
}()

var wanted = func() map[string]bool {
	m := map[string]bool{}
	for _, p := range ospkg.Paths {
		m[p] = true
	}
	return m
}()

// isWanted: files the OS analyzer reads.
func isWanted(p string) bool {
	if wanted[p] {
		return true
	}
	if strings.HasPrefix(p, ospkg.StatusDir) {
		rest := p[len(ospkg.StatusDir):]
		return rest != "" && !strings.Contains(rest, "/")
	}
	if strings.HasPrefix(p, ospkg.InfoDir) {
		rest := p[len(ospkg.InfoDir):]
		return strings.HasSuffix(rest, ".md5sums") && !strings.Contains(rest, "/")
	}
	return false
}

// Open reads a `docker save` archive.
func Open(file string) (*Image, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, errors.New("image archive must be a regular file (docker save -o image.tar)")
	}
	return OpenReader(f, st.Size())
}

// OpenReader reads a `docker save` archive from any random-access source.
func OpenReader(f io.ReaderAt, size int64) (*Image, error) {
	// Pass 1: where is each outer entry?
	cr := &countingReader{r: bufio.NewReaderSize(io.NewSectionReader(f, 0, size), 1<<20)}
	tr := tar.NewReader(cr)
	idx := map[string]span{}
	for n := 0; ; n++ {
		if n > maxOuterEntries {
			return nil, errors.New("image archive has too many entries")
		}
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("not a docker save archive: %w", err)
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		if p, ok := clean(h.Name); ok {
			idx[p] = span{cr.n, h.Size}
		}
	}
	ms, ok := idx["manifest.json"]
	if !ok {
		return nil, errors.New("manifest.json not found: expected `docker save` output")
	}
	if ms.size > MaxManifest {
		return nil, errors.New("manifest.json is too large")
	}
	raw := make([]byte, ms.size)
	if _, err := f.ReadAt(raw, ms.off); err != nil {
		return nil, fmt.Errorf("cannot read manifest.json: %w", err)
	}
	var manifest []struct {
		RepoTags []string `json:"RepoTags"`
		Layers   []string `json:"Layers"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil || len(manifest) == 0 {
		return nil, errors.New("manifest.json is not a docker save manifest")
	}
	if len(manifest) > 1 {
		return nil, errors.New("archive holds more than one image; save one image per file")
	}
	im := &Image{files: map[string][]byte{}, bins: map[string]*langpkg.GoBinary{}, jars: map[string]*langpkg.Jar{},
		rust: map[string]*langpkg.RustBinary{}, under: map[string]int{},
		Tags: manifest[0].RepoTags, Layers: len(manifest[0].Layers)}
	entries := 0
	for _, l := range manifest[0].Layers {
		lp, ok := clean(l)
		if !ok {
			return nil, fmt.Errorf("invalid layer path in manifest")
		}
		sp, ok := idx[lp]
		if !ok {
			return nil, fmt.Errorf("layer %s listed in manifest.json is missing", lp)
		}
		im.layerPkgs = append(im.layerPkgs, nil)
		im.pendingBI = nil
		if err := im.applyLayer(io.NewSectionReader(f, sp.off, sp.size), &entries); err != nil {
			return nil, fmt.Errorf("layer %s: %w", lp, err)
		}
		bi, known := buildinfo.Merge(im.pendingBI)
		im.layerBI = append(im.layerBI, bi)
		im.layerBIUnknown = append(im.layerBIUnknown, !known)
	}
	im.pendingBI = nil
	im.scratch = nil
	sort.Strings(im.Skipped)
	return im, nil
}

func (im *Image) applyLayer(sr *io.SectionReader, entries *int) error {
	var magic [2]byte
	if _, err := sr.ReadAt(magic[:], 0); err != nil && err != io.EOF {
		return err
	}
	var rd io.Reader = io.NewSectionReader(sr, 0, sr.Size())
	switch {
	case magic[0] == 0x1f && magic[1] == 0x8b:
		gz, err := gzip.NewReader(rd)
		if err != nil {
			return err
		}
		defer gz.Close()
		rd = gz
	case magic[0] == 0x28 && magic[1] == 0xb5:
		return errors.New("zstd-compressed layers are not supported yet")
	}
	tr := tar.NewReader(rd)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		*entries++
		if *entries > MaxEntries {
			return errors.New("too many files in image layers")
		}
		p, ok := clean(h.Name)
		if !ok {
			continue
		}
		dir, base := path.Split(p)
		dir = strings.TrimSuffix(dir, "/")
		if base == ".wh..wh..opq" {
			im.dropBelow(dir)
			continue
		}
		if strings.HasPrefix(base, ".wh.") {
			t := path.Join(dir, base[len(".wh."):])
			im.dropExact(t)
			im.dropBelow(t)
			continue
		}
		if h.Typeflag == tar.TypeDir {
			im.dropExact(p) // a file replaced by a directory; its children stay
			continue
		}
		// Any other entry replaces what was at p, including a whole directory.
		im.dropExact(p)
		im.dropBelow(p)
		if h.Typeflag != tar.TypeReg {
			continue // links are never followed
		}
		if buildinfo.IsContentManifest(p) || buildinfo.IsDockerfile(p) {
			// Read per layer, never kept: a later layer's file does not
			// replace this layer's build information (Trivy analyses layers
			// one by one).
			if h.Size > buildinfo.MaxFileBytes {
				im.pendingBI = append(im.pendingBI, buildinfo.File{Path: p, TooLarge: true})
				continue
			}
			b, err := io.ReadAll(io.LimitReader(tr, buildinfo.MaxFileBytes+1))
			if err != nil {
				return err
			}
			im.pendingBI = append(im.pendingBI, buildinfo.File{Path: p, B: b})
			continue
		}
		if langpkg.IsJar(p) {
			// Parsed now, only the result kept (an archive can be large).
			if h.Size > maxJarBytes {
				im.putJar(p, &langpkg.Jar{TooLarge: true})
				continue
			}
			if cap(im.scratch) < int(h.Size) {
				im.scratch = make([]byte, 0, h.Size)
			}
			buf := bytes.NewBuffer(im.scratch[:0])
			if _, err := io.Copy(buf, io.LimitReader(tr, maxJarBytes)); err != nil {
				return err
			}
			im.putJar(p, langpkg.ReadJar(buf.Bytes(), p))
			im.scratch = buf.Bytes()[:0]
			continue
		}
		kinds := langpkg.Classify(p, h.Mode&0o777)
		keep := isWanted(p) || kinds&langpkg.Metadata != 0
		if !keep && kinds&langpkg.GoExe == 0 {
			continue
		}
		var b []byte
		if keep {
			limit := int64(MaxFileBytes)
			if isRPMDB[p] {
				limit = MaxRPMDBBytes
			}
			if h.Size > limit {
				return fmt.Errorf("%s is larger than %d MiB", p, limit>>20)
			}
			if b, err = io.ReadAll(io.LimitReader(tr, limit+1)); err != nil {
				return err
			}
			if err := im.putFile(p, b); err != nil {
				return err
			}
			if isRPMDB[p] {
				im.addLayerRPM(b)
			}
			if kinds&langpkg.GoExe != 0 {
				im.readExe(p, b)
			}
			continue
		}
		// Executable: look at the format first, read the rest only if Go's
		// build-info reader could recognise it.
		var ident [16]byte
		n, err := io.ReadFull(tr, ident[:])
		if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
			return err
		}
		if !langpkg.GoExeCandidate(ident[:n]) && !langpkg.RustExeCandidate(ident[:n]) {
			continue
		}
		if h.Size > MaxBinaryBytes {
			im.Skipped = append(im.Skipped, fmt.Sprintf("%s: executable larger than %d MiB, Go and Rust build information not read", p, MaxBinaryBytes>>20))
			continue
		}
		if cap(im.scratch) < int(h.Size) {
			im.scratch = make([]byte, 0, h.Size)
		}
		buf := bytes.NewBuffer(append(im.scratch[:0], ident[:n]...))
		if _, err := io.Copy(buf, io.LimitReader(tr, MaxBinaryBytes)); err != nil {
			return err
		}
		im.scratch = buf.Bytes()[:0]
		im.execRead++
		im.readExe(p, buf.Bytes())
	}
}

// addLayerRPM records the packages of an rpm database written by the current
// layer. A database that does not parse adds nothing (Trivy skips a failed
// analyzer); the final database is parsed again by the OS analyzer.
func (im *Image) addLayerRPM(b []byte) {
	pkgs, err := rpmdb.Parse(b)
	if err != nil {
		return
	}
	cur := len(im.layerPkgs) - 1
	if im.layerPkgs[cur] == nil {
		im.layerPkgs[cur] = map[rpmKey]bool{}
	}
	for _, p := range pkgs {
		im.layerPkgs[cur][rpmKey{p.Name, p.Version, p.Release}] = true
	}
}

// RPMBuildInfo is the build information of the layer a package came from:
// Trivy's lookupOriginLayerForPkg (the first layer whose rpm database holds
// the name, version and release) and lookupBuildInfo (that layer's, else the
// second layer's for the base layer, else the nearest earlier layer's).
// known is false when the answer depends on a Dockerfile this scanner could
// not read.
func (im *Image) RPMBuildInfo(name, version, release string) (bi *model.BuildInfo, known bool) {
	k := rpmKey{name, version, release}
	for i, pkgs := range im.layerPkgs {
		if pkgs[k] {
			return im.lookupBuildInfo(i)
		}
	}
	return nil, true
}

func (im *Image) lookupBuildInfo(i int) (*model.BuildInfo, bool) {
	at := func(j int) (*model.BuildInfo, bool) { return im.layerBI[j], !im.layerBIUnknown[j] }
	if im.layerBI[i] != nil || im.layerBIUnknown[i] {
		return at(i)
	}
	if i == 0 {
		if len(im.layerBI) > 1 {
			return at(1)
		}
		return nil, true
	}
	for j := i - 1; j >= 0; j-- {
		if im.layerBI[j] != nil || im.layerBIUnknown[j] {
			return at(j)
		}
	}
	return nil, true
}
