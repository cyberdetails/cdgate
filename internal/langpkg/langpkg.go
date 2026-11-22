// Package langpkg reads language packages that are installed in an image or
// root filesystem (as opposed to lockfiles in a source tree).
//
// The rules follow Trivy's "individual package" analyzers, which are the ones
// `trivy image` and `trivy rootfs` run (lockfile analyzers are disabled there:
// pkg/commands/artifact/run.go, 00b7394):
//
//	node-pkg        any package.json with a valid name and a version
//	python-pkg      METADATA under a *.dist-info path, *.egg-info, *.egg-info/PKG-INFO,
//	                *.egg-info/METADATA, EGG-INFO/PKG-INFO
//	python-egg      *.egg (zip) containing EGG-INFO/PKG-INFO
//	gemspec         .*/specifications/.+\.gemspec
//	composer-vendor installed.json (same reader as composer.lock)
//	gobinary        executable files carrying Go build information
//
// Files installed by the OS package manager are dropped (Trivy's
// SystemFileFilteringPostHandler): Debian's python3-yaml ships a dist-info
// whose version is Debian's, and matching it against PyPI advisories would
// produce false positives.
//
// Every input is untrusted: nothing is executed, sizes are capped by the
// caller, and malformed files are reported as skipped, never fatal.
package langpkg

import (
	"archive/zip"
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/textproto"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/ferhatcil/cdgate/internal/model"
	"github.com/ferhatcil/cdgate/internal/parse"
	"github.com/ferhatcil/cdgate/internal/sbom"
)

// Kind is a bit set: one file can match more than one analyzer.
type Kind uint16

const (
	NodePkg Kind = 1 << iota
	PythonPkg
	PythonEgg
	GemSpec
	ComposerVendor
	GoExe // any executable: Go build information and cargo-auditable data
	ImageLock
	// Sibling is a file a reader consults next to its own (Julia's
	// Project.toml); kept, never parsed on its own.
	Sibling
	// CondaMeta: a conda environment's package record. Trivy lists these
	// and matches none of them ("supported for SBOM, not for vulnerability
	// scanning", pkg/detector/library/driver.go); neither does any advisory
	// source here, so they are reported unchecked, never clean.
	CondaMeta
	// SBOMFile: a CycloneDX or SPDX document in the image (Trivy's sbom
	// analyzer: .spdx, .spdx.json, .cdx, .cdx.json, not under .dist-info/sboms/).
	SBOMFile
)

// Metadata is every kind read from file contents (all but GoExe).
const Metadata = NodePkg | PythonPkg | PythonEgg | GemSpec | ComposerVendor | ImageLock | Sibling | CondaMeta | SBOMFile

var eggFiles = []string{"EGG-INFO/PKG-INFO", ".egg-info", ".egg-info/PKG-INFO", ".egg-info/METADATA"}

// Trivy conda/meta fileRegex, unanchored: environments only (not the base
// installation's conda-meta).
var condaMetaPath = regexp.MustCompile(`.*/envs/.+/conda-meta/.+-.+-.+\.json`)

// CondaUnchecked is why conda packages are listed unchecked.
const CondaUnchecked = "conda package: no advisory source matches conda packages (Trivy lists them without matching too); Python packages of the environment are checked from their own metadata"

// Trivy: regexp.MustCompile(`.*/specifications/.+\.gemspec`), unanchored.
var gemspecPath = regexp.MustCompile(`.*/specifications/.+\.gemspec`)

func isEggFile(p string) bool {
	for _, s := range eggFiles {
		if strings.HasSuffix(p, s) {
			return true
		}
	}
	return false
}

// isSBOMFile: Trivy sbomAnalyzer.Required (suffixes are case-sensitive).
func isSBOMFile(p string) bool {
	if strings.Contains(p, ".dist-info/sboms/") {
		return false
	}
	for _, suf := range []string{".spdx", ".spdx.json", ".cdx", ".cdx.json"} {
		if strings.HasSuffix(p, suf) {
			return true
		}
	}
	return false
}

// isImageLock: the dependency files Trivy still reads in image and rootfs
// mode, where only lock-file analyzers are disabled (trivy 00b7394
// analyzer.TypeLockfiles): cargo, nuget, dotnet-core, packages-props, julia.
func isImageLock(base string) bool {
	switch base {
	case "Cargo.lock", "packages.lock.json", "packages.config", "Manifest.toml":
		return true
	}
	return strings.HasSuffix(base, ".deps.json") || parse.IsPackagesProps(base)
}

// Classify says which analyzers want a regular file. p is a cleaned slash
// path relative to the root; perm is the file's permission bits.
func Classify(p string, perm int64) Kind {
	var k Kind
	base := path.Base(p)
	if base == "package.json" {
		k |= NodePkg
	}
	if (strings.Contains(p, ".dist-info") && base == "METADATA") || isEggFile(p) {
		k |= PythonPkg
	}
	if path.Ext(p) == ".egg" {
		k |= PythonEgg
	}
	if gemspecPath.MatchString(p) {
		k |= GemSpec
	}
	if base == "installed.json" {
		k |= ComposerVendor
	}
	if isImageLock(base) {
		k |= ImageLock
	}
	if base == "Project.toml" {
		k |= Sibling
	}
	if condaMetaPath.MatchString(p) {
		k |= CondaMeta
	}
	if isSBOMFile(p) {
		k |= SBOMFile
	}
	if perm&0o111 != 0 || path.Ext(p) == ".exe" {
		k |= GoExe
	}
	return k
}

// Ecosystem names sent to the API.
var ecosystem = map[Kind]string{
	NodePkg: "npm", PythonPkg: "PyPI", PythonEgg: "PyPI", GemSpec: "RubyGems",
	ComposerVendor: "Packagist", GoExe: "Go", rustExe: "crates.io",
}

// rustExe is the ecosystem key of cargo-auditable packages (not a file kind).
const rustExe = Kind(1 << 15)

// Source is what the analysis reads: kept metadata files and the build
// information of Go executables.
type Source interface {
	// Metadata returns the kept files, by path; caller must not modify them.
	Metadata() map[string][]byte
	// GoBinaries returns the Go executables, by path.
	GoBinaries() map[string]*GoBinary
	// Jars returns the Java archives, by path.
	Jars() map[string]*Jar
	// RustBinaries returns the cargo-auditable executables, by path.
	RustBinaries() map[string]*RustBinary
}

// Result of the analysis.
type Result struct {
	Packages []model.Package
	// Files are the paths packages came from, sorted.
	Files []string
	// Skipped counts reasons a candidate file produced no package.
	Skipped map[string]int
	// Unchecked are archives that could not be identified here (see jar.go).
	Unchecked []model.Package
	// LocalNotSent: see parse.Options.LocalProjects.
	LocalNotSent int
	// SBOMOS are OS packages listed by SBOM files in the image; Trivy checks
	// them with the image's OS (ospkg.FromSBOM).
	SBOMOS []sbom.OSPackage
}

// Analyze reads packages from src, dropping files in system (paths
// installed by the OS package manager, see ospkg.InstalledFiles).
func Analyze(src Source, system map[string]bool) *Result {
	res := &Result{Skipped: map[string]int{}}
	files := map[string]bool{}
	add := func(p string, k Kind, name, version string) {
		pk, ok := pkg(name, version)
		if !ok {
			res.Skipped["invalid_name_or_version"]++
			return
		}
		pk.Ecosystem, pk.Source = ecosystem[k], p
		res.Packages = append(res.Packages, pk)
		files[p] = true
	}
	md := src.Metadata()
	paths := make([]string, 0, len(md))
	for p := range md {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		if system[p] {
			res.Skipped["installed_by_os_package"]++
			continue
		}
		b := md[p]
		k := Classify(p, 0)
		if k&NodePkg != 0 {
			if n, v, err := nodePkg(b); err != nil {
				res.Skipped["node_package_json_unreadable"]++
			} else if n != "" && v != "" { // Trivy: no name/version → not a package
				add(p, NodePkg, n, v)
			}
		}
		if k&PythonPkg != 0 {
			if n, v, err := pythonMetadata(b); err != nil {
				res.Skipped["python_metadata_unreadable"]++
			} else {
				add(p, PythonPkg, n, v)
			}
		}
		if k&PythonEgg != 0 {
			if n, v, found, err := pythonEgg(b); err != nil {
				res.Skipped["python_egg_unreadable"]++
			} else if found {
				add(p, PythonEgg, n, v)
			}
		}
		if k&GemSpec != 0 {
			if n, v, err := gemspec(b); err != nil {
				res.Skipped["gemspec_unreadable"]++
			} else {
				add(p, GemSpec, n, v)
			}
		}
		if k&ImageLock != 0 {
			// The readers of `cdgate scan` (workspace crates and .NET
			// projects skipped there and here alike).
			kind, _ := parse.Lookup(p)
			pkgs, err := kind.Parse(bytes.NewReader(b), parse.Options{LocalProjects: &res.LocalNotSent,
				Files: memFiles{md: md, dir: path.Dir(p)}})
			if err != nil {
				res.Skipped[kind.Name+"_unreadable"]++
			}
			for _, c := range pkgs {
				pk, ok := pkg(c.Name, c.Version)
				if !ok {
					res.Skipped["invalid_name_or_version"]++
					continue
				}
				pk.Ecosystem, pk.Source = kind.Ecosystem, p
				res.Packages = append(res.Packages, pk)
				files[p] = true
			}
		}
		if k&CondaMeta != 0 {
			// Trivy conda/meta parser: JSON, name and version both required.
			var c struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			}
			if err := json.NewDecoder(bytes.NewReader(b)).Decode(&c); err != nil || c.Name == "" || c.Version == "" {
				res.Skipped["conda_meta_unreadable"]++
			} else if pk, ok := pkg(c.Name, c.Version); !ok {
				res.Skipped["invalid_name_or_version"]++
			} else {
				pk.Ecosystem, pk.Source, pk.UncheckedReason = "conda", p, CondaUnchecked
				res.Unchecked = append(res.Unchecked, pk)
			}
		}
		if k&SBOMFile != 0 {
			r, err := sbom.Decode(b)
			switch {
			case errors.Is(err, sbom.ErrNotRead):
				// Trivy reads it: listed, so the result is not clean.
				res.Unchecked = append(res.Unchecked, model.Package{Ecosystem: "sbom", Name: path.Base(p), Source: p,
					Version: r.Format, UncheckedReason: sbom.ReasonFormat})
			case err != nil:
				res.Skipped["sbom_unreadable"]++ // Trivy: the file fails, nothing reported
			default:
				for _, c := range r.Packages {
					pk, ok := pkg(c.Name, c.Version)
					if !ok {
						res.Skipped["invalid_name_or_version"]++
						continue
					}
					pk.Ecosystem, pk.Source = c.Ecosystem, p
					res.Packages = append(res.Packages, pk)
					files[p] = true
				}
				for _, u := range r.Unchecked {
					u.Source = p
					res.Unchecked = append(res.Unchecked, u)
				}
				res.LocalNotSent += r.LocalNotSent
				res.Skipped["sbom_component_skipped"] += r.Skipped
				res.SBOMOS = append(res.SBOMOS, r.OSPackages...)
			}
		}
		if k&ComposerVendor != 0 {
			pkgs, err := composerInstalled(b)
			if err != nil {
				res.Skipped["composer_installed_json_unreadable"]++
			}
			for _, c := range pkgs {
				add(p, ComposerVendor, c[0], c[1])
			}
		}
	}
	bins := src.GoBinaries()
	bpaths := make([]string, 0, len(bins))
	for p := range bins {
		bpaths = append(bpaths, p)
	}
	sort.Strings(bpaths)
	for _, p := range bpaths {
		if system[p] {
			res.Skipped["installed_by_os_package"]++
			continue
		}
		pkgs, mainUnknown := goBinary(bins[p])
		if mainUnknown {
			res.Skipped["go_main_module_version_unknown"]++
		}
		for _, g := range pkgs {
			add(p, GoExe, g[0], g[1])
		}
	}
	rust := src.RustBinaries()
	rpaths := make([]string, 0, len(rust))
	for p := range rust {
		rpaths = append(rpaths, p)
	}
	sort.Strings(rpaths)
	for _, p := range rpaths {
		if system[p] {
			res.Skipped["installed_by_os_package"]++
			continue
		}
		if rust[p].Err != "" {
			res.Skipped["rust_binary_unreadable"]++ // Trivy: the file fails, nothing reported
			continue
		}
		for _, c := range rust[p].Packages {
			add(p, rustExe, c[0], c[1])
		}
	}
	jars := src.Jars()
	jpaths := make([]string, 0, len(jars))
	for p := range jars {
		jpaths = append(jpaths, p)
	}
	sort.Strings(jpaths)
	for _, p := range jpaths {
		if system[p] {
			res.Skipped["installed_by_os_package"]++
			continue
		}
		j := jars[p]
		switch {
		case j.TooLarge:
			res.Unchecked = append(res.Unchecked, model.Package{Ecosystem: "Maven", Name: path.Base(p), Source: p,
				UncheckedReason: JarTooLarge})
			continue
		case j.Err != "" && len(j.Packages) == 0 && len(j.Unknown) == 0:
			res.Unchecked = append(res.Unchecked, model.Package{Ecosystem: "Maven", Name: path.Base(p), Source: p,
				UncheckedReason: JarUnreadable})
			continue
		}
		for _, jp := range j.Packages {
			pk, ok := pkg(jp.Name, jp.Version)
			if !ok {
				res.Skipped["invalid_name_or_version"]++
				continue
			}
			pk.Ecosystem, pk.Source = "Maven", jp.FilePath
			res.Packages = append(res.Packages, pk)
			files[p] = true
		}
		for _, u := range j.Unknown {
			// The hint comes from the archive (a manifest value can be 10 MiB):
			// the same bounds as a package name, else the file name.
			name := path.Base(u.FilePath)
			if h, ok := pkg(u.Hint, "-"); ok {
				name = h.Name
			}
			res.Unchecked = append(res.Unchecked, model.Package{Ecosystem: "Maven", Name: name, Source: u.FilePath,
				Version: "sha1:" + u.SHA1, UncheckedReason: JarNeedsJavaDB})
		}
		if j.NoIdentity > 0 {
			res.Skipped["java_archive_without_identity"] += j.NoIdentity
		}
	}
	for p := range files {
		res.Files = append(res.Files, p)
	}
	sort.Strings(res.Files)
	return res
}

// pkg validates a name and version: no control characters, bounded length.
func pkg(name, version string) (model.Package, bool) {
	clean := func(s string, max int) (string, bool) {
		s = strings.TrimSpace(s)
		if s == "" || len(s) > max {
			return "", false
		}
		for _, r := range s {
			if r < 0x20 || r == 0x7f {
				return "", false
			}
		}
		return s, true
	}
	n, ok1 := clean(name, 214)
	v, ok2 := clean(version, 100)
	if !ok1 || !ok2 {
		return model.Package{}, false
	}
	return model.Package{Name: n, Version: v}, true
}

// Trivy packagejson.nameRegexp.
var npmName = regexp.MustCompile(`^(@[A-Za-z0-9-._]+/)?[A-Za-z0-9-._]+$`)

func nodePkg(b []byte) (string, string, error) {
	// Same field types as Trivy's packageJSON: a dependencies map that is not
	// string→string fails the decode there too (license never fails).
	var p struct {
		Name                 string            `json:"name"`
		Version              string            `json:"version"`
		Dependencies         map[string]string `json:"dependencies"`
		OptionalDependencies map[string]string `json:"optionalDependencies"`
		DevDependencies      map[string]string `json:"devDependencies"`
	}
	if err := json.NewDecoder(bytes.NewReader(b)).Decode(&p); err != nil {
		return "", "", err
	}
	if p.Name != "" && !npmName.MatchString(p.Name) {
		return "", "", errors.New("invalid npm package name")
	}
	return p.Name, p.Version, nil
}

// pythonMetadata reads Name and Version from core metadata (RFC 822 style
// headers, Trivy's textproto reader; a protocol error after the needed keys
// still counts, as in Trivy).
func pythonMetadata(b []byte) (string, string, error) {
	h, err := textproto.NewReader(bufio.NewReader(bytes.NewReader(b))).ReadMIMEHeader()
	var pe textproto.ProtocolError
	if err != nil && err != io.EOF && !errors.As(err, &pe) {
		return "", "", err
	}
	n, v := h.Get("Name"), h.Get("Version")
	if n == "" || v == "" {
		return "", "", errors.New("name or version is empty")
	}
	return n, v, nil
}

const maxEggEntry = 1 << 20

// pythonEgg reads PKG-INFO from an .egg zip (Trivy findFileInZip with
// isEggFile: the first entry whose name has one of the egg suffixes).
func pythonEgg(b []byte) (string, string, bool, error) {
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		return "", "", false, err
	}
	for _, f := range zr.File {
		if !isEggFile(f.Name) {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return "", "", false, err
		}
		data, err := io.ReadAll(io.LimitReader(rc, maxEggEntry+1))
		rc.Close()
		if err != nil {
			return "", "", false, err
		}
		if len(data) > maxEggEntry {
			return "", "", false, errors.New("PKG-INFO too large")
		}
		n, v, err := pythonMetadata(data)
		return n, v, err == nil, err
	}
	return "", "", false, nil
}

// Trivy gemspec parser regexps (dependency/parser/ruby/gemspec).
var (
	gemNewVar  = regexp.MustCompile(`\|(?P<var>.*)\|`)
	gemName    = regexp.MustCompile(`\.name\s*=\s*(?P<name>\S+)`)
	gemVersion = regexp.MustCompile(`\.version\s*=\s*(?P<version>\S+)`)
)

func gemTrim(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(s, ".freeze")
	return strings.Trim(s, `'"`)
}

func sub(re *regexp.Regexp, line, name string) string {
	m := re.FindStringSubmatch(line)
	if m == nil {
		return ""
	}
	return m[re.SubexpIndex(name)]
}

// gemspec mirrors Trivy: after the line naming Gem::Specification.new and its
// block variable, "<var>.name" and "<var>.version" lines set the values (a
// later line overwrites an earlier one, as Trivy's loop does).
func gemspec(b []byte) (string, string, error) {
	var newVar, name, version string
	s := bufio.NewScanner(bytes.NewReader(b))
	s.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if strings.Contains(line, "Gem::Specification.new") {
			newVar = sub(gemNewVar, line, "var")
		}
		if newVar == "" {
			continue
		}
		switch {
		case strings.HasPrefix(line, newVar+".name"):
			name = gemTrim(sub(gemName, line, "name"))
		case strings.HasPrefix(line, newVar+".version"):
			version = gemTrim(sub(gemVersion, line, "version"))
		}
	}
	if err := s.Err(); err != nil {
		return "", "", err
	}
	if name == "" || version == "" {
		return "", "", errors.New("failed to parse gemspec")
	}
	return name, version, nil
}

// composerInstalled reads Composer 2's vendor/composer/installed.json with
// the composer.lock reader, as Trivy does: "packages" and "packages-dev",
// first occurrence of a name wins. Composer 1's top-level array is not an
// object and fails to decode, as in Trivy.
func composerInstalled(b []byte) ([][2]string, error) {
	var l struct {
		Packages    []struct{ Name, Version string } `json:"packages"`
		PackagesDev []struct{ Name, Version string } `json:"packages-dev"`
	}
	if err := json.NewDecoder(bytes.NewReader(b)).Decode(&l); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out [][2]string
	for _, list := range [][]struct{ Name, Version string }{l.Packages, l.PackagesDev} {
		for _, p := range list {
			if seen[p.Name] {
				continue
			}
			seen[p.Name] = true
			out = append(out, [2]string{p.Name, p.Version})
		}
	}
	return out, nil
}

// StdlibVersion is Trivy's parseStdlibVersion: "go1.22.3 X:boringcrypto" → "v1.22.3".
func StdlibVersion(goVersion string) string {
	v := strings.TrimPrefix(goVersion, "go")
	v, _, _ = strings.Cut(v, " ")
	v, _, _ = strings.Cut(v, "-X:")
	return "v" + v
}

// goBinary lists stdlib, every dependency (a replacement wins) and the main
// module with the version ReadGoBinary chose (Trivy's order: build info,
// -ldflags -X, ELF symbol, pseudo-version). Without one the main module is
// skipped and counted, as Trivy cannot match an empty version either.
func goBinary(g *GoBinary) (pkgs [][2]string, mainUnknown bool) {
	bi := g.Info
	pkgs = append(pkgs, [2]string{"stdlib", StdlibVersion(bi.GoVersion)})
	for _, d := range bi.Deps {
		if d == nil || d.Path == "" {
			continue
		}
		m := d
		if d.Replace != nil {
			m = d.Replace
		}
		if m.Version == "(devel)" || m.Version == "" {
			continue // Trivy: empty version, not matched
		}
		pkgs = append(pkgs, [2]string{m.Path, m.Version})
	}
	if bi.Main.Path != "" {
		if g.MainVersion == "" {
			mainUnknown = true
		} else {
			pkgs = append(pkgs, [2]string{bi.Main.Path, g.MainVersion})
		}
	}
	return pkgs, mainUnknown
}

// memFiles gives a reader the kept files next to its own (parse.Files).
type memFiles struct {
	md  map[string][]byte
	dir string
}

func (m memFiles) Read(rel string) ([]byte, error) {
	if b, ok := m.md[path.Join(m.dir, rel)]; ok {
		return b, nil
	}
	return nil, fs.ErrNotExist
}

// Glob is not offered in images (no reader that runs here needs it).
func (m memFiles) Glob(string) ([]string, error) { return nil, nil }
