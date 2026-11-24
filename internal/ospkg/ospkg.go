// Package ospkg finds the operating system and its installed packages in a
// container root filesystem (Debian, Ubuntu, Alpine; RPM-based distributions
// in rpm.go).
//
// The rules follow Trivy (aquasecurity/trivy 00b7394), read from its source:
//   - OS: pkg/fanal/analyzer/os/{release,debian,ubuntu,alpine}, merged with
//     pkg/fanal/types.OS.Merge (Ubuntu overrides Debian, the longest version
//     of one family wins); Ubuntu ESM from var/lib/ubuntu-advantage/status.json.
//   - Release used for matching: Debian major (12.8 -> 12), Ubuntu as is or
//     "-ESM" for the versions Trivy keeps ESM data for, Alpine minor
//     (3.21.3 -> 3.21) unless etc/apk/repositories names another release or
//     edge (pkg/detector/ospkg/{debian,ubuntu,alpine}, repo/apk).
//   - dpkg: pkg/fanal/analyzer/pkg/dpkg — var/lib/dpkg/status and status.d/,
//     "deinstall"/"purge" skipped, source package from "Source: name (ver)",
//     packages whose Maintainer is a known third-party vendor are dropped
//     (DropThirdPartyPackages: Debian's advisories do not describe them).
//   - apk: pkg/fanal/analyzer/pkg/apk — lib/apk/db/installed and (usr-merged
//     images, e.g. current Wolfi) usr/lib/apk/db/installed, source package
//     from "o:"; a package without an origin is not matched by Trivy.
//
// Packages are matched by SOURCE package and source version (Trivy
// FormatSrcVersion); the binary package names are kept for the report.
package ospkg

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/cyberdetails/cdgate/internal/model"
	"github.com/cyberdetails/cdgate/internal/rpmdb"
)

// Files is the read-only view of a root filesystem the analyzer needs.
type Files interface {
	// Get returns a regular file by its path relative to the root ("etc/os-release").
	Get(path string) ([]byte, bool)
	// List returns the regular files directly under a directory ("var/lib/dpkg/status.d/").
	List(dir string) []string
}

// Paths the analyzer reads; image and directory readers fetch only these.
var Paths = []string{
	"etc/os-release", "usr/lib/os-release", "etc/debian_version", "etc/lsb-release",
	"etc/alpine-release", "etc/apk/repositories", "var/lib/ubuntu-advantage/status.json",
	"var/lib/dpkg/status", "lib/apk/db/installed", "usr/lib/apk/db/installed",
	"etc/redhat-release", "etc/centos-release", "etc/rocky-release", "etc/almalinux-release",
	"etc/oracle-release", "etc/fedora-release", "usr/lib/fedora-release",
	"etc/system-release", "usr/lib/system-release",
}

func init() { Paths = append(Paths, append(rpmdb.Paths, RpmqaPath)...) }

// ApkPaths are Trivy's apk analyzer requiredFiles (v0.76.2), in its order:
// usr-merged images (current Wolfi, apk-tools 3) keep the database under usr/.
// Both are read when both are present; rows are per source package, so a
// package listed twice collapses into one row.
var ApkPaths = []string{"lib/apk/db/installed", "usr/lib/apk/db/installed"}

// StatusDir holds one status file per package in distroless images.
const StatusDir = "var/lib/dpkg/status.d/"

// InfoDir holds dpkg's per-package file lists (<package>.md5sums).
const InfoDir = "var/lib/dpkg/info/"

// OS is the detected operating system.
type OS struct {
	Family   string `json:"family"` // debian | ubuntu | alpine
	Name     string `json:"name"`   // full version as found (12.8, 22.04, 3.21.3)
	Extended bool   `json:"extended,omitempty"`
	Repo     string `json:"repository,omitempty"` // Alpine release from etc/apk/repositories
}

// Result of analysing a root filesystem.
type Result struct {
	OS        OS     `json:"os"`
	Ecosystem string `json:"ecosystem"` // query ecosystem: Debian:12, Ubuntu:22.04, Alpine:v3.21, Rocky Linux:9
	// Queryable is false while the CyberDetails API has no advisories for the
	// ecosystem (RPM-based for now): packages are listed, never reported clean.
	Queryable bool            `json:"queryable"`
	Packages  []model.Package `json:"packages"`
	// Unchecked are packages of a queryable ecosystem that cannot be matched
	// reliably (UncheckedReason says why); never reported clean.
	Unchecked []model.Package `json:"unchecked,omitempty"`
	Skipped   map[string]int  `json:"skipped"`
	Files     []string        `json:"files"`
}

// Read limits for OS package files, shared by the image and root filesystem
// readers: an rpm database is often tens of MB (BDB Packages), other files a
// few MB.
const (
	MaxFileBytes  = 64 << 20
	MaxRPMDBBytes = 256 << 20
)

// FileLimit is the read limit for one OS package file.
func FileLimit(p string) int64 {
	for _, r := range rpmdb.Paths {
		if p == r {
			return MaxRPMDBBytes
		}
	}
	return MaxFileBytes
}

// BuildInfoSource gives an RPM package's Red Hat build information: the
// content sets and container NVR of the image layer it was installed in.
type BuildInfoSource interface {
	RPMBuildInfo(name, version, release string) (bi *model.BuildInfo, known bool)
}

// ErrUnsupported is returned for an OS this scanner has no data for.
type ErrUnsupported struct{ Family, Name string }

func (e ErrUnsupported) Error() string {
	return fmt.Sprintf("operating system %s %s is not supported yet", e.Family, e.Name)
}

// HasOS reports whether the tree looks like a root filesystem.
func HasOS(f Files) bool {
	for _, p := range append([]string{"etc/os-release", "usr/lib/os-release", "etc/debian_version", "etc/alpine-release",
		"etc/system-release", "usr/lib/system-release"}, bottlerocketOSRelease...) {
		if _, ok := f.Get(p); ok {
			return true
		}
	}
	for _, r := range rpmReleaseFiles {
		if _, ok := f.Get(r.path); ok {
			return true
		}
	}
	return false
}

func merge(o *OS, n OS) {
	if n.Family == "" && n.Name == "" && !n.Extended {
		return
	}
	if (o.Family == "debian" || o.Family == "redhat") && n.Family != "" {
		ext := o.Extended || n.Extended
		*o = n
		o.Extended = ext
		return
	}
	if o.Family == "" {
		o.Family = n.Family
	}
	if o.Name == "" || (o.Family == n.Family && strings.HasPrefix(n.Name, o.Name+".")) {
		o.Name = n.Name
	}
	if o.Extended || n.Extended {
		o.Extended = true
	}
}

func firstLine(b []byte) (string, bool) {
	s := bufio.NewScanner(bytes.NewReader(b))
	if s.Scan() {
		return s.Text(), true
	}
	return "", false
}

func osRelease(b []byte) OS {
	var id, ver, name string
	s := bufio.NewScanner(bytes.NewReader(b))
	for s.Scan() {
		k, v, ok := strings.Cut(s.Text(), "=")
		if !ok {
			continue
		}
		v = strings.Trim(strings.TrimSpace(v), `"'`)
		switch strings.TrimSpace(k) {
		case "ID":
			id = v
		case "VERSION_ID":
			ver = v
		case "NAME":
			name = v
		}
	}
	// Trivy idToOSFamily: no "debian" (and no "amzn") ID mapping
	fam := map[string]string{"ubuntu": "ubuntu", "alpine": "alpine", "rhel": "redhat", "centos": "centos",
		"rocky": "rocky", "almalinux": "alma", "ol": "oracle", "fedora": "fedora",
		"opensuse-leap": "opensuse-leap", "opensuse": "opensuse-leap", "opensuse-tumbleweed": "opensuse-tumbleweed",
		"sles": "sles", "sle-micro": "slem", "sl-micro": "slem", "sle-micro-rancher": "slem", "photon": "photon",
		"azurelinux": "azure", "mariner": "mariner", "wolfi": "wolfi", "chainguard": "chainguard",
		"bottlerocket": "bottlerocket", "minimos": "minimos", "echo": "echo",
		"coreos": "coreos"}[id] // coreos: Trivy detects it and matches nothing; here it is unsupported
	if fam == "centos" && name == "CentOS Stream" { // refineOSFamily
		fam = "centos-stream"
	}
	if fam == "" || ver == "" {
		return OS{}
	}
	return OS{Family: fam, Name: ver}
}

var apkRepo = regexp.MustCompile(`(https*|ftp)://[0-9A-Za-z.-]+/([A-Za-z]+)/v?([0-9A-Za-z_.-]+)/`)

func repoRelease(b []byte) (string, error) {
	fam, rel := "", ""
	s := bufio.NewScanner(bytes.NewReader(b))
	for s.Scan() {
		m := apkRepo.FindStringSubmatch(s.Text())
		if len(m) != 4 {
			continue
		}
		if fam != "" && fam != m[2] {
			return "", fmt.Errorf("mixing different distributions in etc/apk/repositories")
		}
		fam = m[2]
		switch {
		case rel == "":
			rel = m[3]
		case rel == "edge" || m[3] == "edge":
			rel = "edge"
		default:
			if c, ok := cmpDotted(m[3], rel); ok && c > 0 {
				rel = m[3]
			}
		}
	}
	if fam != "alpine" {
		return "", nil
	}
	return rel, nil
}

// cmpDotted compares numeric dotted versions (3.21 vs 3.9).
func cmpDotted(a, b string) (int, bool) {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(pa) || i < len(pb); i++ {
		x, y := 0, 0
		var err error
		if i < len(pa) {
			if x, err = strconv.Atoi(pa[i]); err != nil {
				return 0, false
			}
		}
		if i < len(pb) {
			if y, err = strconv.Atoi(pb[i]); err != nil {
				return 0, false
			}
		}
		if x != y {
			if x < y {
				return -1, true
			}
			return 1, true
		}
	}
	return 0, true
}

// DetectOS merges every OS hint found in the tree.
func DetectOS(f Files) (OS, error) {
	var o OS
	for _, p := range []string{"etc/os-release", "usr/lib/os-release"} {
		if b, ok := f.Get(p); ok {
			merge(&o, osRelease(b))
			break
		}
	}
	// Trivy reads every os-release it finds and keeps the first family, in an
	// order that depends on its file walk; a tree whose sys-root os-release
	// names another family than the root one is refused, not guessed.
	for _, p := range bottlerocketOSRelease {
		if b, ok := f.Get(p); ok {
			n := osRelease(b)
			if n.Family != "" && o.Family != "" && n.Family != o.Family {
				return o, fmt.Errorf("conflicting os-release files: %s and %s (%s)", o.Family, n.Family, p)
			}
			merge(&o, n)
		}
	}
	if b, ok := f.Get("etc/debian_version"); ok {
		if l, ok := firstLine(b); ok {
			merge(&o, OS{Family: "debian", Name: l})
		}
	}
	if b, ok := f.Get("etc/lsb-release"); ok {
		ubuntu := false
		s := bufio.NewScanner(bytes.NewReader(b))
		for s.Scan() {
			l := s.Text()
			if l == "DISTRIB_ID=Ubuntu" {
				ubuntu = true
				continue
			}
			if ubuntu && strings.HasPrefix(l, "DISTRIB_RELEASE=") {
				merge(&o, OS{Family: "ubuntu", Name: strings.TrimSpace(l[16:])})
				break
			}
		}
	}
	detectRPMRelease(f, &o)
	if b, ok := f.Get("etc/alpine-release"); ok {
		if l, ok := firstLine(b); ok {
			merge(&o, OS{Family: "alpine", Name: l})
		}
	}
	if b, ok := f.Get("var/lib/ubuntu-advantage/status.json"); ok {
		var st struct {
			Services []struct {
				Name   string `json:"name"`
				Status string `json:"status"`
			} `json:"services"`
		}
		if json.Unmarshal(b, &st) == nil {
			for _, s := range st.Services {
				if s.Name == "esm-infra" && s.Status == "enabled" {
					merge(&o, OS{Family: "ubuntu", Extended: true})
				}
			}
		}
	}
	if b, ok := f.Get("etc/apk/repositories"); ok && o.Family == "alpine" {
		r, err := repoRelease(b)
		if err != nil {
			return o, err
		}
		o.Repo = r
	}
	return o, nil
}

// ubuntuESM are the releases Trivy keeps ESM advisories for (eolDates keys).
var ubuntuESM = map[string]bool{"12.04": true, "14.04": true, "16.04": true, "18.04": true, "20.04": true}

var numeric = regexp.MustCompile(`^[0-9]+$`)

// Ecosystem is the CyberDetails query ecosystem for a detected OS.
func Ecosystem(o OS) (string, error) {
	switch o.Family {
	case "wolfi":
		return "Wolfi", nil // one rolling stream (Trivy: one "wolfi" bucket)
	case "chainguard":
		return "Chainguard", nil
	case "minimos":
		return "MinimOS", nil
	case "echo":
		return "Echo", nil // one bucket, version not read (Trivy echo driver)
	case "bottlerocket":
		return "Bottlerocket", nil // one bucket, every version supported (Trivy IsSupportedVersion)
	case "debian":
		major, _, _ := strings.Cut(o.Name, ".")
		if !numeric.MatchString(major) {
			return "", ErrUnsupported{o.Family, o.Name} // testing/sid: no release data (Trivy finds nothing either)
		}
		return "Debian:" + major, nil
	case "ubuntu":
		if !regexp.MustCompile(`^[0-9]{2}\.[0-9]{2}$`).MatchString(o.Name) {
			return "", ErrUnsupported{o.Family, o.Name}
		}
		if o.Extended && ubuntuESM[o.Name] {
			return "Ubuntu:" + o.Name + "-ESM", nil
		}
		return "Ubuntu:" + o.Name, nil
	case "alpine":
		minor := o.Name
		if maj, rest, ok := strings.Cut(o.Name, "."); ok {
			m, _, _ := strings.Cut(rest, ".")
			minor = maj + "." + m
		}
		stream := minor
		if o.Repo != "" && o.Repo != minor {
			stream = o.Repo
			if strings.Count(stream, ".") > 1 {
				stream = stream[:strings.LastIndex(stream, ".")]
			}
		}
		if stream == "edge" {
			return "Alpine:edge", nil
		}
		if !regexp.MustCompile(`^[0-9]{1,2}\.[0-9]{1,2}$`).MatchString(stream) {
			return "", ErrUnsupported{o.Family, o.Name}
		}
		return "Alpine:v" + stream, nil
	}
	if IsRPM(o.Family) {
		return rpmRelease(o)
	}
	return "", ErrUnsupported{o.Family, o.Name}
}

// Analyze detects the OS and reads its package database.
func Analyze(f Files) (*Result, error) {
	o, err := DetectOS(f)
	if err != nil {
		return nil, err
	}
	return AnalyzeOS(o, f)
}

// AnalyzeOS is Analyze for an OS already known (an SBOM's, see FromSBOM).
func AnalyzeOS(o OS, f Files) (*Result, error) {
	eco, err := Ecosystem(o)
	if err != nil {
		return nil, err
	}
	res := &Result{OS: o, Ecosystem: eco, Skipped: map[string]int{}, Queryable: !IsRPM(o.Family) || queryableRPM[eco]}
	rapidfort := rapidfortEcosystem(o, f)
	if rapidfort != "" && IsRPM(o.Family) {
		files, pkgs, err := readRPM(f)
		if err != nil {
			return nil, err
		}
		if len(files) == 0 {
			return nil, fmt.Errorf("%s %s: no package database found", o.Family, o.Name)
		}
		res.Files, res.Ecosystem, res.Queryable = files, rapidfort, true
		rapidfortRPM(res, files[0], pkgs)
		rapidfortLimit(res)
		return res, nil
	}
	if IsRPM(o.Family) {
		if err := analyzeRPM(f, res); err != nil {
			return nil, err
		}
		if len(res.Files) == 0 {
			return nil, fmt.Errorf("%s %s: no package database found", o.Family, o.Name)
		}
		return res, nil
	}
	var raw []pkgInfo
	rootio := ""
	if rapidfort == "" {
		rootio = rootioEcosystem(o, f)
	}
	seal := sealFamilies[o.Family] && rootio == "" && rapidfort == ""
	switch o.Family {
	case "debian", "ubuntu", "echo":
		for _, p := range dpkgFiles(f) {
			b, _ := f.Get(p)
			// Echo's feed covers software Debian does not ship: Trivy's echo
			// driver keeps third-party packages (FilterPackages).
			raw = append(raw, parseDpkg(b, res.Skipped, o.Family == "echo" || rapidfort != "", seal)...)
			res.Files = append(res.Files, p)
		}
	case "bottlerocket":
		for _, p := range bottlerocketInventory {
			if b, ok := f.Get(p); ok {
				pk, err := parseBottlerocket(b, res.Skipped)
				if err != nil {
					return nil, err
				}
				raw = append(raw, pk...)
				res.Files = append(res.Files, p)
			}
		}
	case "alpine", "wolfi", "chainguard", "minimos":
		for _, p := range ApkPaths {
			if b, ok := f.Get(p); ok {
				// Trivy's wolfi/chainguard/minimos drivers fall back to the package name
				// when there is no origin; the alpine driver does not match it.
				raw = append(raw, parseApk(b, res.Skipped, o.Family != "alpine" || rapidfort != "")...)
				res.Files = append(res.Files, p)
			}
		}
	}
	if len(res.Files) == 0 {
		return nil, fmt.Errorf("%s %s: no package database found", o.Family, o.Name)
	}
	// One row per source package + source version; binaries listed on it.
	// A Seal package gets its own row under the Seal ecosystem.
	type key struct{ e, n, v string }
	idx := map[key]int{}
	for _, p := range raw {
		e := eco
		switch {
		case rapidfort != "":
			e = rapidfort
		case rootio != "":
			e = rootio
		case seal && sealPkg(p.name, p.srcName):
			e, _ = sealEcosystem(o.Family, "")
		}
		k := key{e, p.srcName, p.srcVersion}
		i, ok := idx[k]
		if !ok {
			i = len(res.Packages)
			idx[k] = i
			res.Packages = append(res.Packages, model.Package{Ecosystem: e, Name: p.srcName,
				Version: p.srcVersion, Source: res.Files[0]})
		}
		if !contains(res.Packages[i].Binaries, p.name) {
			res.Packages[i].Binaries = append(res.Packages[i].Binaries, p.name)
		}
	}
	for i := range res.Packages {
		sort.Strings(res.Packages[i].Binaries)
	}
	sort.Slice(res.Packages, func(i, j int) bool {
		a, b := res.Packages[i], res.Packages[j]
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.Version < b.Version
	})
	if rapidfort != "" {
		rapidfortLimit(res)
	}
	return res, nil
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

type pkgInfo struct {
	name, version, srcName, srcVersion string
	arch                               string // dpkg Architecture (md5sums may be named name:arch)
}
