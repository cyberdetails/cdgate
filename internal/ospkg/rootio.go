package ospkg

// Root.io environments (trivy 00b7394 pkg/detector/ospkg/rootio): when any
// package's version carries Root.io's marker, Trivy scans EVERY OS package of
// the image with the Root.io driver: the distribution's own advisories merged
// with Root.io's (Root.io wins for the same CVE), looked up by source name and
// compared with the source version. Suppliers are tried in the order
// RapidFort, Root.io, Seal, so in a Root.io image Seal packages follow Root.io
// and third-party packages are dropped as usual (Root.io keeps no filter).

import (
	"regexp"
	"strings"
)

var (
	rootioDebian = regexp.MustCompile(`\.root\.io`)
	rootioAlpine = regexp.MustCompile(`-r\d007\d`)
)

// dpkgFiles are the dpkg status files Analyze reads.
func dpkgFiles(f Files) []string {
	files := []string{}
	if _, ok := f.Get("var/lib/dpkg/status"); ok {
		files = append(files, "var/lib/dpkg/status")
	}
	for _, p := range f.List(StatusDir) {
		if !strings.HasSuffix(p, ".md5sums") {
			files = append(files, p)
		}
	}
	return files
}

// rootioEcosystem is the Root.io query ecosystem when the image is a Root.io
// environment, else "". Detection looks at every installed package, third-party
// ones included (Trivy checks before filtering), by its binary version.
func rootioEcosystem(o OS, f Files) string {
	var re *regexp.Regexp
	var all []pkgInfo
	switch o.Family {
	case "debian", "ubuntu":
		re = rootioDebian
		for _, p := range dpkgFiles(f) {
			b, _ := f.Get(p)
			all = append(all, parseDpkg(b, map[string]int{}, true, false)...)
		}
	case "alpine":
		re = rootioAlpine
		for _, p := range ApkPaths {
			if b, ok := f.Get(p); ok {
				all = append(all, parseApk(b, map[string]int{}, true)...)
			}
		}
	default:
		return ""
	}
	found := false
	for _, p := range all {
		if re.MatchString(p.version) {
			found = true
			break
		}
	}
	if !found {
		return ""
	}
	switch o.Family {
	case "debian":
		major, _, _ := strings.Cut(o.Name, ".")
		return "Root.io:Debian:" + major // Trivy version.Major
	case "ubuntu":
		return "Root.io:Ubuntu:" + minorVersion(o.Name)
	}
	return "Root.io:Alpine:" + minorVersion(o.Name)
}

// minorVersion is Trivy's version.Minor (3.17.2 -> 3.17).
func minorVersion(v string) string {
	major, rest, ok := strings.Cut(v, ".")
	if !ok {
		return v
	}
	minor, _, _ := strings.Cut(rest, ".")
	return major + "." + minor
}
