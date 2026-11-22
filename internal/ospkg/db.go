package ospkg

import (
	"bufio"
	"bytes"
	"path"
	"regexp"
	"strconv"
	"strings"
)

// thirdParty are Trivy's dpkg third-party maintainer markers (dpkg.go,
// thirdPartyMaintainerPatterns / thirdPartyMaintainerExact, 00b7394). Their
// packages come from the vendor's own repository; Debian/Ubuntu advisories
// do not describe them (nginx.org's nginx is not Debian's nginx).
var thirdPartyPatterns = []string{
	"support@docker.com", "@nvidia.com", "Google Cloud CLI Authors", "sapmachine@sap.com",
	"@hashicorp.com", "@microsoft.com", "@mongodb.com", "developers@lists.mariadb.org",
	"dev@couchdb.apache.org", "info@elastic.co", "nginx-packaging@f5.com", "@konghq.com",
	"@cloudflare.com", "support@influxdb.com", "support@gitlab.com", "contact@grafana.com",
	"@datadoghq.com", "@nodesource.com", "info@tailscale.com", "@openrobotics.org", "@osrfoundation.org",
}
var thirdPartyExact = []string{"GitHub", "HashiCorp"}

// ThirdParty reports whether a dpkg Maintainer marks a vendor package.
func ThirdParty(maintainer string) bool {
	for _, e := range thirdPartyExact {
		if maintainer == e {
			return true
		}
	}
	for _, p := range thirdPartyPatterns {
		if strings.Contains(maintainer, p) {
			return true
		}
	}
	return false
}

// paragraphs splits a dpkg status file into header maps. Field names are
// case-insensitive (textproto); a continuation line extends the previous
// field; a paragraph with a malformed line is skipped (Trivy logs and goes on).
func paragraphs(b []byte, skipped map[string]int) []map[string]string {
	var out []map[string]string
	cur := map[string]string{}
	last := ""
	bad := false
	flush := func() {
		if len(cur) > 0 && !bad {
			out = append(out, cur)
		} else if bad {
			skipped["malformed_paragraph"]++
		}
		cur, last, bad = map[string]string{}, "", false
	}
	s := bufio.NewScanner(bytes.NewReader(b))
	s.Buffer(make([]byte, 64*1024), 16*1024*1024)
	for s.Scan() {
		l := strings.TrimRight(s.Text(), "\r")
		if strings.TrimSpace(l) == "" {
			flush()
			continue
		}
		if l[0] == ' ' || l[0] == '\t' {
			if last != "" {
				cur[last] += " " + strings.TrimSpace(l)
			}
			continue
		}
		k, v, ok := strings.Cut(l, ":")
		if !ok {
			bad = true
			continue
		}
		k = strings.ToLower(strings.TrimSpace(k))
		if _, dup := cur[k]; !dup { // MIMEHeader.Get returns the first value
			cur[k] = strings.TrimSpace(v)
		}
		last = k
	}
	flush()
	return out
}

var srcField = regexp.MustCompile(`^(\S*)( \((.*)\))?`)

// debVersion splits epoch:upstream-revision; ok=false when it is not a valid
// Debian version (Trivy then skips the package).
func debVersion(v string) (epoch int, upstream, revision string, ok bool) {
	v = strings.TrimSpace(v)
	if e, rest, found := strings.Cut(v, ":"); found {
		n, err := strconv.Atoi(e)
		if err != nil || n < 0 {
			return 0, "", "", false
		}
		epoch, v = n, rest
	}
	upstream = v
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		upstream, revision = v[:i], v[i+1:]
	}
	if upstream == "" || upstream[0] < '0' || upstream[0] > '9' {
		return 0, "", "", false
	}
	for _, r := range upstream {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || strings.ContainsRune(".+~-:", r)) {
			return 0, "", "", false
		}
	}
	for _, r := range revision {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || strings.ContainsRune(".+~", r)) {
			return 0, "", "", false
		}
	}
	return epoch, upstream, revision, true
}

// formatVersion is Trivy's utils.formatVersion: epoch only when non-zero.
func formatVersion(epoch int, upstream, revision string) string {
	v := upstream
	if revision != "" {
		v += "-" + revision
	}
	if epoch != 0 {
		v = strconv.Itoa(epoch) + ":" + v
	}
	return v
}

func parseDpkg(b []byte, skipped map[string]int, keepThirdParty, keepSeal bool) []pkgInfo {
	var out []pkgInfo
	for _, h := range paragraphs(b, skipped) {
		installed := true
		for _, f := range strings.Fields(h["status"]) {
			if f == "deinstall" || f == "purge" {
				installed = false
			}
		}
		if !installed {
			skipped["not_installed"]++
			continue
		}
		name, ver := h["package"], h["version"]
		if name == "" || ver == "" {
			continue
		}
		srcName, srcVer := "", ""
		if src := h["source"]; src != "" {
			m := srcField.FindStringSubmatch(src)
			srcName, srcVer = strings.TrimSpace(m[1]), strings.TrimSpace(m[3])
		}
		if srcName == "" {
			srcName = name
		}
		if !keepThirdParty && !(keepSeal && sealPkg(name, srcName)) && ThirdParty(h["maintainer"]) {
			skipped["third_party"]++
			continue
		}
		if srcVer == "" {
			srcVer = ver
		}
		if _, _, _, ok := debVersion(ver); !ok {
			skipped["invalid_version"]++
			continue
		}
		e, u, r, ok := debVersion(srcVer)
		if !ok {
			skipped["invalid_version"]++
			continue
		}
		out = append(out, pkgInfo{name: name, version: ver, srcName: srcName, srcVersion: formatVersion(e, u, r),
			arch: h["architecture"]})
	}
	return out
}

func parseApk(b []byte, skipped map[string]int, nameFallback bool) []pkgInfo {
	var out []pkgInfo
	seen := map[string]bool{}
	var name, version, origin, originVersion string
	flush := func() {
		if name == "" {
			return
		}
		switch {
		case version == "":
			skipped["invalid_version"]++
		case (origin == "" || originVersion == "") && nameFallback && !seen[name+"@"+version]:
			// Trivy wolfi/chainguard: srcName = pkg.Name when empty, installed = pkg version
			seen[name+"@"+version] = true
			out = append(out, pkgInfo{name: name, version: version, srcName: name, srcVersion: version})
		case origin == "" || originVersion == "":
			skipped["no_origin"]++ // Trivy: empty source version, package not matched
		case !seen[name+"@"+version]:
			seen[name+"@"+version] = true
			out = append(out, pkgInfo{name: name, version: version, srcName: origin, srcVersion: originVersion})
		}
		name, version, origin, originVersion = "", "", "", ""
	}
	s := bufio.NewScanner(bytes.NewReader(b))
	s.Buffer(make([]byte, 64*1024), 16*1024*1024)
	for s.Scan() {
		l := s.Text()
		if len(l) < 2 {
			flush()
			continue
		}
		switch l[:2] {
		case "P:":
			name = l[2:]
		case "V:":
			// Deliberate difference: Trivy drops a version its go-apk-version
			// tokenizer rejects; here it is sent and the server answers
			// "unverified" if it cannot compare it (never silently dropped).
			version = l[2:]
		case "o:":
			origin, originVersion = l[2:], version // Trivy: SrcVersion = the V: seen so far
		}
	}
	flush()
	return out
}

// InstalledFiles returns the paths (relative, no leading slash) that OS
// packages installed, as Trivy's dpkg and apk analyzers report them
// (SystemInstalledFiles): language packages found there are the OS
// package's, not the language registry's.
//
// dpkg: <InfoDir|StatusDir><name>.md5sums, or <name>:<arch>.md5sums, of every
// installed package; third-party packages contribute nothing, so language
// packages they bundle are still scanned (Trivy dpkg.go PostAnalyze). A
// malformed md5sums line is skipped (Trivy fails the whole dpkg analysis
// there). apk: the F: directory joined with each R: file name.
func InstalledFiles(f Files) map[string]bool {
	out := map[string]bool{}
	skipped := map[string]int{}
	lists := map[string][]byte{}
	for _, dir := range []string{InfoDir, StatusDir} {
		for _, p := range f.List(dir) {
			if strings.HasSuffix(p, ".md5sums") {
				b, _ := f.Get(p)
				lists[strings.TrimSuffix(p[len(dir):], ".md5sums")] = b
			}
		}
	}
	var status [][]byte
	if b, ok := f.Get("var/lib/dpkg/status"); ok {
		status = append(status, b)
	}
	for _, p := range f.List(StatusDir) {
		if !strings.HasSuffix(p, ".md5sums") {
			b, _ := f.Get(p)
			status = append(status, b)
		}
	}
	for _, b := range status {
		for _, pk := range parseDpkg(b, skipped, false, false) { // third-party files are never OS-owned (Trivy dpkg.go)
			l, ok := lists[pk.name]
			if !ok {
				l = lists[pk.name+":"+pk.arch]
			}
			s := bufio.NewScanner(bytes.NewReader(l))
			s.Buffer(make([]byte, 64*1024), 1024*1024)
			for s.Scan() {
				if _, file, ok := strings.Cut(s.Text(), "  "); ok {
					if file = strings.TrimLeft(file, "/"); file != "" {
						out[file] = true
					}
				}
			}
		}
	}
	rpmInstalledFiles(f, out)
	for _, p := range ApkPaths {
		b, ok := f.Get(p)
		if !ok {
			continue
		}
		dir := ""
		s := bufio.NewScanner(bytes.NewReader(b))
		s.Buffer(make([]byte, 64*1024), 16*1024*1024)
		for s.Scan() {
			l := s.Text()
			if len(l) < 2 {
				continue
			}
			switch l[:2] {
			case "F:":
				dir = l[2:]
			case "R:":
				if file := strings.TrimLeft(path.Join(dir, l[2:]), "/"); file != "" {
					out[file] = true
				}
			}
		}
	}
	return out
}
