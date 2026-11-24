package parse

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/cyberdetails/cdgate/internal/model"
)

// --- requirements.txt: only exact pins (== / ===) are packages ---
//
// An unpinned line (`requests>=2.0`) has no single installed version; it is
// not guessed. Use a lockfile or `pip freeze` output for full coverage.

var reqLine = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*===?\s*([^\s;#]+)`)

func parseRequirements(r io.Reader, _ Options) ([]model.Package, error) {
	s := lines(r)
	var out []model.Package
	for s.Scan() {
		l := strings.TrimSpace(s.Text())
		if i := strings.Index(l, " #"); i >= 0 {
			l = strings.TrimSpace(l[:i])
		}
		if l == "" || strings.HasPrefix(l, "#") || strings.HasPrefix(l, "-") {
			continue // comments, -r/-c/-e/--hash options
		}
		m := reqLine.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		if p, ok := pkg(m[1], m[3], true); ok {
			out = append(out, p)
		}
	}
	return out, s.Err()
}

// --- TOML [[package]] blocks: Cargo.lock and poetry.lock ---
//
// Both files are machine-written with one `key = "value"` per line inside
// `[[package]]` tables, so a line reader is exact for the fields we need and
// avoids a TOML dependency.

var tomlKV = regexp.MustCompile(`^([A-Za-z_-]+)\s*=\s*"((?:[^"\\]|\\.)*)"\s*$`)

type tomlPkg struct{ name, version, source, category string }

func tomlPackages(r io.Reader) ([]tomlPkg, error) {
	s := lines(r)
	var out []tomlPkg
	var cur *tomlPkg
	for s.Scan() {
		l := strings.TrimSpace(s.Text())
		switch {
		case l == "[[package]]":
			out = append(out, tomlPkg{})
			cur = &out[len(out)-1]
			continue
		case strings.HasPrefix(l, "["):
			cur = nil // another table ([package.dependencies], [metadata])
			continue
		}
		if cur == nil {
			continue
		}
		if m := tomlKV.FindStringSubmatch(l); m != nil {
			switch m[1] {
			case "name":
				cur.name = m[2]
			case "version":
				cur.version = m[2]
			case "source":
				cur.source = m[2]
			case "category":
				cur.category = m[2]
			}
		}
	}
	return out, s.Err()
}

func parseCargoLock(r io.Reader, opt Options) ([]model.Package, error) {
	ps, err := tomlPackages(r)
	if err != nil {
		return nil, fmt.Errorf("Cargo.lock: %w", err)
	}
	var out []model.Package
	for _, t := range ps {
		if t.source == "" {
			countLocal(opt) // a crate of this workspace: its name is not sent
			continue
		}
		if p, ok := pkg(t.name, t.version, false); ok {
			out = append(out, p)
		}
	}
	return out, nil
}

// --- go.mod ---

var goReq = regexp.MustCompile(`^([^\s]+)\s+(v[^\s]+)(\s*//\s*indirect)?`)
var goReplace = regexp.MustCompile(`^([^\s]+)(?:\s+v[^\s]+)?\s*=>\s*([^\s]+)(?:\s+(v[^\s]+))?`)

func parseGoMod(r io.Reader, _ Options) ([]model.Package, error) {
	s := lines(r)
	type req struct {
		path, version string
		direct        bool
	}
	var reqs []req
	replace := map[string][2]string{} // path -> {new path, new version ("" = local dir)}
	block := ""
	for s.Scan() {
		l := strings.TrimSpace(s.Text())
		if i := strings.Index(l, "//"); i == 0 {
			continue
		}
		switch {
		case l == ")":
			block = ""
			continue
		case strings.HasSuffix(l, "(") && (strings.HasPrefix(l, "require") || strings.HasPrefix(l, "replace")):
			block = strings.Fields(l)[0]
			continue
		case strings.HasPrefix(l, "require "):
			l, block = strings.TrimPrefix(l, "require "), "require-one"
		case strings.HasPrefix(l, "replace "):
			l, block = strings.TrimPrefix(l, "replace "), "replace-one"
		}
		switch block {
		case "require", "require-one":
			if m := goReq.FindStringSubmatch(l); m != nil {
				reqs = append(reqs, req{m[1], m[2], m[3] == ""})
			}
		case "replace", "replace-one":
			if m := goReplace.FindStringSubmatch(l); m != nil {
				replace[m[1]] = [2]string{m[2], m[3]}
			}
		}
		if block == "require-one" || block == "replace-one" {
			block = ""
		}
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	var out []model.Package
	for _, q := range reqs {
		path, version := q.path, q.version
		if rp, ok := replace[path]; ok {
			if rp[1] == "" {
				continue // replaced by a local directory: not a module version
			}
			path, version = rp[0], rp[1]
		}
		if p, ok := pkg(path, version, q.direct); ok {
			out = append(out, p)
		}
	}
	return out, nil
}

// --- Gemfile.lock: "GEM ... specs:" section, 4-space entries ---

var gemSpec = regexp.MustCompile(`^    ([A-Za-z0-9_.\-]+) \(([^)\s]+)\)$`)

func parseGemfileLock(r io.Reader, _ Options) ([]model.Package, error) {
	s := lines(r)
	var out []model.Package
	inGem, inSpecs := false, false
	for s.Scan() {
		l := s.Text()
		switch {
		case l == "GEM" || l == "GIT" || l == "PATH":
			// Trivy reads specs from all three: git- and path-sourced gems are
			// real dependencies too (raindrops, webpush in the lab corpus).
			inGem, inSpecs = true, false
			continue
		case l != "" && l[0] != ' ':
			inGem, inSpecs = false, false
			continue
		case inGem && strings.TrimSpace(l) == "specs:":
			inSpecs = true
			continue
		}
		if !inSpecs {
			continue
		}
		if m := gemSpec.FindStringSubmatch(l); m != nil {
			v := m[2]
			// Platform suffix: "nokogiri (1.15.4-x86_64-linux)" -> 1.15.4
			for _, plat := range []string{"-x86", "-arm", "-aarch64", "-java", "-universal", "-mingw", "-darwin", "-linux"} {
				if i := strings.Index(v, plat); i > 0 {
					v = v[:i]
					break
				}
			}
			if p, ok := pkg(m[1], v, false); ok {
				out = append(out, p)
			}
		}
	}
	return out, s.Err()
}

// --- gradle.lockfile: group:artifact:version=configurations ---

func parseGradleLock(r io.Reader, _ Options) ([]model.Package, error) {
	s := lines(r)
	var out []model.Package
	for s.Scan() {
		l := strings.TrimSpace(s.Text())
		if l == "" || strings.HasPrefix(l, "#") || strings.HasPrefix(l, "empty=") {
			continue
		}
		coord := l
		if i := strings.Index(l, "="); i >= 0 {
			coord = l[:i]
		}
		f := strings.Split(coord, ":")
		if len(f) != 3 {
			continue
		}
		if p, ok := pkg(f[0]+":"+f[1], f[2], false); ok {
			out = append(out, p)
		}
	}
	return out, s.Err()
}

// --- NuGet packages.config (XML) ---
//
// A DOCTYPE is rejected: Go's encoding/xml does not expand external entities,
// but a document that declares entities is not a normal packages.config.

func parsePackagesConfig(r io.Reader, opt Options) ([]model.Package, error) {
	d := xml.NewDecoder(r)
	d.Strict = true
	var out []model.Package
	for {
		t, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("packages.config: %w", err)
		}
		switch e := t.(type) {
		case xml.Directive:
			return nil, fmt.Errorf("packages.config: DOCTYPE/entity declarations are not accepted")
		case xml.StartElement:
			if e.Name.Local != "package" {
				continue
			}
			var id, ver, dev string
			for _, a := range e.Attr {
				switch a.Name.Local {
				case "id":
					id = a.Value
				case "version":
					ver = a.Value
				case "developmentDependency":
					dev = a.Value
				}
			}
			if strings.EqualFold(dev, "true") && !opt.IncludeDev {
				continue
			}
			if p, ok := pkg(id, ver, true); ok {
				out = append(out, p)
			}
		}
	}
	return out, nil
}

// --- yarn.lock (v1 and berry) ---

func yarnName(spec string) string {
	spec = strings.Trim(strings.TrimSpace(spec), `"`)
	start := 0
	if strings.HasPrefix(spec, "@") {
		start = 1
	}
	i := strings.Index(spec[start:], "@")
	if i < 0 {
		return ""
	}
	return spec[:start+i]
}

// --- pnpm-lock.yaml (v5, v6, v9) ---
//
// Keys under the top-level `packages:` map name the package and version:
//   v5  /lodash/4.17.21:        /@babel/core/7.0.0_peer@1:
//   v6  /lodash@4.17.21:        /@babel/core@7.0.0(peer@1):
//   v9  lodash@4.17.21:         '@babel/core@7.0.0':
// v6 marks dev-only packages with `dev: true`; v9 records that only per
// importer, so v9 packages are all included.

// v9 records dev/prod per importer and the graph under `snapshots:`
// (see devgraph.go); older lockfiles mark `dev: true` per package.
var pnpmV9 = regexp.MustCompile(`(?m)^lockfileVersion:\s*['"]?(9|[1-9][0-9])\.`)

func pnpmKey(k string) (string, string) {
	k = strings.Trim(strings.TrimSuffix(strings.TrimSpace(k), ":"), `'"`)
	k = strings.TrimPrefix(k, "/")
	// Name first: "@scope/name" is two segments, otherwise one. What follows
	// is "@version" (v6, v9) or "/version" (v5). The peer suffix "(…)" (v6, v9)
	// or "_…" (v5) may itself contain "@" and "/", so it is cut only after the
	// version has been located — splitting on the last "@" read the peer's
	// version as the package's (found by TestPnpmLock).
	var name, rest string
	if strings.HasPrefix(k, "@") {
		i := strings.Index(k, "/")
		if i < 0 {
			return "", ""
		}
		j := strings.IndexAny(k[i+1:], "@/")
		if j < 0 {
			return "", ""
		}
		name, rest = k[:i+1+j], k[i+1+j:]
	} else {
		j := strings.IndexAny(k, "@/")
		if j <= 0 {
			return "", ""
		}
		name, rest = k[:j], k[j:]
	}
	v := rest[1:]
	if i := strings.IndexAny(v, "(_"); i > 0 {
		v = v[:i]
	}
	if v == "" || strings.ContainsAny(v, ":/") {
		return "", "" // tarball / git / link dependency, not a registry version
	}
	return name, v
}

func parsePnpmLock(r io.Reader, opt Options) ([]model.Package, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	if pnpmV9.Match(data) {
		doc, err := readYAMLMap(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		return parsePnpmV9(doc, opt)
	}
	s := lines(bytes.NewReader(data))
	var out []model.Package
	inPkgs := false
	var cur *model.Package
	var curDev bool
	flush := func() {
		if cur != nil && (!curDev || opt.IncludeDev) {
			out = append(out, *cur)
		}
		cur, curDev = nil, false
	}
	for s.Scan() {
		l := s.Text()
		if l == "" {
			continue
		}
		if l[0] != ' ' {
			flush()
			inPkgs = strings.TrimSpace(l) == "packages:"
			continue
		}
		if !inPkgs {
			continue
		}
		if strings.HasPrefix(l, "  ") && !strings.HasPrefix(l, "   ") && strings.HasSuffix(strings.TrimSpace(l), ":") {
			flush()
			n, v := pnpmKey(l)
			if p, ok := pkg(n, v, false); ok {
				cur = &p
			}
			continue
		}
		if cur != nil && strings.TrimSpace(l) == "dev: true" {
			curDev = true
		}
	}
	flush()
	return out, s.Err()
}
