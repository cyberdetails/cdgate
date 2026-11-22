package parse

// Development-dependency detection for lockfiles that do not record it.
//
// yarn.lock, pnpm-lock.yaml (v9) and poetry.lock do not say which packages
// are development-only; the manifest (package.json / the lockfile's
// importers / pyproject.toml) does, and the lockfile's dependency graph tells
// what each root pulls in. The rules below follow Trivy's implementation so
// that `cdgate scan` and `trivy fs` report the same package set by default
// (aquasecurity/trivy: pkg/fanal/analyzer/language/nodejs/yarn/yarn.go,
// pkg/dependency/parser/nodejs/pnpm/parse.go parseV9,
// pkg/fanal/analyzer/language/python/poetry/poetry.go; read 2026-11-18).

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/ferhatcil/cdgate/internal/model"
)

const (
	stUnknown = iota
	stDev
	stProd
)

// --- package.json --------------------------------------------------------

type pkgJSON struct {
	Dependencies         map[string]string `json:"dependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	Workspaces           json.RawMessage   `json:"workspaces"`
}

func (p pkgJSON) workspaces() []string {
	var list []string
	if json.Unmarshal(p.Workspaces, &list) == nil {
		return list
	}
	var obj struct {
		Packages []string `json:"packages"`
	}
	if json.Unmarshal(p.Workspaces, &obj) == nil {
		return obj.Packages
	}
	return nil
}

type manifest struct {
	prod, dev map[string]string
}

// npmManifests returns the root package.json and every workspace manifest
// (Trivy: parsePackageJSON + traverseWorkspaces). ok=false: no package.json.
func npmManifests(f Files) ([]manifest, bool) {
	if f == nil {
		return nil, false
	}
	data, err := f.Read("package.json")
	if err != nil {
		return nil, false
	}
	var root pkgJSON
	if json.Unmarshal(data, &root) != nil {
		return nil, false
	}
	out := []manifest{toManifest(root)}
	seen := map[string]bool{}
	for _, pattern := range root.workspaces() {
		dirs, err := f.Glob(pattern)
		if err != nil {
			continue
		}
		for _, d := range dirs {
			if seen[d] {
				continue
			}
			seen[d] = true
			b, err := f.Read(path.Join(d, "package.json"))
			if err != nil {
				continue
			}
			var w pkgJSON
			if json.Unmarshal(b, &w) == nil {
				out = append(out, toManifest(w))
			}
		}
	}
	return out, true
}

func toManifest(p pkgJSON) manifest {
	prod := map[string]string{}
	for k, v := range p.Dependencies {
		prod[k] = v
	}
	for k, v := range p.OptionalDependencies {
		prod[k] = v
	}
	return manifest{prod: prod, dev: p.DevDependencies}
}

// --- yarn.lock (v1 and berry) ---------------------------------------------
//
// Trivy's yarn parser (pkg/dependency/parser/nodejs/yarn/parse.go): the
// protocol is stripped from patterns ("lodash@npm:^4" -> "lodash@^4"), blocks
// with any protocol other than npm (workspace, patch, file, link, portal,
// git, ...) are skipped entirely, and only the `dependencies:` block forms
// the graph (not optionalDependencies).

var (
	yarnPattern = regexp.MustCompile(`^\s?\\?"?(\S+?)@(?:(\S+?):)?(.+?)\\?"?:?$`)
	yarnDepLine = regexp.MustCompile(`^\s{4,}"?(.+?)"?:?\s"?(?:(\S+?):)?([^"]+)"?`)
	yarnAlias   = regexp.MustCompile(`^npm:((?:@[^/]+/)?[^@]+)@(.+)$`)
)

type yarnEntry struct {
	name, version string
	patterns      map[string]bool // name@range, protocol stripped
	deps          []string        // name@range
}

func readYarnEntries(r io.Reader) ([]yarnEntry, error) {
	s := lines(r)
	var out []yarnEntry
	var cur *yarnEntry
	skip, inDeps := false, false
	for s.Scan() {
		raw := s.Text()
		if raw == "" {
			continue
		}
		if raw[0] == '#' {
			continue
		}
		indent := len(raw) - len(strings.TrimLeft(raw, " "))
		if indent == 0 {
			cur, skip, inDeps = nil, false, false
			line := strings.TrimPrefix(strings.TrimSpace(raw), "\"")
			if strings.HasPrefix(line, "__metadata") {
				skip = true
				continue
			}
			parts := strings.Split(line, ", ")
			m := yarnPattern.FindStringSubmatch(parts[0])
			if m == nil {
				skip = true
				continue
			}
			if proto := m[2]; proto != "" && proto != "npm" {
				skip = true // workspace / patch / git / file / ...: not a registry package
				continue
			}
			// Alias "esbuild@npm:esbuild-wasm@^0.23.0": the installed package is
			// esbuild-wasm (Trivy reports it so; advisories are filed under it).
			// Patterns stay keyed by the alias, as dependency lines refer to it.
			name := m[1]
			if am := yarnAlias.FindStringSubmatch("npm:" + m[3]); m[2] == "npm" && am != nil {
				name = am[1]
			}
			e := yarnEntry{name: name, patterns: map[string]bool{}}
			for _, sp := range parts {
				if pm := yarnPattern.FindStringSubmatch(strings.TrimPrefix(strings.TrimSpace(sp), "\"")); pm != nil {
					e.patterns[pm[1]+"@"+pm[3]] = true
				}
			}
			out = append(out, e)
			cur = &out[len(out)-1]
			continue
		}
		if cur == nil || skip {
			continue
		}
		t := strings.TrimPrefix(strings.TrimSpace(raw), "\"")
		if indent == 2 {
			inDeps = false
			switch {
			case strings.HasPrefix(t, "version"):
				f := strings.Fields(strings.NewReplacer(":", " ", "\"", " ").Replace(t))
				if len(f) >= 2 {
					cur.version = f[1]
				}
			case strings.HasPrefix(t, "dependencies:"):
				inDeps = true
			}
			continue
		}
		if inDeps {
			m := yarnDepLine.FindStringSubmatch(raw)
			if m == nil {
				inDeps = false
				continue
			}
			if proto := m[2]; proto != "" && proto != "npm" {
				continue
			}
			cur.deps = append(cur.deps, m[1]+"@"+m[3])
		}
	}
	return out, s.Err()
}

func parseYarnLock(r io.Reader, opt Options) ([]model.Package, error) {
	entries, err := readYarnEntries(r)
	if err != nil {
		return nil, fmt.Errorf("yarn.lock: %w", err)
	}
	byPattern := map[string]int{}
	byName := map[string][]int{}
	for i, e := range entries {
		for p := range e.patterns {
			byPattern[p] = i
		}
		byName[e.name] = append(byName[e.name], i)
	}
	children := make([][]int, len(entries))
	for i, e := range entries {
		for _, d := range e.deps {
			if j, ok := byPattern[d]; ok {
				children[i] = append(children[i], j)
			}
		}
	}
	// Direct dependencies of a manifest: every installed version whose
	// pattern matches the constraint exactly, or whose version satisfies it
	// (Trivy walkDependencies; several versions can match one constraint).
	matchDirect := func(name, constraint string) []int {
		if m := yarnAlias.FindStringSubmatch(constraint); m != nil {
			name, constraint = m[1], m[2]
		}
		var ids []int
		for _, i := range byName[name] {
			if entries[i].patterns[name+"@"+constraint] {
				ids = append(ids, i)
				continue
			}
			if ok, valid := npmSatisfies(entries[i].version, constraint); valid && ok {
				ids = append(ids, i)
			}
		}
		return ids
	}
	state := make([]int, len(entries))
	direct := make([]bool, len(entries))
	if roots, ok := npmManifests(opt.Files); ok {
		for _, m := range roots {
			// Dev first, then prod, so prod wins (Trivy resolveDependencies).
			walkRoots(m.dev, stDev, matchDirect, children, state, direct)
			walkRoots(m.prod, stProd, matchDirect, children, state, direct)
		}
	}
	var out []model.Package
	seen := map[string]bool{}
	for i, e := range entries {
		if (state[i] == stDev && !opt.IncludeDev) || seen[e.name+"@"+e.version] {
			continue
		}
		seen[e.name+"@"+e.version] = true
		if p, ok := pkg(e.name, e.version, direct[i]); ok {
			out = append(out, p)
		}
	}
	return out, nil
}

// walkRoots marks the packages reachable from direct dependencies (Trivy
// walkDependencies + walkIndirectDependencies): a node already marked prod is
// never downgraded; children inherit the parent's resulting state.
func walkRoots(deps map[string]string, st int, lookup func(string, string) []int,
	children [][]int, state []int, direct []bool) {
	names := make([]string, 0, len(deps))
	for n := range deps {
		names = append(names, n)
	}
	sort.Strings(names)
	seen := map[int]bool{}
	var walk func(i int)
	walk = func(i int) {
		for _, c := range children[i] {
			if seen[c] {
				continue
			}
			seen[c] = true
			if state[c] == stUnknown || state[c] == stDev {
				state[c] = state[i]
			}
			walk(c)
		}
	}
	for _, n := range names {
		for _, i := range lookup(n, deps[n]) {
			if state[i] == stUnknown || state[i] == stDev {
				state[i] = st
			}
			direct[i] = true
			seen[i] = true
			walk(i)
		}
	}
}

// --- pnpm-lock.yaml v9 -------------------------------------------------------

// ynode is a minimal block-YAML mapping: enough for pnpm's machine-written
// lockfile (nested mappings of scalars). Sequences and flow collections are
// kept as raw scalar text; nothing is ever evaluated.
type ynode struct {
	val  string
	kids map[string]*ynode
	keys []string
}

func (n *ynode) get(k string) *ynode {
	if n == nil {
		return nil
	}
	return n.kids[k]
}

func yamlKey(t string) (key, rest string, ok bool) {
	if t == "" {
		return "", "", false
	}
	if t[0] == '\'' || t[0] == '"' {
		end := strings.IndexByte(t[1:], t[0])
		if end < 0 {
			return "", "", false
		}
		key, t = t[1:1+end], t[2+end:]
		if !strings.HasPrefix(t, ":") {
			return "", "", false
		}
		return key, strings.TrimSpace(t[1:]), true
	}
	if strings.HasSuffix(t, ":") {
		return t[:len(t)-1], "", true
	}
	if i := strings.Index(t, ": "); i > 0 {
		return t[:i], strings.TrimSpace(t[i+2:]), true
	}
	return "", "", false
}

func readYAMLMap(r io.Reader) (*ynode, error) {
	s := lines(r)
	root := &ynode{kids: map[string]*ynode{}}
	type frame struct {
		indent int
		n      *ynode
	}
	stack := []frame{{-1, root}}
	for s.Scan() {
		l := s.Text()
		t := strings.TrimSpace(l)
		if t == "" || strings.HasPrefix(t, "#") || t == "---" || strings.HasPrefix(t, "- ") || t == "-" {
			continue
		}
		indent := len(l) - len(strings.TrimLeft(l, " "))
		key, rest, ok := yamlKey(t)
		if !ok {
			continue
		}
		for len(stack) > 1 && stack[len(stack)-1].indent >= indent {
			stack = stack[:len(stack)-1]
		}
		parent := stack[len(stack)-1].n
		if parent.kids == nil {
			parent.kids = map[string]*ynode{}
		}
		n := &ynode{val: unquote(rest)}
		if _, dup := parent.kids[key]; !dup {
			parent.keys = append(parent.keys, key)
		}
		parent.kids[key] = n
		if rest == "" {
			stack = append(stack, frame{indent, n})
		}
		if len(stack) > 64 {
			return nil, fmt.Errorf("pnpm-lock.yaml: nesting deeper than 64")
		}
	}
	return root, s.Err()
}

func trimPeers(v string) string {
	if i := strings.Index(v, "("); i > 0 {
		return v[:i]
	}
	return v
}

func parsePnpmV9(doc *ynode, opt Options) ([]model.Package, error) {
	directProd, directDev := map[string]bool{}, map[string]bool{}
	if imp := doc.get("importers"); imp != nil {
		for _, ik := range imp.keys {
			im := imp.kids[ik]
			for _, sec := range []struct {
				name string
				set  map[string]bool
			}{{"devDependencies", directDev}, {"dependencies", directProd}} {
				d := im.get(sec.name)
				if d == nil {
					continue
				}
				for _, n := range d.keys {
					v := d.kids[n].val
					if vn := d.kids[n].get("version"); vn != nil {
						v = vn.val
					}
					sec.set[n+"@"+trimPeers(v)] = true
				}
			}
		}
	}
	pkgs := doc.get("packages")
	snaps := doc.get("snapshots")
	if snaps == nil {
		return nil, nil
	}
	type node struct {
		name, version string
		deps          []string
		dev, direct   bool
	}
	nodes := map[string]*node{}
	for _, sk := range snaps.keys {
		name, version := pnpmKey(sk)
		if name == "" {
			continue
		}
		id := name + "@" + version
		n := &node{name: name, version: version, dev: true}
		if directDev[id] {
			n.direct = true
		}
		if directProd[id] {
			n.direct, n.dev = true, false
		}
		sn := snaps.kids[sk]
		for _, sec := range []string{"optionalDependencies", "dependencies"} {
			d := sn.get(sec)
			if d == nil {
				continue
			}
			for _, dn := range d.keys {
				dv := d.kids[dn].val
				if pkgs != nil && pkgs.get(dn+"@"+trimPeers(dv)) == nil {
					continue // not installed (Trivy checks the packages section)
				}
				n.deps = append(n.deps, dn+"@"+dv)
			}
		}
		nodes[sk] = n
	}
	visited := map[string]bool{}
	var mark func(k string)
	mark = func(k string) {
		if visited[k] {
			return
		}
		n, ok := nodes[k]
		if !ok {
			return
		}
		visited[k] = true
		n.dev = false
		for _, d := range n.deps {
			mark(d)
		}
	}
	keys := make([]string, 0, len(nodes))
	for k := range nodes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if !nodes[k].dev {
			mark(k)
		}
	}
	var out []model.Package
	seen := map[string]bool{}
	for _, k := range keys {
		n := nodes[k]
		id := n.name + "@" + n.version
		if (n.dev && !opt.IncludeDev) || seen[id] {
			continue
		}
		seen[id] = true
		if p, ok := pkg(n.name, n.version, n.direct); ok {
			out = append(out, p)
		}
	}
	return out, nil
}

// --- poetry.lock + pyproject.toml --------------------------------------------

var pyNorm = regexp.MustCompile(`[-_.]+`)

func normPy(n string) string { return strings.ToLower(pyNorm.ReplaceAllString(n, "-")) }

type poetryLockFile struct {
	Package []struct {
		Name         string         `toml:"name"`
		Version      string         `toml:"version"`
		Category     string         `toml:"category"`
		Groups       []string       `toml:"groups"`
		Dependencies map[string]any `toml:"dependencies"`
	} `toml:"package"`
}

type pyprojectFile struct {
	Project struct {
		Dependencies         []string            `toml:"dependencies"`
		OptionalDependencies map[string][]string `toml:"optional-dependencies"`
	} `toml:"project"`
	Tool struct {
		Poetry struct {
			Dependencies map[string]any `toml:"dependencies"`
		} `toml:"poetry"`
	} `toml:"tool"`
}

var pep508Name = strings.NewReplacer(">", " ", "<", " ", "=", " ", "(", " ", "[", " ", "~", " ", "!", " ", ";", " ")

// mainDeps is Trivy's PyProject.MainDeps: PEP 621 [project] dependencies and
// optional-dependencies if present, else [tool.poetry.dependencies].
func mainDeps(pp pyprojectFile) map[string]bool {
	out := map[string]bool{}
	if pp.Project.Dependencies != nil || pp.Project.OptionalDependencies != nil {
		all := append([]string{}, pp.Project.Dependencies...)
		for _, extra := range pp.Project.OptionalDependencies {
			all = append(all, extra...)
		}
		for _, d := range all {
			if f := strings.Fields(pep508Name.Replace(d)); len(f) > 0 {
				out[normPy(f[0])] = true
			}
		}
		return out
	}
	for n := range pp.Tool.Poetry.Dependencies {
		out[normPy(n)] = true
	}
	return out
}

func parsePoetryLock(r io.Reader, opt Options) ([]model.Package, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	var lf poetryLockFile
	if _, err := toml.NewDecoder(bytes.NewReader(data)).Decode(&lf); err != nil {
		return nil, fmt.Errorf("poetry.lock: %w", err)
	}
	type node struct {
		name, version string
		deps          []string
		dev           bool
	}
	nodes := make([]node, 0, len(lf.Package))
	byName := map[string][]int{}
	for _, p := range lf.Package {
		dev := p.Category == "dev"
		if len(p.Groups) > 0 {
			main := false
			for _, g := range p.Groups {
				main = main || g == "main"
			}
			dev = dev || !main
		}
		n := node{name: p.Name, version: p.Version, dev: dev}
		for d := range p.Dependencies {
			n.deps = append(n.deps, normPy(d))
		}
		sort.Strings(n.deps)
		byName[normPy(p.Name)] = append(byName[normPy(p.Name)], len(nodes))
		nodes = append(nodes, n)
	}
	if opt.Files != nil {
		if b, err := opt.Files.Read("pyproject.toml"); err == nil {
			var pp pyprojectFile
			if _, err := toml.NewDecoder(bytes.NewReader(b)).Decode(&pp); err == nil {
				roots := mainDeps(pp)
				prod := map[int]bool{}
				var walk func(i int)
				walk = func(i int) {
					if prod[i] {
						return
					}
					prod[i] = true
					for _, d := range nodes[i].deps {
						// Trivy matches the dependency's constraint against the
						// installed versions; every installed version of the name
						// is taken here (a superset: more prod, never less).
						for _, j := range byName[d] {
							walk(j)
						}
					}
				}
				for i := range nodes {
					if roots[normPy(nodes[i].name)] {
						walk(i)
					}
				}
				for i := range nodes {
					nodes[i].dev = !prod[i] || nodes[i].dev
				}
			}
		}
	}
	var out []model.Package
	for _, n := range nodes {
		if n.dev && !opt.IncludeDev {
			continue
		}
		if p, ok := pkg(n.name, n.version, false); ok {
			out = append(out, p)
		}
	}
	return out, nil
}

func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && (s[0] == '"' || s[0] == '\'') && s[len(s)-1] == s[0] {
		return s[1 : len(s)-1]
	}
	return s
}
