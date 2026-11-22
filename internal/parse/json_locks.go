package parse

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/ferhatcil/cdgate/internal/model"
)

// --- npm: package-lock.json / npm-shrinkwrap.json (lockfileVersion 1-3) ---

// v2/v3 "packages" entry: dependencies are name -> version range strings.
type npmPackage struct {
	Version              string            `json:"version"`
	Dev                  bool              `json:"dev"`
	DevOptional          bool              `json:"devOptional"`
	Link                 bool              `json:"link"`
	Dependencies         map[string]string `json:"dependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
}

// v1 "dependencies" entry: dependencies are nested entries.
type npmV1 struct {
	Version      string           `json:"version"`
	Dev          bool             `json:"dev"`
	DevOptional  bool             `json:"devOptional"`
	Dependencies map[string]npmV1 `json:"dependencies"`
}

type npmLock struct {
	LockfileVersion int                   `json:"lockfileVersion"`
	Packages        map[string]npmPackage `json:"packages"`
	Dependencies    map[string]npmV1      `json:"dependencies"`
}

func parseNpmLock(r io.Reader, opt Options) ([]model.Package, error) {
	var l npmLock
	if err := json.NewDecoder(r).Decode(&l); err != nil {
		return nil, fmt.Errorf("package-lock.json: %w", err)
	}
	var out []model.Package
	if len(l.Packages) > 0 { // v2, v3
		direct := map[string]bool{}
		if root, ok := l.Packages[""]; ok {
			for _, m := range []map[string]string{root.Dependencies, root.OptionalDependencies, root.DevDependencies} {
				for n := range m {
					direct[n] = true
				}
			}
		}
		keys := make([]string, 0, len(l.Packages))
		for k := range l.Packages {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			e := l.Packages[k]
			i := strings.LastIndex(k, "node_modules/")
			if k == "" || i < 0 || e.Link {
				continue // the project itself, or a workspace link
			}
			if (e.Dev || e.DevOptional) && !opt.IncludeDev {
				continue
			}
			name := k[i+len("node_modules/"):]
			top := !strings.Contains(k[:i], "node_modules/")
			if p, ok := pkg(name, e.Version, top && direct[name]); ok {
				out = append(out, p)
			}
		}
		return out, nil
	}
	// v1: nested "dependencies"
	var walk func(m map[string]npmV1, depth int) error
	walk = func(m map[string]npmV1, depth int) error {
		if depth > 64 {
			return fmt.Errorf("package-lock.json: dependency nesting deeper than 64")
		}
		names := make([]string, 0, len(m))
		for n := range m {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			e := m[n]
			if (e.Dev || e.DevOptional) && !opt.IncludeDev {
				continue
			}
			if strings.HasPrefix(e.Version, "file:") || strings.HasPrefix(e.Version, "link:") {
				continue
			}
			if p, ok := pkg(n, e.Version, false); ok {
				out = append(out, p)
			}
			if err := walk(e.Dependencies, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(l.Dependencies, 0); err != nil {
		return nil, err
	}
	return out, nil
}

// --- Pipfile.lock ---

type pipfileEntry struct {
	Version string `json:"version"`
}

func parsePipfileLock(r io.Reader, opt Options) ([]model.Package, error) {
	var l struct {
		Default map[string]pipfileEntry `json:"default"`
		Develop map[string]pipfileEntry `json:"develop"`
	}
	if err := json.NewDecoder(r).Decode(&l); err != nil {
		return nil, fmt.Errorf("Pipfile.lock: %w", err)
	}
	var out []model.Package
	add := func(m map[string]pipfileEntry) {
		names := make([]string, 0, len(m))
		for n := range m {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			v := strings.TrimPrefix(m[n].Version, "==")
			if v == m[n].Version { // not an exact pin (git/path dependency)
				continue
			}
			if p, ok := pkg(n, v, false); ok {
				out = append(out, p)
			}
		}
	}
	add(l.Default)
	if opt.IncludeDev {
		add(l.Develop)
	}
	return out, nil
}

// --- composer.lock ---

type composerPkg struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

func parseComposerLock(r io.Reader, opt Options) ([]model.Package, error) {
	var l struct {
		Packages    []composerPkg `json:"packages"`
		PackagesDev []composerPkg `json:"packages-dev"`
	}
	if err := json.NewDecoder(r).Decode(&l); err != nil {
		return nil, fmt.Errorf("composer.lock: %w", err)
	}
	var out []model.Package
	add := func(ps []composerPkg) {
		for _, c := range ps {
			if p, ok := pkg(c.Name, c.Version, false); ok {
				out = append(out, p)
			}
		}
	}
	add(l.Packages)
	if opt.IncludeDev {
		add(l.PackagesDev)
	}
	return out, nil
}

// --- NuGet packages.lock.json ---

func parseNugetLock(r io.Reader, _ Options) ([]model.Package, error) {
	var l struct {
		Dependencies map[string]map[string]struct {
			Type     string `json:"type"`
			Resolved string `json:"resolved"`
		} `json:"dependencies"`
	}
	if err := json.NewDecoder(r).Decode(&l); err != nil {
		return nil, fmt.Errorf("packages.lock.json: %w", err)
	}
	seen := map[string]bool{}
	var out []model.Package
	frameworks := make([]string, 0, len(l.Dependencies))
	for f := range l.Dependencies {
		frameworks = append(frameworks, f)
	}
	sort.Strings(frameworks)
	for _, f := range frameworks {
		deps := l.Dependencies[f]
		names := make([]string, 0, len(deps))
		for n := range deps {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			d := deps[n]
			if strings.EqualFold(d.Type, "Project") {
				continue // another project in the solution, not a package
			}
			k := strings.ToLower(n) + "@" + d.Resolved
			if seen[k] {
				continue
			}
			seen[k] = true
			if p, ok := pkg(n, d.Resolved, strings.EqualFold(d.Type, "Direct")); ok {
				out = append(out, p)
			}
		}
	}
	return out, nil
}
