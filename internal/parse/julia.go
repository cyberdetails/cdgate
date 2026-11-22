package parse

// Julia Manifest.toml (trivy 00b7394 pkg/dependency/parser/julia/manifest and
// pkg/fanal/analyzer/language/julia/pkg; on in every mode, image included):
//
//   - a v1 manifest is a top-level table of [[Name]] entries; anything that
//     does not decode that way is read as v2 ([[deps.Name]] plus
//     julia_version and manifest_format); a v2 file without manifest_format
//     yields nothing (Trivy keeps its empty v1 result).
//   - an entry's deps are names (each must name exactly one entry, or the
//     file fails) or a name -> UUID table.
//   - a standard library has no version: it takes julia_version ("unknown"
//     in v1).
//   - with a Project.toml next to it, only what [deps] reaches is kept, and
//     what only [extras] reaches is a development dependency; an unreadable
//     Project.toml keeps everything (Trivy warns and keeps them).
//
// Deliberate difference: without a Project.toml Trivy reports nothing (its
// project lookup returns no error and no roots, so every package is
// filtered out; measured: 56 -> 0 on julia v1.11.2's doc/Manifest.toml).
// A silent empty result would read as clean, so here everything is kept.

import (
	"bytes"
	"fmt"
	"io"
	"sort"

	"github.com/BurntSushi/toml"

	"github.com/ferhatcil/cdgate/internal/model"
)

type juliaDep struct {
	Deps    toml.Primitive `toml:"deps"`
	UUID    string         `toml:"uuid"`
	Version string         `toml:"version"`
}

type juliaManifest struct {
	JuliaVersion   string                `toml:"julia_version"`
	ManifestFormat string                `toml:"manifest_format"`
	Deps           map[string][]juliaDep `toml:"deps"`
}

type juliaPkg struct {
	name, version, uuid string
	dependsOn           []string
}

func parseJuliaManifest(r io.Reader, opt Options) ([]model.Package, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	var old map[string][]juliaDep
	var man juliaManifest
	md, err := toml.NewDecoder(bytes.NewReader(data)).Decode(&old)
	if err != nil {
		if md, err = toml.NewDecoder(bytes.NewReader(data)).Decode(&man); err != nil {
			return nil, fmt.Errorf("Manifest.toml: %w", err)
		}
	}
	if man.ManifestFormat == "" {
		man = juliaManifest{JuliaVersion: "unknown", Deps: old}
	}
	names := make([]string, 0, len(man.Deps))
	for n := range man.Deps {
		names = append(names, n)
	}
	sort.Strings(names)
	var pkgs []juliaPkg
	for _, name := range names {
		for _, d := range man.Deps[name] {
			p := juliaPkg{name: name, version: d.Version, uuid: d.UUID}
			if p.version == "" {
				p.version = man.JuliaVersion
			}
			var byName []string
			if err := md.PrimitiveDecode(d.Deps, &byName); err == nil {
				for _, dn := range byName {
					e := man.Deps[dn]
					if len(e) != 1 {
						return nil, fmt.Errorf("Manifest.toml: dependency %q has invalid format (%d entries)", dn, len(e))
					}
					p.dependsOn = append(p.dependsOn, e[0].UUID)
				}
			} else {
				var byUUID map[string]string
				if err := md.PrimitiveDecode(d.Deps, &byUUID); err != nil {
					return nil, fmt.Errorf("Manifest.toml: %w", err)
				}
				for _, u := range byUUID {
					p.dependsOn = append(p.dependsOn, u)
				}
			}
			pkgs = append(pkgs, p)
		}
	}
	keep := juliaReachable(pkgs, opt)
	var out []model.Package
	for i, p := range pkgs {
		if keep != nil && !keep[i] {
			continue
		}
		if mp, ok := pkg(p.name, p.version, false); ok {
			out = append(out, mp)
		}
	}
	return out, nil
}

// juliaReachable: nil keeps everything (no Project.toml, or one that does not read).
func juliaReachable(pkgs []juliaPkg, opt Options) map[int]bool {
	if opt.Files == nil {
		return nil
	}
	b, err := opt.Files.Read("Project.toml")
	if err != nil {
		return nil
	}
	var proj struct {
		Deps   map[string]string `toml:"deps"`
		Extras map[string]string `toml:"extras"`
	}
	if _, err := toml.NewDecoder(bytes.NewReader(b)).Decode(&proj); err != nil {
		return nil
	}
	// Trivy keys packages by UUID (lo.SliceToMap: the last entry wins).
	byUUID := map[string]int{}
	for i, p := range pkgs {
		byUUID[p.uuid] = i
	}
	keep := map[int]bool{}
	walk := func(roots map[string]string) {
		var visit func(i int)
		seen := map[int]bool{}
		visit = func(i int) {
			if seen[i] {
				return
			}
			seen[i] = true
			keep[i] = true
			for _, u := range pkgs[i].dependsOn {
				if j, ok := byUUID[u]; ok {
					visit(j)
				}
			}
		}
		for _, u := range roots {
			if i, ok := byUUID[u]; ok {
				visit(i)
			}
		}
	}
	walk(proj.Deps)
	if opt.IncludeDev {
		walk(proj.Extras)
	}
	return keep
}
