package parse

// .NET files Trivy reads in every mode (trivy 00b7394; image/rootfs disable
// only lock files, and neither of these is one):
//
//	*.deps.json      pkg/dependency/parser/dotnet/core_deps
//	*packages.props  pkg/dependency/parser/nuget/packagesprops (suffix, any case)
//
// Deliberate difference, as for Cargo workspace crates: a "project" library is
// one of the application's own projects and its name is not sent to the API
// (it can name a customer's internal code; Trivy matches it locally). This
// costs findings when a project is also a published package (PowerShell's
// System.Management.Automation), so the count is reported, never silent.

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/ferhatcil/cdgate/internal/model"
)

const runtimePackPrefix = "runtimepack."

func parseDepsJSON(r io.Reader, opt Options) ([]model.Package, error) {
	var d struct {
		Libraries map[string]struct {
			Type string `json:"type"`
		} `json:"libraries"`
		RuntimeTarget struct {
			Name string `json:"name"`
		} `json:"runtimeTarget"`
		Targets map[string]map[string]struct {
			Runtime        json.RawMessage `json:"runtime"`
			RuntimeTargets json.RawMessage `json:"runtimeTargets"`
			Native         json.RawMessage `json:"native"`
		} `json:"targets"`
	}
	if err := json.NewDecoder(r).Decode(&d); err != nil {
		return nil, fmt.Errorf(".deps.json: %w", err)
	}
	id := func(nameVer string) string {
		name, version, _ := strings.Cut(nameVer, "/")
		return strings.TrimPrefix(name, runtimePackPrefix) + "/" + version
	}
	// Trivy: a library listed in the runtime target counts only if it ships
	// something at run time (runtime, runtimeTargets or native, non-null);
	// without that target every library counts.
	target, found := d.Targets[d.RuntimeTarget.Name]
	runtime := map[string]bool{}
	for k, t := range target {
		// Two keys can name one package ("runtimepack.X/1" and "X/1"); Trivy
		// keeps either at random, here the one that ships something.
		runtime[id(k)] = runtime[id(k)] || present(t.Runtime) || present(t.RuntimeTargets) || present(t.Native)
	}
	keys := make([]string, 0, len(d.Libraries))
	for k := range d.Libraries {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	seen := map[string]bool{}
	var out []model.Package
	for _, nameVer := range keys {
		name, version, ok := strings.Cut(nameVer, "/")
		if !ok {
			continue
		}
		typ := d.Libraries[nameVer].Type
		if strings.EqualFold(typ, "project") {
			countLocal(opt)
			continue
		}
		if !strings.EqualFold(typ, "package") && !strings.EqualFold(typ, "runtimepack") {
			continue
		}
		name = strings.TrimPrefix(name, runtimePackPrefix)
		k := name + "/" + version
		if rt, listed := runtime[k]; found && listed && !rt {
			continue
		}
		if seen[k] {
			continue
		}
		seen[k] = true
		if p, ok := pkg(name, version, false); ok {
			out = append(out, p)
		}
	}
	return out, nil
}

func present(m json.RawMessage) bool { return len(m) > 0 && string(m) != "null" }

// IsPackagesProps: Trivy's suffix test, any case.
func IsPackagesProps(name string) bool {
	return strings.HasSuffix(strings.ToLower(name), "packages.props")
}

func parsePackagesProps(r io.Reader, _ Options) ([]model.Package, error) {
	type entry struct {
		Version string `xml:"Version,attr"`
		Update  string `xml:"Update,attr"`
		Include string `xml:"Include,attr"`
	}
	var proj struct {
		XMLName    xml.Name `xml:"Project"`
		ItemGroups []struct {
			Refs     []entry `xml:"PackageReference"`
			Versions []entry `xml:"PackageVersion"`
		} `xml:"ItemGroup"`
	}
	// Decode, but refuse a DOCTYPE before the root (same rule as
	// packages.config: Go does not expand entities, but such a document is
	// not a normal MSBuild file).
	dec := xml.NewDecoder(r)
	for root := false; !root; {
		t, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("packages.props: %w", err)
		}
		switch e := t.(type) {
		case xml.Directive:
			return nil, fmt.Errorf("packages.props: DOCTYPE/entity declarations are not accepted")
		case xml.StartElement:
			if err := dec.DecodeElement(&proj, &e); err != nil {
				return nil, fmt.Errorf("packages.props: %w", err)
			}
			root = true
		}
	}
	isVar := func(s string) bool { return strings.HasPrefix(s, "$(") && strings.HasSuffix(s, ")") }
	seen := map[string]bool{}
	var out []model.Package
	for _, g := range proj.ItemGroups {
		for _, e := range append(g.Refs, g.Versions...) {
			name := e.Update
			if e.Include != "" {
				name = e.Include
			}
			name, version := strings.TrimSpace(name), strings.TrimSpace(e.Version)
			if name == "" || version == "" || isVar(name) || isVar(version) {
				continue
			}
			if seen[name+"@"+version] {
				continue
			}
			seen[name+"@"+version] = true
			if p, ok := pkg(name, version, true); ok {
				out = append(out, p)
			}
		}
	}
	return out, nil
}
