package ospkg

// RapidFort curated images (trivy 00b7394 pkg/fanal/analyzer/rapidfort,
// pkg/detector/ospkg/rapidfort): an image carrying
// usr/share/rapidfort/curated.json is scanned with RapidFort's advisories
// only, for every OS package, third-party ones included. Each package is
// looked up by its source name (and its binary name) with the source version
// (binary version when there is none); the server picks the RapidFort bucket
// from that version (Trivy's route). RapidFort is the first supplier Trivy
// tries, before Root.io and Seal.

import (
	"sort"
	"strings"

	"github.com/cyberdetails/cdgate/internal/model"
	"github.com/cyberdetails/cdgate/internal/rpmdb"
)

// RapidFortMarker is the file whose presence marks a curated image.
const RapidFortMarker = "usr/share/rapidfort/curated.json"

func init() { Paths = append(Paths, RapidFortMarker) }

// rapidfortFamilies are the families Trivy's RapidFort supplier accepts, with
// the ecosystem name the server knows them by.
var rapidfortFamilies = map[string]string{"ubuntu": "Ubuntu", "debian": "Debian", "alpine": "Alpine",
	"redhat": "RedHat", "oracle": "Oracle", "rocky": "Rocky", "alma": "Alma", "amazon": "Amazon"}

// MaxRapidFortBinaries is the server's limit on binary names per package; a
// source package with more is reported unchecked, never sent cut short.
const MaxRapidFortBinaries = 256

// RapidFortTooManyBinaries is the reason given for such a package.
const RapidFortTooManyBinaries = "RapidFort image source package with more binary packages than one query carries (256)"

// rapidfortLimit moves rows with too many binaries to Unchecked.
func rapidfortLimit(res *Result) {
	kept := res.Packages[:0]
	for _, p := range res.Packages {
		if len(p.Binaries) > MaxRapidFortBinaries {
			p.UncheckedReason = RapidFortTooManyBinaries
			res.Unchecked = append(res.Unchecked, p)
			continue
		}
		kept = append(kept, p)
	}
	res.Packages = kept
}

// RapidFortNoSource is the reason given for a RapidFort RPM without a source
// RPM but with an epoch: Trivy compares the meaningless version "N:".
const RapidFortNoSource = "RapidFort image package without a source RPM: Trivy would compare an epoch with no version"

// rapidfortEcosystem is the query ecosystem when the image is a RapidFort
// curated image of a supported family, else "".
func rapidfortEcosystem(o OS, f Files) string {
	name, ok := rapidfortFamilies[o.Family]
	if !ok {
		return ""
	}
	if _, ok := f.Get(RapidFortMarker); !ok {
		return ""
	}
	var v string
	switch o.Family {
	case "ubuntu", "alpine":
		v = minorVersion(o.Name)
	case "amazon":
		fields := strings.Fields(o.Name)
		if len(fields) == 0 {
			return ""
		}
		v, _, _ = strings.Cut(fields[0], ".")
	default:
		v, _, _ = strings.Cut(o.Name, ".")
	}
	return "RapidFort:" + name + ":" + v
}

// rapidfortRPM builds the rows of a RapidFort RPM image: no vendor filter, no
// build information, one row per (source name, version) with its binaries.
func rapidfortRPM(res *Result, source string, pkgs []rpmdb.Package) {
	type key struct{ n, v string }
	idx := map[key]int{}
	for _, p := range pkgs {
		src, srcVer, srcRel := "", "", ""
		if p.SourceRpm != "" && p.SourceRpm != "(none)" {
			if n, v, r, err := rpmdb.SplitSourceRpm(p.SourceRpm); err == nil {
				src, srcVer, srcRel = n, v, r
			}
		}
		name := src
		if name == "" {
			name = p.Name // Trivy: cmp.Or(SrcName, Name)
		}
		ver := srcVersion(p.Epoch, srcVer, srcRel)
		if src == "" && p.Epoch != 0 {
			res.Unchecked = append(res.Unchecked, model.Package{Ecosystem: res.Ecosystem, Name: p.Name,
				Version: p.EVR(), Source: source, Binaries: []string{p.Name}, UncheckedReason: RapidFortNoSource})
			continue
		}
		if ver == "" {
			ver = p.EVR() // Trivy: cmp.Or(FormatSrcVersion, FormatVersion)
		}
		k := key{name, ver}
		i, ok := idx[k]
		if !ok {
			i = len(res.Packages)
			idx[k] = i
			res.Packages = append(res.Packages, model.Package{Ecosystem: res.Ecosystem, Name: name, Version: ver,
				Source: source, SourcePackage: src})
		}
		if !contains(res.Packages[i].Binaries, p.Name) {
			res.Packages[i].Binaries = append(res.Packages[i].Binaries, p.Name)
			sort.Strings(res.Packages[i].Binaries)
		}
	}
	sort.Slice(res.Packages, func(i, j int) bool {
		a, b := res.Packages[i], res.Packages[j]
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.Version < b.Version
	})
}
