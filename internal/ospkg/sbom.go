package ospkg

// OS packages listed in an SBOM (trivy 00b7394 pkg/sbom/io decodePackage +
// fillSrcPkg, then the same OS drivers as an image). The SBOM's packages are
// written as the package database the OS's own reader parses (dpkg status,
// apk installed), so every rule of the image path applies unchanged:
// source package and version, third-party exclusion (from the SBOM's
// RepositoryClass instead of the maintainer), Seal, Root.io and Echo.
//
// Packages whose type does not match the OS are listed unchecked (Trivy hands
// them to the OS's driver).
//
// RPM systems: the rows come from rpmPackages, the image path's own
// conversion, fed with the SBOM's packages: the vendor test reads the SBOM's
// RepositoryClass, the source RPM is rebuilt from the source fields, and Red
// Hat build information comes from the package's ContentSet / NVR properties
// (none: nil, the server's default repositories, as Trivy's driver does).
// Deliberate difference: the source version takes the binary epoch, as the
// image path does (Trivy's SBOM path can carry a different SrcEpoch).
//
// RapidFort is never selected: Trivy selects it from an image file an SBOM
// does not carry.

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/cyberdetails/cdgate/internal/model"
	"github.com/cyberdetails/cdgate/internal/rpmdb"
	"github.com/cyberdetails/cdgate/internal/sbom"
)

// SBOMNotRead is why an SBOM's OS packages are listed unchecked.
const SBOMNotRead = "operating-system package listed in an SBOM: not checked yet for this operating system"

// SBOMNoOS: OS packages with no operating-system component to match them against.
const SBOMNoOS = "operating-system package listed in an SBOM without an operating-system component"

var errSBOMField = errors.New("SBOM package field not usable in a package database")

type memDB map[string][]byte

func (m memDB) Get(p string) ([]byte, bool) { b, ok := m[p]; return b, ok }
func (m memDB) List(string) []string        { return nil }

// srcFields: Trivy fillPkgFieldsFromComponentProps then fillSrcPkg (the SPDX
// source name only when no property gave one; the SPDX source version, parsed
// as the package type's version, over the properties'; then the binary's own).
func srcFields(p sbom.OSPackage) (name, version, release string, epoch int) {
	name, version, release, epoch = p.SrcName, p.SrcVersion, p.SrcRelease, p.SrcEpoch
	if epoch < 0 {
		epoch = 0
	}
	if p.InfoSrcName != "" && name == "" {
		name = p.InfoSrcName
	}
	if p.InfoSrcVersion != "" && p.Type == "deb" {
		if e, u, r, ok := debVersion(p.InfoSrcVersion); ok {
			epoch, version, release = e, u, r
		}
	}
	if name != "" && version != "" {
		return name, version, release, epoch
	}
	if name == "" {
		name = p.Name
	}
	if version == "" {
		version = p.Version
	}
	if release == "" {
		release = p.Release
	}
	if epoch == 0 {
		epoch = p.Epoch
	}
	return name, version, release, epoch
}

// formatTrivyVersion: Trivy scan/utils formatVersion.
func formatTrivyVersion(epoch int, version, release string) string {
	v := version
	if release != "" {
		v += "-" + release
	}
	if epoch != 0 {
		v = strconv.Itoa(epoch) + ":" + v
	}
	return v
}

// dbField refuses anything that would change the synthesized database's
// structure (a line break, or for a name a space or parenthesis).
func dbField(s string, name bool) error {
	if s == "" || strings.ContainsAny(s, "\r\n\x00") || (name && strings.ContainsAny(s, " \t()")) {
		return errSBOMField
	}
	return nil
}

// FromSBOM returns the queryable rows of an SBOM's OS packages and the
// packages it cannot check, with the reason set.
func FromSBOM(o *sbom.OS, pkgs []sbom.OSPackage) (*Result, []sbom.OSPackage, error) {
	if len(pkgs) == 0 {
		return nil, nil, nil
	}
	if o == nil {
		return nil, pkgs, errors.New(SBOMNoOS)
	}
	os := OS{Family: o.Family, Name: o.Name}
	if f, ok := trivyFamily[os.Family]; ok {
		os.Family = f
	}
	if IsRPM(os.Family) {
		return sbomRPM(os, pkgs)
	}
	want, file := "", ""
	switch os.Family {
	case "debian", "ubuntu", "echo":
		want, file = "deb", "var/lib/dpkg/status"
	case "alpine", "wolfi", "chainguard", "minimos":
		want, file = "apk", "lib/apk/db/installed"
	default:
		return nil, pkgs, errors.New(SBOMNotRead)
	}
	var db strings.Builder
	var rest []sbom.OSPackage
	skipped, skipped3 := 0, 0
	for _, p := range pkgs {
		if p.Type != want {
			rest = append(rest, p) // Trivy would hand it to this OS's driver; listed instead
			continue
		}
		sn, sv, sr, se := srcFields(p)
		src := formatTrivyVersion(se, sv, sr)
		bin := formatTrivyVersion(p.Epoch, p.Version, p.Release)
		if dbField(p.Name, true) != nil || dbField(sn, true) != nil || dbField(src, false) != nil ||
			dbField(bin, false) != nil || strings.ContainsAny(p.Arch, "\r\n\x00") {
			skipped++
			continue
		}
		if want == "deb" {
			fmt.Fprintf(&db, "Package: %s\nStatus: install ok installed\nVersion: %s\nSource: %s (%s)\n", p.Name, bin, sn, src)
			if p.Arch != "" {
				fmt.Fprintf(&db, "Architecture: %s\n", p.Arch)
			}
			if p.ThirdParty {
				db.WriteString("Maintainer: GitHub\n") // an exact third-party marker (ThirdParty)
			}
			db.WriteString("\n")
		} else {
			// Trivy's default filter drops third-party packages (apk has no
			// maintainer to carry it); Seal keeps its own on Alpine.
			if p.ThirdParty && !(sealFamilies[os.Family] && sealPkg(p.Name, sn)) {
				skipped3++
				continue
			}
			// apk: the source version is the V: line read before o:
			fmt.Fprintf(&db, "P:%s\nV:%s\no:%s\n\n", p.Name, src, sn)
		}
	}
	res, err := AnalyzeOS(os, memDB{file: []byte(db.String())})
	if err != nil {
		return nil, pkgs, err
	}
	res.Skipped["sbom_field_unusable"] += skipped
	res.Skipped["third_party"] += skipped3
	return res, rest, nil
}

// trivyFamily: Trivy OS type names that differ from this package's.
var trivyFamily = map[string]string{"azurelinux": "azure", "cbl-mariner": "mariner"}

// sbomBuildInfo answers RPMBuildInfo from the SBOM's package properties.
type sbomBuildInfo map[[3]string]*model.BuildInfo

func (sbomBuildInfo) Get(string) ([]byte, bool) { return nil, false }
func (sbomBuildInfo) List(string) []string      { return nil }
func (m sbomBuildInfo) RPMBuildInfo(name, version, release string) (*model.BuildInfo, bool) {
	return m[[3]string{name, version, release}], true
}

func sbomRPM(os OS, pkgs []sbom.OSPackage) (*Result, []sbom.OSPackage, error) {
	eco, err := Ecosystem(os)
	if err != nil {
		return nil, pkgs, err
	}
	res := &Result{OS: os, Ecosystem: eco, Skipped: map[string]int{}, Queryable: queryableRPM[eco]}
	bi := sbomBuildInfo{}
	var rows []rpmdb.Package
	var rest []sbom.OSPackage
	for _, p := range pkgs {
		if p.Type != "rpm" {
			rest = append(rest, p)
			continue
		}
		sn, sv, sr, _ := srcFields(p)
		rp := rpmdb.Package{Name: p.Name, Version: p.Version, Release: p.Release, Arch: p.Arch,
			Epoch: p.Epoch, ModularityLabel: p.Modularity, Vendor: osVendors[0]}
		if p.ThirdParty {
			rp.Vendor = "third-party (SBOM RepositoryClass)" // not an OS vendor
		}
		if sn != "" && sv != "" && sr != "" {
			rp.SourceRpm = sn + "-" + sv + "-" + sr + ".src.rpm"
		}
		if strings.ContainsAny(p.Name+p.Version+p.Release+p.Arch+rp.SourceRpm, "\r\n\x00") || p.Name == "" || p.Version == "" {
			res.Skipped["sbom_field_unusable"]++
			continue
		}
		if len(p.ContentSets) > 0 || p.NVR != "" {
			// Trivy sets BuildInfo only then (fillPkgFieldsFromComponentProps)
			bi[[3]string{p.Name, p.Version, p.Release}] = &model.BuildInfo{
				ContentSets: append([]string{}, p.ContentSets...), Nvr: p.NVR, Arch: p.BuildArch}
		}
		rows = append(rows, rp)
	}
	rpmPackages(bi, res, "", rows)
	return res, rest, nil
}
