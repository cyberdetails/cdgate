package ospkg

import (
	"bufio"
	"bytes"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/cyberdetails/cdgate/internal/model"
	"github.com/cyberdetails/cdgate/internal/rpmdb"
)

// RPM-based distributions, as Trivy reads them (00b7394):
//   - OS: pkg/fanal/analyzer/os/redhatbase ({redhat,centos,rocky,almalinux,
//     oracle,fedora}-release, regexp "(.*) release (\d[\d\.]*)" on the first
//     line), amazonlinux ({etc,usr/lib}/system-release) and os-release IDs
//     rhel/centos/rocky/almalinux/ol/fedora (NAME "CentOS Stream" → centos-stream);
//     types.OS.Merge lets any family replace "redhat" (an Oracle image's
//     redhat-release says RHEL).
//   - packages: pkg/fanal/analyzer/pkg/rpm with go-rpmdb (internal/rpmdb);
//     a package whose Vendor is not an OS vendor is third-party and is not
//     matched (DropThirdPartyPackages), only vendor packages list installed
//     files (SystemInstalledFiles).
//   - release used for matching: the major version (osver.Major); Amazon:
//     the first word's major, anything but 2/2022/2023 is Amazon Linux 1;
//     SUSE (os-release only: opensuse-leap/opensuse, opensuse-tumbleweed,
//     sles, sle-micro/sl-micro/sle-micro-rancher): the full version.
//
// RPM packages are matched by BINARY package name and epoch:version-release
// (Trivy's Red Hat family drivers), so one row per installed binary package.

var rpmFamilies = map[string]string{
	"redhat": "Red Hat", "centos": "CentOS", "centos-stream": "CentOS Stream", "rocky": "Rocky Linux",
	"alma": "AlmaLinux", "oracle": "Oracle Linux", "fedora": "Fedora", "amazon": "Amazon Linux",
	"opensuse-leap": "openSUSE Leap", "opensuse-tumbleweed": "openSUSE Tumbleweed", "sles": "SLES",
	"slem": "SLE Micro", "photon": "Photon OS", "azure": "Azure Linux", "mariner": "CBL-Mariner",
}

// suseFamilies use the full release (Trivy suse.go: Release: osVer, 15.6).
var suseFamilies = map[string]bool{"opensuse-leap": true, "opensuse-tumbleweed": true, "sles": true, "slem": true}

// IsRPM reports whether a family uses the RPM package database.
func IsRPM(family string) bool { _, ok := rpmFamilies[family]; return ok }

// queryableRPM are the RPM ecosystems the CyberDetails API has advisories for
// (sca_key: Rocky and AlmaLinux 8/9/10, Amazon Linux 2/2023, Red Hat 6-9,
// CentOS 6-8, Oracle Linux 5-10, SUSE); any other release is listed as unchecked,
// never reported clean.
var queryableRPM = map[string]bool{
	"Rocky Linux:8": true, "Rocky Linux:9": true, "Rocky Linux:10": true,
	"AlmaLinux:8": true, "AlmaLinux:9": true, "AlmaLinux:10": true,
	"Amazon Linux:2": true, "Amazon Linux:2023": true,
	"Red Hat:6": true, "Red Hat:7": true, "Red Hat:8": true, "Red Hat:9": true,
	"CentOS:6": true, "CentOS:7": true, "CentOS:8": true,
	"Oracle Linux:5": true, "Oracle Linux:6": true, "Oracle Linux:7": true, "Oracle Linux:8": true,
	"Oracle Linux:9": true, "Oracle Linux:10": true,
	// SUSE: the versions the CVRF archive has a bucket for (sca_key, 2026-11-18).
	"SLES:11": true, "SLES:11.1": true, "SLES:11.2": true, "SLES:11.3": true, "SLES:11.4": true,
	"SLES:12": true, "SLES:12.1": true, "SLES:12.2": true, "SLES:12.3": true, "SLES:12.4": true, "SLES:12.5": true,
	"SLES:15": true, "SLES:15.1": true, "SLES:15.2": true, "SLES:15.3": true, "SLES:15.4": true, "SLES:15.5": true,
	"SLES:15.6": true, "SLES:15.7": true, "SLES:16.0": true, "SLES:16.1": true,
	"SLE Micro:5.0": true, "SLE Micro:5.1": true, "SLE Micro:5.2": true, "SLE Micro:5.3": true, "SLE Micro:5.4": true,
	"SLE Micro:5.5": true, "SLE Micro:6.0": true, "SLE Micro:6.1": true, "SLE Micro:6.2": true,
	"openSUSE Leap:15.0": true, "openSUSE Leap:15.1": true, "openSUSE Leap:15.2": true, "openSUSE Leap:15.3": true,
	"openSUSE Leap:15.4": true, "openSUSE Leap:15.5": true, "openSUSE Leap:15.6": true, "openSUSE Leap:16.0": true,
	"openSUSE Leap:16.1": true, "openSUSE Leap:42.1": true, "openSUSE Leap:42.2": true, "openSUSE Leap:42.3": true,
	"openSUSE Tumbleweed": true,
	// Photon OS: photon_versions.json branches (except "dev").
	"Photon OS:1.0": true, "Photon OS:2.0": true, "Photon OS:3.0": true, "Photon OS:4.0": true, "Photon OS:5.0": true,
	// Azure Linux / CBL-Mariner: the three OVAL files of AzureLinuxVulnerabilityData.
	"Azure Linux:3.0": true, "CBL-Mariner:1.0": true, "CBL-Mariner:2.0": true,
}

// bySource: families whose Trivy driver matches by source package name.
var bySource = map[string]bool{"photon": true, "azure": true, "mariner": true}

// srcVersion is Trivy's formatVersion(SrcEpoch, SrcVersion, SrcRelease).
func srcVersion(epoch int, ver, rel string) string {
	v := ver
	if rel != "" {
		v += "-" + rel
	}
	if epoch != 0 {
		v = strconv.Itoa(epoch) + ":" + v
	}
	return v
}

// usesBuildInfo: Trivy's Red Hat driver (RHEL and CentOS) selects advisories
// by the content sets of the layer a package came from.
func usesBuildInfo(family string) bool { return family == "redhat" || family == "centos" }

// BuildInfoUnknown is the reason given for a package whose layer's build
// information could not be read.
const BuildInfoUnknown = "the image's Red Hat build information (root/buildinfo Dockerfile) uses syntax this scanner does not read"

// queryName is the name an RPM package is matched under: AlmaLinux, Rocky,
// Red Hat and CentOS key modular packages by "module:stream::name" (Trivy
// alma/rocky/redhat drivers); Amazon and the other families use the plain name.
func queryName(family string, p rpmdb.Package) string {
	if family == "alma" || family == "rocky" || family == "redhat" || family == "centos" {
		return modularName(p.Name, p.ModularityLabel)
	}
	return p.Name
}

// modularName is Trivy's addModularNamespace (alma.go/rocky.go):
// npm + "nodejs:12:8030020201124152102:229f0a1c" -> "nodejs:12::npm".
func modularName(name, label string) string {
	count := 0
	for i, r := range label {
		if r == ':' {
			count++
		}
		if count == 2 {
			return label[:i] + "::" + name
		}
	}
	return name
}

var redhatRe = regexp.MustCompile(`(.*) release (\d[\d\.]*)`)

// rpmReleaseFiles: path → the family names its analyzer accepts ("" = any:
// redhat-release maps names itself, oracle-release takes the first line).
var rpmReleaseFiles = []struct {
	path  string
	names map[string]string
}{
	{"etc/redhat-release", nil},
	{"etc/centos-release", map[string]string{"centos": "centos", "centos linux": "centos"}},
	{"etc/rocky-release", map[string]string{"rocky": "rocky", "rocky linux": "rocky"}},
	{"etc/almalinux-release", map[string]string{"alma": "alma", "almalinux": "alma", "alma linux": "alma"}},
	{"etc/oracle-release", map[string]string{"": "oracle"}},
	{"etc/fedora-release", map[string]string{"fedora": "fedora", "fedora linux": "fedora"}},
	{"usr/lib/fedora-release", map[string]string{"fedora": "fedora", "fedora linux": "fedora"}},
}

// redhatReleaseFamily is the name mapping of Trivy's redhat-release analyzer.
func redhatReleaseFamily(name string) string {
	switch strings.ToLower(name) {
	case "centos", "centos linux":
		return "centos"
	case "rocky", "rocky linux":
		return "rocky"
	case "alma", "almalinux", "alma linux":
		return "alma"
	case "oracle", "oracle linux", "oracle linux server":
		return "oracle"
	case "fedora", "fedora linux":
		return "fedora"
	}
	return "redhat"
}

// releaseFileOS reads one redhatbase release file. A line the regexp does not
// match ends the analysis with no OS (Trivy returns an error there); a line of
// another distribution is skipped by the per-distribution analyzers.
func releaseFileOS(b []byte, names map[string]string) OS {
	s := bufio.NewScanner(bytes.NewReader(b))
	for s.Scan() {
		m := redhatRe.FindStringSubmatch(strings.TrimSpace(s.Text()))
		if len(m) != 3 {
			return OS{}
		}
		if names == nil {
			return OS{Family: redhatReleaseFamily(m[1]), Name: m[2]}
		}
		if f, ok := names[""]; ok {
			return OS{Family: f, Name: m[2]}
		}
		if f, ok := names[strings.ToLower(m[1])]; ok {
			return OS{Family: f, Name: m[2]}
		}
	}
	return OS{}
}

// amazonRelease is Trivy's amazonlinux analyzer.
func amazonRelease(b []byte) OS {
	s := bufio.NewScanner(bytes.NewReader(b))
	for s.Scan() {
		line := s.Text()
		f := strings.Fields(line)
		if strings.HasPrefix(line, "Amazon Linux release 2") {
			if len(f) < 5 {
				continue
			}
			return OS{Family: "amazon", Name: strings.Join(f[3:], " ")}
		} else if strings.HasPrefix(line, "Amazon Linux") {
			return OS{Family: "amazon", Name: strings.Join(f[2:], " ")}
		}
	}
	return OS{}
}

func detectRPMRelease(f Files, o *OS) {
	for _, r := range rpmReleaseFiles {
		if b, ok := f.Get(r.path); ok {
			merge(o, releaseFileOS(b, r.names))
		}
	}
	for _, p := range []string{"etc/system-release", "usr/lib/system-release"} {
		if b, ok := f.Get(p); ok {
			merge(o, amazonRelease(b))
		}
	}
}

func rpmRelease(o OS) (string, error) {
	if o.Family == "amazon" {
		f := strings.Fields(o.Name)
		major := "1"
		if len(f) > 0 {
			m, _, _ := strings.Cut(f[0], ".")
			if m == "2" || m == "2022" || m == "2023" {
				major = m
			}
		}
		return "Amazon Linux:" + major, nil
	}
	if o.Family == "photon" {
		// Trivy's photon driver uses the full release ("5.0").
		if !regexp.MustCompile(`^[0-9]+\.[0-9]+$`).MatchString(o.Name) {
			return "", ErrUnsupported{o.Family, o.Name}
		}
		return "Photon OS:" + o.Name, nil
	}
	if o.Family == "azure" || o.Family == "mariner" {
		// Trivy's azure driver: osver.Minor ("2.0.20240117" -> "2.0").
		major, rest, ok := strings.Cut(o.Name, ".")
		if ok {
			minor, _, _ := strings.Cut(rest, ".")
			major += "." + minor
		}
		return rpmFamilies[o.Family] + ":" + major, nil
	}
	if o.Family == "opensuse-tumbleweed" {
		return "openSUSE Tumbleweed", nil // rolling: one stream
	}
	if suseFamilies[o.Family] {
		if !regexp.MustCompile(`^[0-9]+(\.[0-9]+)*$`).MatchString(o.Name) {
			return "", ErrUnsupported{o.Family, o.Name}
		}
		return rpmFamilies[o.Family] + ":" + o.Name, nil
	}
	major, _, _ := strings.Cut(o.Name, ".")
	if !numeric.MatchString(major) {
		return "", ErrUnsupported{o.Family, o.Name}
	}
	return rpmFamilies[o.Family] + ":" + major, nil
}

// osVendors: Trivy rpm.go osVendors (prefix match on Vendor).
var osVendors = []string{"Amazon Linux", "Amazon.com", "CentOS", "Fedora Project", "Oracle America", "Red Hat",
	"AlmaLinux", "CloudLinux", "VMware", "SUSE", "openSUSE", "Microsoft Corporation", "Rocky"}

// vendorPackage is Trivy's packageProvidedByVendor: no Vendor counts as
// official only for Amazon ("amzn" in the release).
func vendorPackage(p rpmdb.Package) bool {
	if p.Vendor == "" {
		return strings.Contains(p.Release, "amzn")
	}
	for _, v := range osVendors {
		if strings.HasPrefix(p.Vendor, v) {
			return true
		}
	}
	return false
}

// invalidVendorFiles: Trivy lists installed files only for vendor packages and
// fails the whole database when such a list is inconsistent.
func invalidVendorFiles(pkgs []rpmdb.Package) error {
	for _, pk := range pkgs {
		if pk.FilesInvalid && vendorPackage(pk) {
			return fmt.Errorf("invalid file list in package %s", pk.Name)
		}
	}
	return nil
}

// RpmqaPath: CBL-Mariner / Azure Linux distroless images list their packages
// as `rpm -qa --qf` text instead of an rpm database (Trivy rpmqa analyzer,
// requiredRpmqaFiles, v0.76.2).
const RpmqaPath = "var/lib/rpmmanifest/container-manifest-2"

// parseRpmqa is Trivy's rpmqaPkgAnalyzer.parseRpmqaManifest:
// %{NAME}\t%{VERSION}-%{RELEASE}\t%{INSTALLTIME}\t%{BUILDTIME}\t%{VENDOR}\t(none)\t%{SIZE}\t%{ARCH}\t%{EPOCHNUM}\t%{SOURCERPM}.
// Any line without exactly ten fields fails the whole file (an empty line
// too); VERSION-RELEASE must split on "-" into exactly two parts; the source
// RPM goes through splitFileName ("(none)" fails); the epoch is strconv.Atoi
// and is also the source epoch. No vendor filter and no file list. Deliberate
// difference: a line over bufio.Scanner's 64 KiB token limit is an error
// here, where Trivy stops reading without reporting it (a silently short list).
func parseRpmqa(b []byte) ([]rpmdb.Package, error) {
	var pkgs []rpmdb.Package
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := sc.Text()
		s := strings.Split(line, "\t")
		if len(s) != 10 {
			return nil, fmt.Errorf("failed to parse a line (%d fields)", len(s))
		}
		verRel := strings.Split(s[1], "-")
		if len(verRel) != 2 {
			return nil, fmt.Errorf("failed to split a version")
		}
		if _, _, _, err := rpmdb.SplitSourceRpm(s[9]); err != nil {
			return nil, fmt.Errorf("failed to split source rpm: %w", err)
		}
		epoch, err := strconv.Atoi(s[8])
		if err != nil {
			return nil, fmt.Errorf("failed to parse epoch number")
		}
		pkgs = append(pkgs, rpmdb.Package{Name: s[0], Version: verRel[0], Release: verRel[1], Arch: s[7],
			Epoch: epoch, SourceRpm: s[9], FromRpmqa: true})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return pkgs, nil
}

// readRPM parses every rpm database present (Trivy analyzes each one) and
// the distroless rpmqa manifest.
func readRPM(f Files) (files []string, pkgs []rpmdb.Package, err error) {
	for _, p := range rpmdb.Paths {
		b, ok := f.Get(p)
		if !ok {
			continue
		}
		got, err := rpmdb.Parse(b)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", p, err)
		}
		if err := invalidVendorFiles(got); err != nil {
			return nil, nil, fmt.Errorf("%s: %w", p, err)
		}
		files = append(files, p)
		pkgs = append(pkgs, got...)
	}
	if b, ok := f.Get(RpmqaPath); ok {
		got, err := parseRpmqa(b)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", RpmqaPath, err)
		}
		files = append(files, RpmqaPath)
		pkgs = append(pkgs, got...)
	}
	return files, pkgs, nil
}

func analyzeRPM(f Files, res *Result) error {
	files, pkgs, err := readRPM(f)
	if err != nil {
		return err
	}
	res.Files = files
	if len(files) == 0 {
		return nil
	}
	rpmPackages(f, res, files[0], pkgs)
	return nil
}

// rpmPackages turns parsed rpm database rows into query rows (vendor filter,
// per-family name rules, build information, sorting).
func rpmPackages(f Files, res *Result, source string, pkgs []rpmdb.Package) {
	type key struct{ n, v, a string }
	seen := map[key]bool{}
	photonRow := map[key]int{}
	sealRow := map[[4]string]int{}
	for _, p := range pkgs {
		if sealFamilies[res.OS.Family] && sealRPM(res, source, p, sealRow) {
			continue
		}
		if !p.FromRpmqa && !vendorPackage(p) {
			res.Skipped["third_party"]++
			continue
		}
		k := key{p.Name, p.EVR(), p.Arch}
		if seen[k] {
			continue
		}
		seen[k] = true
		if res.OS.Family == "alma" && strings.Contains(p.Release, ".module_el") && p.ModularityLabel == "" {
			// Trivy alma: modular packages without a label are skipped (AlmaLinux bug 173)
			res.Skipped["alma_modular_without_label"]++
			continue
		}
		name := queryName(res.OS.Family, p)
		src, srcVer, srcRel := "", "", ""
		if p.SourceRpm != "" {
			if n, v, r, err := rpmdb.SplitSourceRpm(p.SourceRpm); err == nil {
				src, srcVer, srcRel = n, v, r
			}
		}
		if bySource[res.OS.Family] {
			// Trivy's photon and azure drivers look advisories up by the SOURCE
			// package name (pkg.SrcName); a package without a source RPM finds
			// nothing there. Photon compares the binary's version, Azure Linux
			// and CBL-Mariner the source package's (FormatSrcVersion: the
			// binary's epoch, the source RPM's version and release). One row
			// per (source, version, arch); the binaries built from it are listed.
			if src == "" {
				res.Skipped[res.OS.Family+"_no_source_rpm"]++
				continue
			}
			ver := p.EVR()
			if res.OS.Family != "photon" {
				ver = srcVersion(p.Epoch, srcVer, srcRel)
			}
			pk := key{src, ver, p.Arch}
			if i, ok := photonRow[pk]; ok {
				res.Packages[i].Binaries = append(res.Packages[i].Binaries, p.Name)
				sort.Strings(res.Packages[i].Binaries)
				continue
			}
			photonRow[pk] = len(res.Packages)
			res.Packages = append(res.Packages, model.Package{Ecosystem: res.Ecosystem, Name: src, Version: ver,
				Source: source, Arch: p.Arch, SourcePackage: src, Binaries: []string{p.Name}})
			continue
		}
		pkg := model.Package{Ecosystem: res.Ecosystem, Name: name, Version: p.EVR(),
			Source: source, Arch: p.Arch, ModularityLabel: p.ModularityLabel, SourcePackage: src}
		if bs, ok := f.(BuildInfoSource); ok && usesBuildInfo(res.OS.Family) {
			bi, known := bs.RPMBuildInfo(p.Name, p.Version, p.Release)
			if !known {
				pkg.UncheckedReason = BuildInfoUnknown
				res.Unchecked = append(res.Unchecked, pkg)
				continue
			}
			pkg.BuildInfo = bi
		}
		res.Packages = append(res.Packages, pkg)
	}
	sort.Slice(res.Packages, func(i, j int) bool {
		a, b := res.Packages[i], res.Packages[j]
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		if a.Version != b.Version {
			return a.Version < b.Version
		}
		return a.Arch < b.Arch
	})
}

// sealRPM adds a Seal package (source name, FormatSrcVersion, release-derived
// Red Hat version) and reports whether p was one.
func sealRPM(res *Result, source string, p rpmdb.Package, rows map[[4]string]int) bool {
	src, srcVer, srcRel := "", "", ""
	if p.SourceRpm != "" && p.SourceRpm != "(none)" {
		if n, v, r, err := rpmdb.SplitSourceRpm(p.SourceRpm); err == nil {
			src, srcVer, srcRel = n, v, r
		}
	}
	if !sealPkg(p.Name, src) {
		return false
	}
	name, rel := src, srcRel
	if src == "" {
		name, rel = p.Name, p.Release // Trivy: cmp.Or(SrcName, Name), release of the same
	}
	pkg := model.Package{Name: name, Source: source, Arch: p.Arch, SourcePackage: src, Binaries: []string{p.Name}}
	eco, reason := sealEcosystem(res.OS.Family, rel)
	pkg.Ecosystem = eco
	switch {
	case reason != "":
		pkg.Ecosystem, pkg.UncheckedReason = res.Ecosystem, reason
	case src == "":
		pkg.Ecosystem, pkg.UncheckedReason = eco, SealNoSource
	}
	if pkg.UncheckedReason != "" {
		pkg.Version = p.EVR()
		res.Unchecked = append(res.Unchecked, pkg)
		return true
	}
	pkg.Version = srcVersion(p.Epoch, srcVer, srcRel)
	k := [4]string{eco, name, pkg.Version, p.Arch}
	if i, ok := rows[k]; ok {
		if !contains(res.Packages[i].Binaries, p.Name) {
			res.Packages[i].Binaries = append(res.Packages[i].Binaries, p.Name)
			sort.Strings(res.Packages[i].Binaries)
		}
		return true
	}
	rows[k] = len(res.Packages)
	res.Packages = append(res.Packages, pkg)
	return true
}

// rpmInstalledFiles: files of vendor packages (Trivy SystemInstalledFiles).
func rpmInstalledFiles(f Files, out map[string]bool) {
	_, pkgs, err := readRPM(f)
	if err != nil {
		return
	}
	for _, p := range pkgs {
		if !vendorPackage(p) {
			continue
		}
		for _, file := range p.Files {
			if file = strings.TrimLeft(file, "/"); file != "" {
				out[file] = true
			}
		}
	}
}
