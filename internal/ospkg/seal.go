package ospkg

// Seal Security patched OS packages (trivy 00b7394 pkg/detector/ospkg/seal):
// on the supported families a package whose binary or source name starts with
// "seal-" is matched against Seal's own advisories, by source name and source
// version, never against the distribution's. Trivy picks the Seal driver for
// the whole image when any such package exists and hands the other packages
// to the base driver unchanged, so deciding per package is the same thing.
// Seal packages are not dropped as third-party packages (Seal FilterPackages).

import "strings"

// sealFamilies is Trivy's supportedOSFamilies.
var sealFamilies = map[string]bool{"alpine": true, "mariner": true, "centos": true, "redhat": true,
	"debian": true, "oracle": true, "ubuntu": true}

// sealRedHat are the Red Hat versions Seal publishes advisories for.
var sealRedHat = map[string]bool{"6": true, "7": true, "8": true, "9": true}

// SealNoRelease is the reason given for a Seal RPM whose release names no
// Red Hat version Seal publishes advisories for (Trivy looks it up in an
// empty bucket and reports nothing).
const SealNoRelease = "Seal Security package whose release does not name a Red Hat version (el6-el9) Seal publishes advisories for"

// SealNoSource is the reason given for a Seal RPM without a source RPM: Trivy
// compares an empty version and reports nothing.
const SealNoSource = "Seal Security package without a source RPM: no version to compare"

func sealPkg(name, src string) bool {
	return strings.HasPrefix(strings.ToLower(name), "seal-") || strings.HasPrefix(strings.ToLower(src), "seal-")
}

// sealRelease is Trivy's releaseVersion: the text after the first "el", cut
// at "_" and "+" (9.el10_0.1 -> 10, 3.el8+sp1 -> 8).
func sealRelease(release string) string {
	if !strings.Contains(release, "el") {
		return ""
	}
	_, v, _ := strings.Cut(release, "el")
	v, _, _ = strings.Cut(v, "_")
	v, _, _ = strings.Cut(v, "+")
	return v
}

// sealEcosystem is the query ecosystem for a Seal package, or "" and the
// reason it cannot be checked.
func sealEcosystem(family, srcRelease string) (string, string) {
	switch family {
	case "alpine":
		return "Seal:Alpine", ""
	case "debian", "ubuntu":
		return "Seal:Debian", "" // Trivy: one Seal Debian bucket for both
	}
	if v := sealRelease(srcRelease); sealRedHat[v] {
		return "Seal:Red Hat:" + v, ""
	}
	return "", SealNoRelease
}
