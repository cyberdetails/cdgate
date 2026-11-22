// Package model holds the types shared by the scanner, the API client and the report.
package model

// Package is one dependency found on disk. Only Ecosystem, Name and Version
// are ever sent to the CyberDetails API; Source stays on the machine.
type Package struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	// Source is the file the package was read from, relative to the scan root.
	Source string `json:"source"`
	// Direct is true when the manifest says the project depends on it directly.
	// False means transitive or unknown (not every lockfile records it).
	Direct bool `json:"direct"`
	// Binaries are the installed binary packages built from this source
	// package (OS packages only; matching uses the source name and version).
	Binaries []string `json:"binaries,omitempty"`
	// RPM packages are matched per binary package; these travel with it.
	Arch            string `json:"arch,omitempty"`
	ModularityLabel string `json:"modularity_label,omitempty"`
	SourcePackage   string `json:"source_package,omitempty"`
	// BuildInfo is the Red Hat build information (content sets, container NVR)
	// of the image layer the package was installed in (Trivy BuildInfo).
	BuildInfo *BuildInfo `json:"build_info,omitempty"`
	// UncheckedReason says why a package found on disk was not sent for
	// matching (empty: its ecosystem has no advisories yet).
	UncheckedReason string `json:"unchecked_reason,omitempty"`
}

// BuildInfo mirrors Trivy's types.BuildInfo.
type BuildInfo struct {
	ContentSets []string `json:"content_sets,omitempty"`
	Nvr         string   `json:"nvr,omitempty"`
	Arch        string   `json:"arch,omitempty"`
}
