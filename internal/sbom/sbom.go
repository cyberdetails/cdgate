// Package sbom reads CycloneDX JSON and SPDX JSON documents into packages,
// with Trivy's rules (00b7394: pkg/sbom/{cyclonedx,spdx,io}, pkg/purl; the
// format test of pkg/sbom.DetectFormat):
//
//   - CycloneDX: top-level components only (not nested ones), cryptographic
//     assets skipped, a component of an unsupported type or with an invalid
//     purl skipped; metadata.component is the root (an invalid root fails the
//     document).
//   - SPDX (2.1-2.3): a package's purl is its first externalRef with category
//     PACKAGE-MANAGER and type purl (an invalid purl fails the document); its
//     type comes from the SPDXID (OperatingSystem / Application / anything
//     else a library); the root is what the document DESCRIBES first.
//   - A component is a package when it is a library or carries a purl, unless
//     it is an application with a "Type" property (an application container)
//     or the operating system (the first one). Its name is the component's
//     (group/name) except for Maven, Gradle, Bitnami and CocoaPods, where the
//     purl gives it; its version is the purl's.
//   - Packages of operating systems not reached from the OS component or an
//     application must be of one purl type, or the document fails.
//
// Differences, each stated where it applies: the document's own project (the
// root component, except a Bitnami one) is not sent; conda, Swift, CocoaPods,
// Conan, Kubernetes and OS packages are listed unchecked; SPDX
// sub-fields (supplier, checksum algorithm...) are not validated as strictly
// as tools-golang does.
package sbom

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/cyberdetails/cdgate/internal/model"
)

// Formats.
const (
	CycloneDXJSON = "cyclonedx-json"
	SPDXJSON      = "spdx-json"
	CycloneDXXML  = "cyclonedx-xml"
	SPDXTagValue  = "spdx-tag-value"
)

// ErrNotRead: CycloneDX XML, which Trivy does not read either ("cyclonedx-xml
// scanning is not yet supported", lab oracle); listed, never silently dropped.
var ErrNotRead = errors.New("SBOM format not read")

// Reasons packages are listed unchecked.
const (
	ReasonConda  = "conda package: no advisory source matches conda packages (Trivy lists them without matching too)"
	ReasonFormat = "CycloneDX XML SBOM: not read (Trivy does not read it either)"
)

// Result of one document.
type Result struct {
	Format   string
	Packages []model.Package
	// Unchecked: packages no advisory source here covers yet (see Reason*;
	// an empty reason means "no advisories for this ecosystem yet").
	Unchecked []model.Package
	// Skipped counts components Trivy also ignores: no purl, a purl type it
	// does not support, or an empty name or version.
	Skipped int
	// LocalNotSent counts root components (the document's own project).
	LocalNotSent int
	// OS is the first operating-system component (Trivy: Family = its name,
	// Name = its version); nil when the document has none.
	OS *OS
	// OSPackages are the deb, apk, rpm and bottlerocket packages, raw: what
	// is queried from them is decided with the OS (ospkg.FromSBOM).
	OSPackages []OSPackage
}

// OS of the document.
type OS struct{ Family, Name string }

// OSPackage: the fields Trivy's decoder fills (pkg/sbom/io decodePackage:
// purl, then component properties, then the SPDX source information).
type OSPackage struct {
	Type, Name, Version, Release, Arch, Modularity string
	Epoch                                          int
	// From properties (aquasecurity:trivy:Src*); SrcEpoch < 0 when absent.
	SrcName, SrcVersion, SrcRelease string
	SrcEpoch                        int
	// From SPDX sourceInfo "built package from: <name> <version>".
	InfoSrcName, InfoSrcVersion string
	ThirdParty                  bool // RepositoryClass third-party
	ContentSets                 []string
	NVR, BuildArch              string
}

// Detect: Trivy's order and tests.
func Detect(b []byte) string {
	var cdx struct {
		BOMFormat string `json:"bomFormat"`
	}
	if json.NewDecoder(bytes.NewReader(b)).Decode(&cdx) == nil && cdx.BOMFormat == "CycloneDX" {
		return CycloneDXJSON
	}
	var cx struct {
		XMLNS string `xml:"xmlns,attr"`
	}
	if xml.NewDecoder(bytes.NewReader(b)).Decode(&cx) == nil && strings.HasPrefix(cx.XMLNS, "http://cyclonedx.org") {
		return CycloneDXXML
	}
	var sp struct {
		SPDXID string `json:"SPDXID"`
	}
	if json.NewDecoder(bytes.NewReader(b)).Decode(&sp) == nil && sp.SPDXID == "SPDXRef-DOCUMENT" {
		return SPDXJSON
	}
	line, _, _ := bytes.Cut(b, []byte("\n"))
	if bytes.HasPrefix(line, []byte("SPDX")) {
		return SPDXTagValue
	}
	return ""
}

type component struct {
	typ        string // library | application | os | container | platform | file
	name       string
	version    string
	group      string
	srcName    string // SPDX sourceInfo
	srcVersion string
	purl       *PURL
	root       bool
	properties []property
}

type property struct{ name, value string }

type bom struct {
	comps []*component
	rels  map[*component][]*component
}

// Decode reads one document.
func Decode(b []byte) (*Result, error) {
	f := Detect(b)
	var d *bom
	var err error
	switch f {
	case CycloneDXJSON:
		d, err = decodeCycloneDX(b)
	case SPDXJSON:
		d, err = decodeSPDX(b)
	case SPDXTagValue:
		d, err = decodeSPDXTagValue(b)
	case CycloneDXXML:
		return &Result{Format: f}, ErrNotRead
	default:
		return nil, errors.New("not a CycloneDX or SPDX document")
	}
	if err != nil {
		return nil, err
	}
	res, err := d.packages()
	if err != nil {
		return nil, err
	}
	res.Format = f
	return res, nil
}

// --- CycloneDX ---

type cdxComponent struct {
	Type       string `json:"type"`
	BOMRef     string `json:"bom-ref"`
	Name       string `json:"name"`
	Version    string `json:"version"`
	Group      string `json:"group"`
	PURL       string `json:"purl"`
	Properties []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	} `json:"properties"`
}

const trivyNamespace = "aquasecurity:trivy:"

func cdxType(t string) (string, bool) {
	switch t {
	case "container":
		return "container", true
	case "application":
		return "application", true
	case "library", "framework":
		return "library", true
	case "operating-system":
		return "os", true
	case "platform":
		return "platform", true
	case "file":
		return "file", true
	}
	return "", false
}

func (c cdxComponent) parse() (*component, error) {
	t, ok := cdxType(c.Type)
	if !ok {
		return nil, errUnsupportedType
	}
	out := &component{typ: t, name: c.Name, version: c.Version, group: c.Group}
	if c.PURL != "" {
		p, err := ParsePURL(c.PURL)
		if err != nil {
			return nil, fmt.Errorf("invalid purl: %w", err)
		}
		out.purl = &p
	}
	for _, pr := range c.Properties {
		// Trivy keeps an external property under its own name, so a plain
		// "Type" counts as well as "aquasecurity:trivy:Type".
		out.properties = append(out.properties, property{strings.TrimPrefix(pr.Name, trivyNamespace), pr.Value})
	}
	return out, nil
}

var errUnsupportedType = errors.New("unsupported component type")

func decodeCycloneDX(b []byte) (*bom, error) {
	var doc struct {
		Metadata *struct {
			Component *cdxComponent `json:"component"`
		} `json:"metadata"`
		Components   []cdxComponent `json:"components"`
		Dependencies []struct {
			Ref       string   `json:"ref"`
			DependsOn []string `json:"dependsOn"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("CycloneDX: %w", err)
	}
	d := &bom{rels: map[*component][]*component{}}
	byRef := map[string]*component{}
	for _, c := range doc.Components {
		pc, err := c.parse() // a cryptographic asset is an unsupported type too
		if err != nil {
			continue // Trivy: skipped (unsupported type) or warned (invalid purl)
		}
		d.comps = append(d.comps, pc)
		byRef[c.BOMRef] = pc
	}
	if doc.Metadata != nil && doc.Metadata.Component != nil {
		root, err := doc.Metadata.Component.parse()
		if err != nil {
			return nil, fmt.Errorf("CycloneDX root component: %w", err)
		}
		root.root = true
		d.comps = append(d.comps, root)
		byRef[doc.Metadata.Component.BOMRef] = root
	}
	for _, dep := range doc.Dependencies {
		parent, ok := byRef[dep.Ref]
		if !ok {
			continue
		}
		for _, r := range dep.DependsOn {
			if child, ok := byRef[r]; ok {
				d.rels[parent] = append(d.rels[parent], child)
			}
		}
	}
	return d, nil
}

// --- SPDX ---

func elementID(s string) (string, error) {
	id, ok := strings.CutPrefix(s, "SPDXRef-")
	if !ok || id == "" {
		return "", fmt.Errorf("invalid SPDX element ID")
	}
	return id, nil
}

// docElementID returns the element part ("" for NONE, NOASSERTION or a bare
// DocumentRef).
func docElementID(s string) (string, error) {
	if s == "NONE" || s == "NOASSERTION" {
		return "", nil
	}
	if strings.HasPrefix(s, "DocumentRef-") {
		doc, el, ok := strings.Cut(s, ":")
		if strings.TrimPrefix(doc, "DocumentRef-") == "" {
			return "", fmt.Errorf("invalid SPDX document reference")
		}
		if !ok {
			return "", nil
		}
		s = el
	}
	return elementID(s)
}

type spdxRef struct {
	Category string `json:"referenceCategory"`
	Type     string `json:"referenceType"`
	Locator  string `json:"referenceLocator"`
}

type spdxPackage struct {
	SPDXID       string   `json:"SPDXID"`
	Name         string   `json:"name"`
	Version      string   `json:"versionInfo"`
	SourceInfo   string   `json:"sourceInfo"`
	Attributions []string `json:"attributionTexts"`
	Annotations  []struct {
		Comment string `json:"comment"`
	} `json:"annotations"`
	ExternalRefs []spdxRef `json:"externalRefs"`
}

type spdxRel struct {
	A    string `json:"spdxElementId"`
	B    string `json:"relatedSpdxElement"`
	Type string `json:"relationshipType"`
}

// spdxDoc: what both SPDX readers (JSON, tag-value) produce.
type spdxDoc struct {
	Version  string `json:"spdxVersion"`
	Creation *struct {
		Creators []string `json:"creators"`
	} `json:"creationInfo"`
	Packages      []*spdxPackage `json:"packages"`
	Relationships []*spdxRel     `json:"relationships"`
	Describes     []string       `json:"documentDescribes"`
	// jsonReader: tools-golang's JSON readers (2.2, 2.3) turn "_" into "-" in
	// a reference category; its tag-value readers do not.
	jsonReader bool
}

func decodeSPDX(b []byte) (*bom, error) {
	var doc spdxDoc
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("SPDX: %w", err)
	}
	doc.jsonReader = true
	return spdxBOM(&doc)
}

func spdxBOM(doc *spdxDoc) (*bom, error) {
	switch doc.Version {
	case "SPDX-2.1", "SPDX-2.2", "SPDX-2.3":
	default:
		return nil, fmt.Errorf("unsupported SPDX version")
	}
	// tools-golang: explicit relationships, then documentDescribes as
	// DOCUMENT DESCRIBES x (it drops duplicates; a repeated DESCRIBES changes
	// neither the root nor the package relationships, so it is kept here).
	type rel struct{ a, b, typ string }
	var rels []rel
	for _, r := range doc.Relationships {
		if r == nil {
			continue
		}
		a, err := docElementID(r.A)
		if err != nil {
			return nil, err
		}
		bb, err := docElementID(r.B)
		if err != nil {
			return nil, err
		}
		rels = append(rels, rel{a, bb, r.Type})
	}
	for _, id := range doc.Describes {
		e, err := docElementID(id)
		if err != nil {
			return nil, err
		}
		rels = append(rels, rel{"DOCUMENT", e, "DESCRIBES"})
	}
	rootID := ""
	for _, r := range rels {
		if r.a == "DOCUMENT" && r.typ == "DESCRIBES" {
			rootID = r.b
			break
		}
	}
	trivySBOM := false
	if doc.Creation != nil {
		for _, c := range doc.Creation.Creators {
			if t, v, ok := strings.Cut(c, ": "); ok && t == "Tool" && strings.HasPrefix(v, "trivy") {
				trivySBOM = true
			}
		}
	}
	d := &bom{rels: map[*component][]*component{}}
	byID := map[string]*component{}
	for _, p := range doc.Packages {
		if p == nil {
			continue
		}
		id, err := elementID(p.SPDXID)
		if err != nil {
			return nil, err
		}
		c := &component{typ: "library", name: p.Name, version: p.Version}
		// Trivy SourcePackagePrefix: "built package from: <name> <version>"
		if src, ok := strings.CutPrefix(p.SourceInfo, "built package from: "); ok {
			c.srcName, c.srcVersion, _ = strings.Cut(src, " ")
		}
		switch {
		case strings.HasPrefix(id, "OperatingSystem"):
			c.typ = "os"
		case strings.HasPrefix(id, "Application"):
			c.typ = "application"
		}
		for _, r := range p.ExternalRefs {
			cat := r.Category
			if doc.jsonReader && doc.Version != "SPDX-2.1" {
				cat = strings.ReplaceAll(cat, "_", "-") // tools-golang 2.2/2.3 readers
			}
			if r.Type != "purl" || cat != "PACKAGE-MANAGER" {
				continue
			}
			pu, err := ParsePURL(r.Locator)
			if err != nil {
				return nil, fmt.Errorf("SPDX package purl: %w", err)
			}
			c.purl = &pu
			break
		}
		var props []string
		if len(p.Annotations) > 0 {
			for _, a := range p.Annotations {
				props = append(props, a.Comment)
			}
		} else {
			props = p.Attributions
		}
		for _, pr := range props {
			if k, v, ok := strings.Cut(pr, ": "); ok {
				c.properties = append(c.properties, property{k, v})
			}
		}
		if trivySBOM && c.typ == "application" && p.SourceInfo != "" {
			c.properties = append(c.properties, property{"Type", p.Name})
			c.name = p.SourceInfo
		}
		c.root = id == rootID
		d.comps = append(d.comps, c)
		byID[id] = c
	}
	for _, r := range rels {
		if r.typ == "DESCRIBES" || r.typ == "DESCRIBE" {
			continue
		}
		a, ok1 := byID[r.a]
		b, ok2 := byID[r.b]
		if ok1 && ok2 {
			d.rels[a] = append(d.rels[a], b)
		}
	}
	return d, nil
}

// --- components -> packages (Trivy pkg/sbom/io/decode.go) ---

// langEcosystem: Trivy's LangType per purl type, as the API's ecosystem name;
// checked false when no advisory source here covers it yet.
func langEcosystem(t string) (eco string, checked, ok bool) {
	switch t {
	case "composer":
		return "Packagist", true, true
	case "maven":
		return "Maven", true, true
	case "gem":
		return "RubyGems", true, true
	case "pypi":
		return "PyPI", true, true
	case "golang":
		return "Go", true, true
	case "npm":
		return "npm", true, true
	case "cargo":
		return "crates.io", true, true
	case "nuget":
		return "NuGet", true, true
	case "hex":
		return "Hex", true, true
	case "pub":
		return "Pub", true, true
	case "julia":
		return "Julia", true, true
	case "conda":
		return "conda", false, true
	case "swift":
		return "Swift", false, true
	case "cocoapods":
		return "CocoaPods", false, true
	case "conan":
		return "Conan", false, true
	case "bitnami":
		return "Bitnami", true, true
	case "k8s":
		return "Kubernetes", false, true
	}
	return "", false, false
}

func osType(t string) bool {
	return t == "apk" || t == "deb" || t == "rpm" || t == "bottlerocket"
}

// purlName: Trivy purl.Package().Name.
func purlName(p *PURL) string {
	name := p.Name
	if p.Namespace != "" && !osType(p.Type) {
		if p.Type == "maven" || p.Type == "gradle" {
			name = p.Namespace + ":" + p.Name
		} else {
			name = p.Namespace + "/" + p.Name
		}
	}
	if p.Subpath != "" && p.Type == "cocoapods" {
		name = p.Name + "/" + p.Subpath
	}
	return name
}

// hasTypeProperty: Trivy decodeApplication keeps the last "Type" value, and
// the BOM sorts properties by (name, value) when the component is added, so
// the largest value wins: any non-empty one makes an application container.
func (c *component) hasTypeProperty() bool {
	for _, p := range c.properties {
		if p.name == "Type" && p.value != "" {
			return true
		}
	}
	return false
}

func (d *bom) packages() (*Result, error) {
	res := &Result{}
	var osComp *component
	var apps []*component
	isPkg := map[*component]bool{}
	for _, c := range d.comps {
		switch {
		case c.typ == "os":
			// Trivy takes the first OS component of a map walk (random);
			// here the first in document order.
			if osComp == nil {
				osComp = c
				res.OS = &OS{Family: c.name, Name: c.version}
			}
			continue
		case c.typ == "application" && c.hasTypeProperty():
			apps = append(apps, c)
			continue
		}
		if c.typ != "library" && c.purl == nil {
			continue
		}
		if c.purl == nil {
			res.Skipped++ // Trivy: a component without purl is skipped
			continue
		}
		if _, _, lang := langEcosystem(c.purl.Type); !lang && !osType(c.purl.Type) {
			res.Skipped++ // Trivy: unsupported purl type
			continue
		}
		isPkg[c] = true
	}
	// Orphan OS packages (not reached from the OS or an application) must be
	// of one purl type (Trivy: "multiple types of OS packages ... not supported").
	reached := map[*component]bool{}
	var walk func(c *component)
	walk = func(c *component) {
		for _, ch := range d.rels[c] {
			if isPkg[ch] && !reached[ch] {
				reached[ch] = true
				walk(ch)
			}
		}
	}
	if osComp != nil {
		walk(osComp)
	}
	for _, a := range apps {
		walk(a)
	}
	orphanOS := map[string]bool{}
	for _, c := range d.comps {
		if isPkg[c] && !reached[c] && osType(c.purl.Type) {
			orphanOS[c.purl.Type] = true
		}
	}
	if len(orphanOS) > 1 {
		return nil, errors.New("multiple types of OS packages in SBOM are not supported")
	}
	for _, c := range d.comps {
		if !isPkg[c] {
			continue
		}
		p := c.purl
		name := c.name
		switch {
		case p.Type == "cocoapods" || p.Type == "maven" || p.Type == "gradle" || p.Type == "bitnami":
			name = purlName(p)
		case c.group != "":
			name = c.group + "/" + c.name
		}
		pk := model.Package{Name: strings.TrimSpace(name), Version: strings.TrimSpace(p.Version)}
		if !validField(pk.Name, 214) || !validField(pk.Version, 100) {
			res.Skipped++
			continue
		}
		if osType(p.Type) {
			op, err := osPackage(c, pk.Name)
			if err != nil {
				return nil, err
			}
			res.OSPackages = append(res.OSPackages, op)
			continue
		}
		eco, checked, _ := langEcosystem(p.Type)
		pk.Ecosystem = eco
		switch {
		case c.root && p.Type != "bitnami":
			// The document's own project: its name is not sent (Trivy
			// matches it; a Bitnami root is the published component itself).
			res.LocalNotSent++
		case !checked && eco == "conda":
			pk.UncheckedReason = ReasonConda
			res.Unchecked = append(res.Unchecked, pk)
		case !checked:
			res.Unchecked = append(res.Unchecked, pk)
		default:
			res.Packages = append(res.Packages, pk)
		}
	}
	return res, nil
}

func validField(s string, max int) bool {
	if s == "" || len(s) > max {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// osPackage: Trivy purl.Package (arch, modularitylabel, epoch qualifiers; RPM
// version split at the last "-") and fillPkgFieldsFromComponentProps.
func osPackage(c *component, name string) (OSPackage, error) {
	p := c.purl
	op := OSPackage{Type: p.Type, Name: name, Version: p.Version, SrcEpoch: -1,
		Arch: p.Qualifiers["arch"], Modularity: p.Qualifiers["modularitylabel"],
		InfoSrcName: c.srcName, InfoSrcVersion: c.srcVersion}
	if e, err := strconv.Atoi(p.Qualifiers["epoch"]); err == nil {
		op.Epoch = e
	}
	if p.Type == "rpm" {
		// go-rpm-version NewVersion: epoch before ":", release after the FIRST
		// "-" (lab oracle: 1.2-3-4.el9 -> 1.2 / 3-4.el9)
		v := p.Version
		if i := strings.Index(v, ":"); i >= 0 {
			v = v[i+1:]
		}
		if i := strings.Index(v, "-"); i >= 0 {
			op.Version, op.Release = v[:i], v[i+1:]
		} else {
			op.Version = v
		}
	}
	// Trivy sorts a component's properties by (name, value) when it is added:
	// for a repeated single-valued property the largest value is the last.
	props := append([]property(nil), c.properties...)
	sort.SliceStable(props, func(i, j int) bool {
		if props[i].name != props[j].name {
			return props[i].name < props[j].name
		}
		return props[i].value < props[j].value
	})
	for _, pr := range props {
		switch pr.name {
		case "SrcName":
			op.SrcName = pr.value
		case "SrcVersion":
			op.SrcVersion = pr.value
		case "SrcRelease":
			op.SrcRelease = pr.value
		case "SrcEpoch":
			e, err := strconv.Atoi(pr.value)
			if err != nil {
				return OSPackage{}, errors.New("invalid src epoch") // Trivy fails the document
			}
			op.SrcEpoch = e
		case "Modularitylabel":
			op.Modularity = pr.value
		case "RepositoryClass":
			op.ThirdParty = pr.value == "third-party"
		case "ContentSet":
			op.ContentSets = append(op.ContentSets, pr.value)
		case "NVR":
			op.NVR = pr.value
		case "Arch":
			op.BuildArch = pr.value
		}
	}
	return op, nil
}
