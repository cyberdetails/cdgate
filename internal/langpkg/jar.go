package langpkg

// Java archives (trivy 00b7394 pkg/fanal/analyzer/language/java/jar,
// pkg/dependency/parser/java/jar): every valid META-INF/.../pom.properties in
// the archive and in nested .jar/.war/.ear archives is a Maven package
// "groupId:artifactId" at its version, reported at the archive's path (nested
// ones at "outer.jar/inner/path.jar").
//
// When no pom.properties matches the archive's own file name, Trivy identifies
// the archive through its Java DB: a groupId:artifactId from MANIFEST.MF
// checked for existence, else the archive's SHA-1, else an artifactId-version
// file name. That database is a 1 GB download and is not used here, so such an
// archive is reported unchecked (with its SHA-1 and the hints Trivy would have
// used), never as clean. An archive with no hint at all (an application's own
// jar, usually) is counted, not listed.
//
// Untrusted input: depth, per-entry and total uncompressed sizes are capped
// (Trivy has no caps); nothing is written to disk.

import (
	"archive/zip"
	"bufio"
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"io"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

// Reasons a Java archive is reported unchecked.
const (
	JarNeedsJavaDB = "Java archive without a matching pom.properties: Trivy identifies it with its Java DB (MANIFEST.MF, SHA-1, file name), which is not used here"
	JarTooLarge    = "Java archive larger than this scanner reads"
	JarUnreadable  = "Java archive that could not be read"
)

const (
	maxJarDepth       = 8
	maxJarNestedBytes = 1 << 30 // all nested archives of one outer archive, uncompressed
	maxJarEntryBytes  = 1 << 20 // one pom.properties
	maxManifestSize   = 10 << 20
)

// Trivy jarFileRegEx.
var jarFileRegEx = regexp.MustCompile(`^([a-zA-Z0-9\._-]*[^-*])-(\d\S*(?:-SNAPSHOT)?).jar$`)

// JarPackage is one Maven package found in an archive.
type JarPackage struct {
	Name, Version, FilePath string
}

// JarUnknown is an archive Trivy would have identified with its Java DB.
type JarUnknown struct {
	FilePath, SHA1 string
	// Hint is the groupId:artifactId:version from MANIFEST.MF, or
	// artifactId:version from the file name, that Trivy would have looked up.
	Hint string
}

// Jar is what one archive (with its nested archives) yields.
type Jar struct {
	Packages []JarPackage
	Unknown  []JarUnknown
	// NoIdentity counts archives without pom.properties, manifest or
	// versioned file name (Trivy would look up their SHA-1 only).
	NoIdentity int
	TooLarge   bool
	Err        string
}

type jarProps struct{ groupID, artifactID, version, filePath string }

func (p jarProps) valid() bool { return p.groupID != "" && p.artifactID != "" && p.version != "" }

// IsJar reports whether Trivy's jar analyzer wants the file (extension, any case).
func IsJar(p string) bool {
	ext := filepath.Ext(p)
	for _, e := range []string{".jar", ".war", ".ear", ".par"} {
		if strings.EqualFold(ext, e) {
			return true
		}
	}
	return false
}

// ReadJar parses an archive read in full; p is its path in the image.
func ReadJar(b []byte, p string) *Jar {
	j := &Jar{}
	budget := int64(maxJarNestedBytes)
	if err := j.parse(b, p, 0, &budget); err != nil {
		// Trivy: the archive fails as a whole, nothing it yielded is kept;
		// here it is reported unreadable instead of silently empty.
		return &Jar{Err: err.Error()}
	}
	j.Packages = removePackageDuplicates(j.Packages)
	return j
}

func parseFileName(filePath string) jarProps {
	m := jarFileRegEx.FindStringSubmatch(path.Base(filePath))
	if len(m) != 3 {
		return jarProps{filePath: filePath}
	}
	return jarProps{artifactID: m[1], version: m[2], filePath: filePath}
}

func (j *Jar) parse(b []byte, filePath string, depth int, budget *int64) error {
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		return errors.New("zip error: " + err.Error())
	}
	fileProps := parseFileName(filePath)
	var m manifest
	found := false
	for _, f := range zr.File {
		base := path.Base(f.Name)
		switch {
		case base == "pom.properties":
			props, err := parsePomProperties(f, filePath)
			if err != nil {
				return errors.New("pom.properties: " + err.Error())
			}
			if props.valid() {
				j.Packages = append(j.Packages, JarPackage{props.groupID + ":" + props.artifactID, props.version, filePath})
				if fileProps.artifactID == props.artifactID && fileProps.version == props.version {
					found = true
				}
			}
		case base == "MANIFEST.MF":
			if m, err = parseManifest(f); err != nil {
				return errors.New("MANIFEST.MF: " + err.Error())
			}
		case isArtifact(f.Name):
			full := path.Join(filePath, f.Name)
			if !strings.HasPrefix(full, path.Clean(filePath)) {
				continue // zip slip (Trivy skips it)
			}
			if depth+1 > maxJarDepth || f.UncompressedSize64 > uint64(*budget) {
				j.Err = "nested archives too deep or too large"
				continue
			}
			inner, err := readEntry(f, *budget)
			if err != nil {
				continue // Trivy: a nested archive that fails is skipped
			}
			*budget -= int64(len(inner))
			child := &Jar{}
			if err := child.parse(inner, full, depth+1, budget); err != nil {
				continue // Trivy: a nested archive that fails adds nothing
			}
			j.Packages = append(j.Packages, child.Packages...)
			j.Unknown = append(j.Unknown, child.Unknown...)
			j.NoIdentity += child.NoIdentity
			if child.Err != "" {
				j.Err = child.Err
			}
		}
	}
	if found {
		return nil
	}
	sum := sha1.Sum(b)
	u := JarUnknown{FilePath: filePath, SHA1: hex.EncodeToString(sum[:])}
	if mp := m.properties(filePath); mp.valid() {
		u.Hint = mp.groupID + ":" + mp.artifactID + ":" + mp.version
	} else if fileProps.artifactID != "" && fileProps.version != "" {
		u.Hint = fileProps.artifactID + ":" + fileProps.version
	}
	if u.Hint == "" {
		j.NoIdentity++
		return nil
	}
	j.Unknown = append(j.Unknown, u)
	return nil
}

// isArtifact is Trivy's nested-archive test (case-sensitive, no .par).
func isArtifact(name string) bool {
	ext := filepath.Ext(name)
	return ext == ".jar" || ext == ".ear" || ext == ".war"
}

func readEntry(f *zip.File, limit int64) ([]byte, error) {
	r, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer r.Close()
	b, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, errors.New("entry too large")
	}
	return b, nil
}

// parsePomProperties: Trivy reads "groupId=", "artifactId=", "version=" lines.
func parsePomProperties(f *zip.File, filePath string) (jarProps, error) {
	b, err := readEntry(f, maxJarEntryBytes)
	if err != nil {
		return jarProps{}, err
	}
	p := jarProps{filePath: filePath}
	s := bufio.NewScanner(bytes.NewReader(b))
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		switch {
		case strings.HasPrefix(line, "groupId="):
			p.groupID = strings.TrimPrefix(line, "groupId=")
		case strings.HasPrefix(line, "artifactId="):
			p.artifactID = strings.TrimPrefix(line, "artifactId=")
		case strings.HasPrefix(line, "version="):
			p.version = strings.TrimPrefix(line, "version=")
		}
	}
	return p, s.Err()
}

type manifest struct {
	implementationVersion, implementationTitle, implementationVendor, implementationVendorID string
	specificationTitle, specificationVersion, specificationVendor                            string
	bundleName, bundleVersion, bundleSymbolicName                                            string
}

func parseManifest(f *zip.File) (manifest, error) {
	r, err := f.Open()
	if err != nil {
		return manifest{}, err
	}
	defer r.Close()
	return parseManifestMainSection(io.LimitReader(r, maxManifestSize))
}

// scanManifestLines: Trivy's line splitter (LF, CRLF or a lone CR).
func scanManifestLines(data []byte, atEOF bool) (int, []byte, error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}
	for i, c := range data {
		switch c {
		case '\n':
			return i + 1, data[:i], nil
		case '\r':
			if i+1 == len(data) && !atEOF {
				return 0, nil, nil
			}
			adv := i + 1
			if i+1 < len(data) && data[i+1] == '\n' {
				adv++
			}
			return adv, data[:i], nil
		}
	}
	if atEOF {
		return len(data), data, nil
	}
	return 0, nil, nil
}

func parseManifestMainSection(r io.Reader) (manifest, error) {
	var m manifest
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 64*1024), maxManifestSize)
	s.Split(scanManifestLines)
	var attr strings.Builder
	for s.Scan() {
		line := s.Text()
		if line == "" {
			break
		}
		if cont, ok := strings.CutPrefix(line, " "); ok {
			attr.WriteString(cont)
			continue
		}
		m.add(attr.String())
		attr.Reset()
		attr.WriteString(line)
	}
	m.add(attr.String())
	return m, s.Err()
}

func (m *manifest) add(line string) {
	key, value, ok := strings.Cut(line, ":")
	value = strings.TrimSpace(value)
	if !ok || value == "" || strings.HasPrefix(value, "%") {
		return
	}
	switch key {
	case "Implementation-Version":
		m.implementationVersion = value
	case "Implementation-Title":
		m.implementationTitle = value
	case "Implementation-Vendor":
		m.implementationVendor = value
	case "Implementation-Vendor-Id":
		m.implementationVendorID = value
	case "Specification-Version":
		m.specificationVersion = value
	case "Specification-Title":
		m.specificationTitle = value
	case "Specification-Vendor":
		m.specificationVendor = value
	case "Bundle-Version":
		m.bundleVersion = value
	case "Bundle-Name":
		m.bundleName = value
	case "Bundle-SymbolicName":
		m.bundleSymbolicName = value
	}
}

// properties: Trivy's determineGroupID / ArtifactID / Version order.
func (m manifest) properties(filePath string) jarProps {
	var p jarProps
	switch {
	case m.implementationVendorID != "":
		p.groupID = m.implementationVendorID
	case m.bundleSymbolicName != "":
		p.groupID = m.bundleSymbolicName
		if i := strings.LastIndex(m.bundleSymbolicName, "."); i >= 0 {
			p.groupID = m.bundleSymbolicName[:i]
		}
	case m.implementationVendor != "":
		p.groupID = m.implementationVendor
	case m.specificationVendor != "":
		p.groupID = m.specificationVendor
	}
	switch {
	case m.implementationTitle != "":
		p.artifactID = m.implementationTitle
	case m.specificationTitle != "":
		p.artifactID = m.specificationTitle
	case m.bundleName != "":
		p.artifactID = m.bundleName
	}
	switch {
	case m.implementationVersion != "":
		p.version = m.implementationVersion
	case m.specificationVersion != "":
		p.version = m.specificationVersion
	case m.bundleVersion != "":
		p.version = m.bundleVersion
	}
	p.filePath = filePath
	return p
}

// removePackageDuplicates: one entry per name, path and version (Trivy compares
// versions with Maven equality; here the string, so "1.0" and "1.0.0" in one
// archive both stay — a duplicate row, never a lost one).
func removePackageDuplicates(pkgs []JarPackage) []JarPackage {
	seen := map[JarPackage]bool{}
	var out []JarPackage
	for _, p := range pkgs {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}
