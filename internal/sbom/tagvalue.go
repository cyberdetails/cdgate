package sbom

// SPDX tag-value documents, read as spdx/tools-golang v0.5.7 does (Trivy
// 00b7394 decodes them through tagvalue.Read):
//
//   - lines (tagvalue/reader): leading space trimmed, blank and "#" lines
//     skipped, "Tag: Value" split at the first colon (none: error), a value
//     between <text> and </text> may span lines; a line longer than 64 KiB
//     fails (bufio.Scanner); an unfinished <text> fails.
//   - the version is the first SPDXVersion; 2.1, 2.2 and 2.3 are read.
//   - sections (v2_3/tagvalue/reader parser.go): document start, creation
//     info, package, file, snippet, other license, review. A package is
//     added when its SPDXID is read; a package or file without SPDXID before
//     the next one fails; an unknown tag in the creation info or package
//     section fails; Creator must be Person, Organization or Tool; an
//     ExternalRef has exactly three fields; a Relationship has three fields
//     and valid identifiers. Annotations belong to the document, not to a
//     package (so a package's properties come from PackageAttributionText).
//
// Deliberate difference: tags inside file, snippet, other-license and review
// sections are not validated one by one (tools-golang rejects an unknown
// one); nothing read from them reaches a package.

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"strings"
	"unicode"
)

type tvPair struct{ tag, value string }

// tvLines: tools-golang tagvalue/reader ReadTagValues.
func tvLines(b []byte) ([]tvPair, error) {
	var out []tvPair
	s := bufio.NewScanner(bytes.NewReader(b))
	midtext := false
	var tag, val string
	for s.Scan() {
		line := s.Text()
		if midtext {
			before, _, found := strings.Cut(line, "</text>")
			if !found {
				val += line + "\n"
				continue
			}
			out = append(out, tvPair{tag, val + before})
			midtext = false
			continue
		}
		l := strings.TrimLeftFunc(line, unicode.IsSpace)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		k, v, ok := strings.Cut(l, ":")
		if !ok {
			return nil, errors.New("SPDX tag-value: line without colon")
		}
		tag = strings.TrimSpace(k)
		if _, after, ok := strings.Cut(v, "<text>"); ok {
			if text, _, closed := strings.Cut(after, "</text>"); closed {
				out = append(out, tvPair{tag, text})
			} else {
				val, midtext = after+"\n", true
			}
			continue
		}
		out = append(out, tvPair{tag, strings.TrimSpace(v)})
	}
	if err := s.Err(); err != nil {
		return nil, fmt.Errorf("SPDX tag-value: %w", err)
	}
	if midtext {
		return nil, errors.New("SPDX tag-value: unfinished <text>")
	}
	return out, nil
}

// tvElementID: extractElementID (prefix, no colon, not empty).
func tvElementID(v string) (string, error) {
	id, ok := strings.CutPrefix(v, "SPDXRef-")
	if !ok || id == "" || strings.Contains(v, ":") {
		return "", errors.New("SPDX tag-value: invalid element identifier")
	}
	return id, nil
}

// tvDocElementID: extractDocElementID / extractDocElementSpecial.
func tvDocElementID(v string, special bool) (string, error) {
	if special && (v == "NONE" || v == "NOASSERTION") {
		return "", nil
	}
	if strings.HasPrefix(v, "DocumentRef-") {
		parts := strings.Split(v, ":")
		if len(parts) != 2 || strings.TrimPrefix(parts[0], "DocumentRef-") == "" {
			return "", errors.New("SPDX tag-value: invalid document reference")
		}
		v = parts[1]
	}
	return tvElementID(v)
}

// packageTags: the tags the package section accepts (parse_package.go).
var packageTags = map[string]bool{
	"PackageVersion": true, "PackageFileName": true, "PackageSupplier": true, "PackageOriginator": true,
	"PackageDownloadLocation": true, "FilesAnalyzed": true, "PackageVerificationCode": true,
	"PackageChecksum": true, "PackageHomePage": true, "PackageSourceInfo": true, "PackageLicenseConcluded": true,
	"PackageLicenseInfoFromFiles": true, "PackageLicenseDeclared": true, "PackageLicenseComments": true,
	"PackageCopyrightText": true, "PackageSummary": true, "PackageDescription": true, "PackageComment": true,
	"PrimaryPackagePurpose": true, "ReleaseDate": true, "BuiltDate": true, "ValidUntilDate": true,
	"PackageAttributionText": true, "ExternalRef": true, "ExternalRefComment": true,
}

var annotationTags = map[string]bool{"Annotator": true, "AnnotationDate": true, "AnnotationType": true,
	"SPDXREF": true, "AnnotationComment": true}

var startTags = map[string]bool{"DocumentComment": true, "SPDXVersion": true, "DataLicense": true, "SPDXID": true,
	"DocumentName": true, "DocumentNamespace": true, "ExternalDocumentRef": true}

// decodeSPDXTagValue reads a tag-value document into the SPDX JSON reader's form.
func decodeSPDXTagValue(b []byte) (*bom, error) {
	pairs, err := tvLines(b)
	if err != nil {
		return nil, err
	}
	if len(pairs) == 0 {
		return nil, errors.New("SPDX tag-value: no tag values found")
	}
	doc := &spdxDoc{}
	for _, p := range pairs {
		if p.tag == "SPDXVersion" {
			doc.Version = p.value
			break
		}
	}
	switch doc.Version {
	case "SPDX-2.1", "SPDX-2.2", "SPDX-2.3":
	default:
		return nil, errors.New("unsupported SPDX version")
	}
	const (
		stStart = iota
		stCreation
		stPackage
		stFile
		stSnippet
		stOther
		stReview
	)
	st := stStart
	var pkg *spdxPackage
	pkgHasID, fileOpen, fileHasID := false, false, false
	newPackage := func(name string) error {
		if pkg != nil && !pkgHasID {
			return errors.New("SPDX tag-value: package without SPDXID")
		}
		pkg, pkgHasID = &spdxPackage{Name: name}, false
		return nil
	}
	for _, p := range pairs {
		tag, value := p.tag, p.value
		if st == stStart && !startTags[tag] {
			st = stCreation
		}
		if (st == stFile || st == stSnippet) && tag == "PackageName" {
			if fileOpen && !fileHasID {
				return nil, errors.New("SPDX tag-value: file without SPDXID")
			}
			fileOpen, st = false, stPackage
		}
		switch {
		case tag == "Relationship": // every section after the start one accepts it
			f := strings.Fields(value)
			if len(f) != 3 {
				return nil, errors.New("SPDX tag-value: invalid relationship")
			}
			a, err := tvDocElementID(f[0], false)
			if err != nil {
				return nil, err
			}
			bb, err := tvDocElementID(f[2], true)
			if err != nil {
				return nil, err
			}
			doc.Relationships = append(doc.Relationships, &spdxRel{A: "SPDXRef-" + a, B: refOrSpecial(f[2], bb), Type: f[1]})
			continue
		case tag == "RelationshipComment" || annotationTags[tag]:
			continue // annotations are the document's in tag-value
		}
		switch st {
		case stStart:
			if tag == "SPDXID" {
				if _, err := tvElementID(value); err != nil {
					return nil, err
				}
			}
		case stCreation:
			switch tag {
			case "LicenseListVersion", "Created", "CreatorComment":
			case "Creator":
				k, v, ok := strings.Cut(value, ":")
				k, v = strings.TrimSpace(k), strings.TrimSpace(v)
				if !ok || (k != "Person" && k != "Organization" && k != "Tool") {
					return nil, errors.New("SPDX tag-value: invalid Creator")
				}
				if doc.Creation == nil {
					doc.Creation = &struct {
						Creators []string `json:"creators"`
					}{}
				}
				doc.Creation.Creators = append(doc.Creation.Creators, k+": "+v)
			case "PackageName":
				if fileOpen && !fileHasID {
					return nil, errors.New("SPDX tag-value: file without SPDXID")
				}
				st = stPackage
				if err := newPackage(value); err != nil {
					return nil, err
				}
			case "FileName":
				st, pkg, fileOpen, fileHasID = stFile, nil, true, false
			case "LicenseID":
				st = stOther
			case "Reviewer":
				st = stReview
			case "DocumentComment":
				st = stStart
			default:
				return nil, fmt.Errorf("SPDX tag-value: unknown tag in creation info")
			}
		case stPackage:
			switch {
			case tag == "PackageName":
				if pkg == nil || pkg.Name != "" {
					if err := newPackage(value); err != nil {
						return nil, err
					}
				} else {
					pkg.Name = value
				}
			case tag == "SPDXID":
				if _, err := tvElementID(value); err != nil {
					return nil, err
				}
				pkg.SPDXID, pkgHasID = value, true
				doc.Packages = append(doc.Packages, pkg)
			case tag == "PackageVersion":
				pkg.Version = value
			case tag == "PackageSourceInfo":
				pkg.SourceInfo = value
			case tag == "PackageAttributionText":
				pkg.Attributions = append(pkg.Attributions, value)
			case tag == "ExternalRef":
				f := strings.Fields(value)
				if len(f) != 3 {
					return nil, errors.New("SPDX tag-value: ExternalRef needs three fields")
				}
				pkg.ExternalRefs = append(pkg.ExternalRefs, spdxRef{Category: f[0], Type: f[1], Locator: f[2]})
			case tag == "FileName":
				st, fileOpen, fileHasID = stFile, true, false
			case tag == "LicenseID":
				st = stOther
			case tag == "Reviewer":
				st = stReview
			case packageTags[tag]:
			default:
				return nil, fmt.Errorf("SPDX tag-value: unknown tag in package section")
			}
		case stFile, stSnippet:
			switch tag {
			case "FileName":
				if fileOpen && !fileHasID {
					return nil, errors.New("SPDX tag-value: file without SPDXID")
				}
				st, fileOpen, fileHasID = stFile, true, false
			case "SPDXID":
				if st == stFile {
					if _, err := tvElementID(value); err != nil {
						return nil, err
					}
					fileHasID = true
				}
			case "SnippetSPDXID":
				st = stSnippet
			case "LicenseID":
				st = stOther
			case "Reviewer":
				st = stReview
			}
		case stOther:
			switch tag {
			case "Reviewer":
				st = stReview
			case "PackageName", "FileName", "SPDXID":
				return nil, fmt.Errorf("SPDX tag-value: %s in an other-license section", tag)
			}
		case stReview:
			switch tag {
			case "PackageName", "FileName", "SPDXID", "LicenseID":
				return nil, fmt.Errorf("SPDX tag-value: %s in a review section", tag)
			}
		}
	}
	if pkg != nil && !pkgHasID {
		return nil, errors.New("SPDX tag-value: package without SPDXID")
	}
	if fileOpen && !fileHasID {
		return nil, errors.New("SPDX tag-value: file without SPDXID")
	}
	return spdxBOM(doc)
}

func refOrSpecial(raw, id string) string {
	if id == "" {
		return raw // NONE / NOASSERTION
	}
	return "SPDXRef-" + id
}
