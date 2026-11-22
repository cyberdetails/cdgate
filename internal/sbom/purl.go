package sbom

// Package URL parsing as github.com/package-url/packageurl-go v0.1.7 FromString
// does it (Trivy 00b7394 reads every purl with that library): scheme, leading
// slashes, subpath, qualifiers, type, then namespace/name@version, all
// percent-decoded, and the type's own normalisation and validity rules.

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// PURL is a parsed package URL.
type PURL struct {
	Type, Namespace, Name, Version, Subpath string
	Qualifiers                              map[string]string
}

func lowerASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}

// ParsePURL parses s; any error means the library would refuse it.
func ParsePURL(s string) (PURL, error) {
	if len(s) < 4 || lowerASCII(s[:4]) != "pkg:" {
		return PURL{}, errors.New("purl scheme is not \"pkg\"")
	}
	rest := s[4:]
	for len(rest) > 0 && rest[0] == '/' {
		rest = rest[1:]
	}
	var p PURL
	if i := strings.IndexByte(rest, '#'); i != -1 {
		sub := rest[i+1:]
		if strings.Contains(sub, "%") {
			segs := strings.Split(sub, "/")
			for j, seg := range segs {
				d, err := url.PathUnescape(seg)
				if err != nil {
					return PURL{}, err
				}
				segs[j] = d
			}
			sub = strings.Join(segs, "/")
		}
		p.Subpath = sub
		rest = rest[:i]
	}
	var rawQuery string
	if i := strings.IndexByte(rest, '?'); i != -1 {
		rawQuery = rest[i+1:]
		rest = rest[:i]
	}
	typ, rest, ok := strings.Cut(rest, "/")
	if !ok {
		return PURL{}, errors.New("purl is missing type or name")
	}
	p.Type = lowerASCII(typ)
	q, err := parseQualifiers(rawQuery)
	if err != nil {
		return PURL{}, err
	}
	if p.Namespace, p.Name, p.Version, err = splitNSNameVersion(p.Type, rest); err != nil {
		return PURL{}, err
	}
	return p.normalize(q)
}

type qualifier struct{ key, value string }

func parseQualifiers(raw string) ([]qualifier, error) {
	var q []qualifier
	for raw != "" {
		var kv string
		kv, raw, _ = strings.Cut(raw, "&")
		if strings.Contains(kv, ";") {
			return nil, errors.New("invalid semicolon separator in query")
		}
		if kv == "" {
			continue
		}
		k, v, _ := strings.Cut(kv, "=")
		k = strings.ToLower(k)
		if !validQualifierKey(k) {
			return nil, fmt.Errorf("invalid qualifier key")
		}
		d, err := url.PathUnescape(v)
		if err != nil {
			return nil, err
		}
		q = append(q, qualifier{k, d})
	}
	return q, nil
}

func splitNSNameVersion(typ, rest string) (ns, name, version string, err error) {
	if typ != "npm" && strings.HasPrefix(rest, "@") {
		return "", "", "", errors.New("purl is missing name")
	}
	if typ == "npm" && strings.HasPrefix(rest, "@") && !strings.Contains(rest, "/") {
		return "", "", "", errors.New("purl is missing name")
	}
	if strings.LastIndex(rest, "@") > 0 {
		i := strings.LastIndex(rest, "@")
		rest, version = rest[:i], rest[i+1:]
		if version, err = url.PathUnescape(version); err != nil {
			return "", "", "", err
		}
	}
	i := strings.LastIndex(rest, "/")
	name = rest[i+1:]
	if i >= 0 {
		rest = rest[:i]
	} else {
		rest = ""
	}
	if name, err = url.PathUnescape(name); err != nil {
		return "", "", "", err
	}
	var segs []string
	for _, seg := range strings.Split(rest, "/") {
		if seg == "" {
			continue
		}
		d, err := url.PathUnescape(seg)
		if err != nil {
			return "", "", "", err
		}
		segs = append(segs, d)
	}
	ns = strings.Join(segs, "/")
	if name == "" {
		return "", "", "", errors.New("purl is missing name")
	}
	return ns, name, version, nil
}

func (p PURL) normalize(q []qualifier) (PURL, error) {
	if !validType(p.Type) {
		return PURL{}, errors.New("invalid type")
	}
	p.Namespace = strings.Trim(p.Namespace, "/")
	p.Qualifiers = map[string]string{}
	for _, x := range q {
		if x.value == "" {
			continue // an empty value is the key omitted
		}
		if _, dup := p.Qualifiers[x.key]; dup {
			return PURL{}, errors.New("duplicate qualifier key")
		}
		p.Qualifiers[x.key] = x.value
	}
	for i, s := range strings.Split(p.Subpath, "/") {
		if (s == "." || s == "..") && i != 0 {
			return PURL{}, errors.New("invalid Package URL subpath")
		}
	}
	p.Subpath = strings.Trim(p.Subpath, "/")
	switch p.Type {
	case "alpm", "apk", "bitbucket", "brew", "composer", "deb", "github", "golang", "rpm", "qpkg":
		p.Namespace = strings.ToLower(p.Namespace)
	}
	switch p.Type {
	case "alpm", "apk", "bitbucket", "bitnami", "brew", "chrome-extension", "composer", "deb", "github", "golang":
		p.Name = strings.ToLower(p.Name)
	case "pypi":
		p.Name = strings.ToLower(strings.ReplaceAll(p.Name, "_", "-"))
	case "mlflow":
		if repo, ok := p.Qualifiers["repository_url"]; ok && strings.Contains(repo, "databricks") {
			p.Name = strings.ToLower(p.Name)
		}
	}
	if p.Type == "huggingface" {
		p.Version = strings.ToLower(p.Version)
	}
	return p, customRules(p)
}

func customRules(p PURL) error {
	switch p.Type {
	case "chrome-extension":
		if p.Namespace != "" || len(p.Name) != 32 || strings.Trim(p.Name, "abcdefghijklmnopqrstuvwxyz") != "" {
			return errors.New("invalid chrome-extension purl")
		}
		if p.Version != "" && !chromeVersion(p.Version) {
			return errors.New("invalid chrome-extension version")
		}
	case "cpan":
		if strings.ToUpper(p.Namespace) != p.Namespace || strings.Contains(p.Name, "::") {
			return errors.New("invalid cpan purl")
		}
	case "julia":
		if _, ok := p.Qualifiers["uuid"]; p.Namespace != "" || !ok {
			return errors.New("invalid julia purl")
		}
	case "otp", "vcpkg":
		if p.Namespace != "" {
			return errors.New("namespace not allowed")
		}
	case "swift", "vscode-extension":
		if p.Namespace == "" {
			return errors.New("namespace is required")
		}
	}
	return nil
}

// chromeVersion: ^\d+(\.\d+){0,3}$
func chromeVersion(v string) bool {
	segs := strings.Split(v, ".")
	if len(segs) > 4 {
		return false
	}
	for _, s := range segs {
		if s == "" || strings.Trim(s, "0123456789") != "" {
			return false
		}
	}
	return true
}

func validQualifierKey(k string) bool {
	if k == "" {
		return false
	}
	for i := 0; i < len(k); i++ {
		c := k[i]
		alpha := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '.' || c == '-' || c == '_'
		if !alpha && (i == 0 || c < '0' || c > '9') {
			return false
		}
	}
	return true
}

func validType(t string) bool {
	if t == "" {
		return false
	}
	for i := 0; i < len(t); i++ {
		c := t[i]
		alpha := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '.' || c == '-' || c == '+'
		if !alpha && (i == 0 || c < '0' || c > '9') {
			return false
		}
	}
	return true
}
