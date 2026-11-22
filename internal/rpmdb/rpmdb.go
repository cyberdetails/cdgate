// Package rpmdb reads the installed-package database of an RPM-based system
// (RHEL, CentOS, Rocky, Alma, Oracle, Fedora, Amazon Linux) from memory.
//
// It follows github.com/knqyf263/go-rpmdb v0.1.1, the reader Trivy uses
// (pkg/fanal/analyzer/pkg/rpm), without its dependencies: the three on-disk
// formats are SQLite (rpm >= 4.16: only "SELECT blob FROM Packages" is
// needed, so a small read-only B-tree reader stands in for a SQL engine),
// NDB (SUSE) and Berkeley DB hash (older RHEL/CentOS/Amazon). Each value is an
// rpm header blob, imported with rpm's header.c checks (header.go).
//
// The input is untrusted: every offset is bounds-checked, page chains are
// cycle- and length-limited, and sizes are capped. Where go-rpmdb would loop
// forever or panic on a malformed database, an error is returned instead.
// Format detection is go-rpmdb's order: SQLite magic, NDB magic, else BDB.
package rpmdb

import (
	"bytes"
	"errors"
	"fmt"
	"path"
	"strconv"
)

// Paths Trivy reads (rpm.go requiredFiles, 00b7394).
var Paths = []string{
	"usr/lib/sysimage/rpm/Packages", "var/lib/rpm/Packages",
	"usr/lib/sysimage/rpm/Packages.db", "var/lib/rpm/Packages.db",
	"usr/lib/sysimage/rpm/rpmdb.sqlite", "var/lib/rpm/rpmdb.sqlite",
	"usr/share/rpm/rpmdb.sqlite",
}

// MaxBlob caps one package header (rpm's own limit is 256 MiB).
const MaxBlob = 64 << 20

// Package is what the analysis uses from one installed package.
type Package struct {
	Name, Version, Release, Arch string
	Epoch                        int    // EpochNum: 0 when the tag is absent
	SourceRpm                    string // "" for "(none)"
	Vendor                       string // "" for "(none)"
	ModularityLabel              string
	Files                        []string // installed file paths (DIRNAMES/DIRINDEXES/BASENAMES)
	// FilesInvalid: the file list tags are inconsistent. Trivy fails the
	// whole database then, but only for a vendor package (the only ones whose
	// files it lists); the caller applies that rule.
	FilesInvalid bool
	// FromRpmqa: the row comes from a distroless `rpm -qa` manifest
	// (ospkg.RpmqaPath), for which Trivy applies no vendor filter.
	FromRpmqa bool
}

// Parse reads every package from a database file's bytes.
func Parse(b []byte) ([]Package, error) {
	var blobs [][]byte
	var err error
	switch {
	case bytes.HasPrefix(b, []byte("SQLite format 3\x00")):
		blobs, err = sqliteBlobs(b)
	case len(b) >= 4 && le32(b) == ndbHeaderMagic:
		blobs, err = ndbBlobs(b)
	default:
		blobs, err = bdbBlobs(b)
	}
	if err != nil {
		return nil, err
	}
	out := make([]Package, 0, len(blobs))
	for i, bl := range blobs {
		ies, err := headerImport(bl)
		if err != nil {
			return nil, fmt.Errorf("package header %d: %w", i, err)
		}
		p, err := packageInfo(ies)
		if err != nil {
			return nil, fmt.Errorf("package header %d: %w", i, err)
		}
		out = append(out, p)
	}
	return out, nil
}

// EVR is the version string Trivy matches with: "epoch:version-release",
// the epoch only when non-zero (utils.FormatVersion).
func (p Package) EVR() string {
	v := p.Version
	if p.Release != "" {
		v += "-" + p.Release
	}
	if p.Epoch != 0 {
		v = strconv.Itoa(p.Epoch) + ":" + v
	}
	return v
}

var errNameFormat = errors.New("unexpected name format")

// SplitSourceRpm is Trivy's splitFileName: "foo-1.0-1.src.rpm" → foo, 1.0, 1.
func SplitSourceRpm(f string) (name, ver, rel string, err error) {
	f = trimSuffix(f, ".rpm")
	i := lastIndex(f, '.')
	if i < 0 {
		return "", "", "", errNameFormat
	}
	nvr := f[:i]
	i = lastIndex(nvr, '-')
	if i < 0 {
		return "", "", "", errNameFormat
	}
	nv, rel := nvr[:i], nvr[i+1:]
	i = lastIndex(nv, '-')
	if i < 0 {
		return "", "", "", errNameFormat
	}
	return nv[:i], nv[i+1:], rel, nil
}

func trimSuffix(s, suf string) string {
	if len(s) >= len(suf) && s[len(s)-len(suf):] == suf {
		return s[:len(s)-len(suf)]
	}
	return s
}

func lastIndex(s string, c byte) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == c {
			return i
		}
	}
	return -1
}

// installedFiles is go-rpmdb's InstalledFileNames.
func installedFiles(dirs []string, idx []int32, bases []string) ([]string, error) {
	if len(dirs) == 0 || len(idx) == 0 || len(bases) == 0 {
		return nil, nil
	}
	if len(idx) != len(bases) || len(dirs) > len(bases) {
		return nil, errors.New("invalid file list")
	}
	out := make([]string, 0, len(bases))
	for i, b := range bases {
		d := idx[i]
		if d < 0 || int(d) >= len(dirs) {
			return nil, errors.New("invalid file list")
		}
		out = append(out, path.Join(dirs[d], b))
	}
	return out, nil
}

func le32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}
func be32(b []byte) uint32 {
	return uint32(b[3]) | uint32(b[2])<<8 | uint32(b[1])<<16 | uint32(b[0])<<24
}
func be16(b []byte) uint16 { return uint16(b[1]) | uint16(b[0])<<8 }
func le16(b []byte) uint16 { return uint16(b[0]) | uint16(b[1])<<8 }
