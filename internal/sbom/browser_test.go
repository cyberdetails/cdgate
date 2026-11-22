package sbom

// Shared fixtures with the site's in-browser reader (cyberdetails.ui
// src/lib/sca-sbom.ts): both read testdata/* and testdata/browser/* and are
// tested against one expected file this test writes from Decode
// (CD_REGEN_FIXTURES=1 go test ./internal/sbom -run TestBrowserFixtures).
// CD_SBOM_CORPUS=<dir> CD_SBOM_CORPUS_OUT=<file> writes the same summary for a
// lab corpus that is not committed.

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

type browserPkg struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	Reason    string `json:"reason,omitempty"`
}

type browserCase struct {
	Format       string       `json:"format"`
	Error        bool         `json:"error"`
	NotRead      bool         `json:"not_read"`
	Packages     []browserPkg `json:"packages"`
	Unchecked    []browserPkg `json:"unchecked"`
	Skipped      int          `json:"skipped"`
	LocalNotSent int          `json:"local_not_sent"`
	OS           *OS          `json:"os"`
	OSPackages   int          `json:"os_packages"`
}

func browserSummary(b []byte) browserCase {
	c := browserCase{Format: Detect(b), Packages: []browserPkg{}, Unchecked: []browserPkg{}}
	res, err := Decode(b)
	if errors.Is(err, ErrNotRead) {
		c.NotRead = true
		return c
	}
	if err != nil {
		c.Error = true
		return c
	}
	for _, p := range res.Packages {
		c.Packages = append(c.Packages, browserPkg{p.Ecosystem, p.Name, p.Version, ""})
	}
	for _, p := range res.Unchecked {
		c.Unchecked = append(c.Unchecked, browserPkg{p.Ecosystem, p.Name, p.Version, p.UncheckedReason})
	}
	c.Skipped, c.LocalNotSent, c.OS, c.OSPackages = res.Skipped, res.LocalNotSent, res.OS, len(res.OSPackages)
	return c
}

func browserDirs(t *testing.T, dirs ...string) []byte {
	t.Helper()
	got := map[string]browserCase{}
	for _, dir := range dirs {
		ents, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range ents {
			if e.IsDir() || strings.HasSuffix(e.Name(), ".tsv") || strings.HasSuffix(e.Name(), "_expected.json") {
				continue
			}
			b, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				t.Fatal(err)
			}
			got[filepath.ToSlash(filepath.Join(filepath.Base(dir), e.Name()))] = browserSummary(b)
		}
	}
	keys := make([]string, 0, len(got))
	for k := range got {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	enc, err := json.MarshalIndent(got, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	return append(enc, '\n')
}

func TestBrowserFixtures(t *testing.T) {
	if dir := os.Getenv("CD_SBOM_CORPUS"); dir != "" {
		if err := os.WriteFile(os.Getenv("CD_SBOM_CORPUS_OUT"), browserDirs(t, dir), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	const want = "testdata/browser_expected.json"
	enc := browserDirs(t, "testdata", "testdata/browser")
	if os.Getenv("CD_REGEN_FIXTURES") == "1" {
		if err := os.WriteFile(want, enc, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	b, err := os.ReadFile(want)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b, enc) {
		t.Fatalf("%s is stale: regenerate with CD_REGEN_FIXTURES=1 and update the browser port", want)
	}
}
