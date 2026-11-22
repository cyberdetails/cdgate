package parse

// Shared fixtures with the site's in-browser reader (cyberdetails.ui
// src/lib/sca-lockfile.ts): both read testdata/browser/* and are tested
// against one expected file that this test writes from the Go parsers
// (CD_REGEN_FIXTURES=1 go test ./internal/parse -run TestBrowserFixtures).
// A change in a Go parser changes the expected file, and the browser test
// fails until its port follows.

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"testing"
)

const browserDir = "testdata/browser"
const browserExpected = "testdata/browser_expected.json"

type browserPkg struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Direct  bool   `json:"direct"`
}

type browserCase struct {
	Ecosystem string       `json:"ecosystem"`
	Error     bool         `json:"error"`
	Packages  []browserPkg `json:"packages"`
	Dev       []browserPkg `json:"packages_with_dev"`
}

func browserRun(t *testing.T, kind Kind, b []byte, dev bool) ([]browserPkg, bool) {
	t.Helper()
	pkgs, err := kind.Parse(bytes.NewReader(b), Options{IncludeDev: dev})
	if err != nil {
		return nil, true
	}
	out := []browserPkg{}
	for _, p := range pkgs {
		out = append(out, browserPkg{p.Name, p.Version, p.Direct})
	}
	return out, false
}

func TestBrowserFixtures(t *testing.T) {
	got := map[string]browserCase{}
	err := filepath.WalkDir(browserDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(browserDir, p)
		rel = filepath.ToSlash(rel)
		kind, ok := Lookup(path.Base(rel))
		if !ok {
			t.Fatalf("%s: not a supported file name", rel)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		c := browserCase{Ecosystem: kind.Ecosystem}
		var e1, e2 bool
		c.Packages, e1 = browserRun(t, kind, b, false)
		c.Dev, e2 = browserRun(t, kind, b, true)
		if e1 != e2 {
			t.Fatalf("%s: error depends on IncludeDev", rel)
		}
		c.Error = e1
		got[rel] = c
		return nil
	})
	if err != nil {
		t.Fatal(err)
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
	enc = append(enc, '\n')
	if os.Getenv("CD_REGEN_FIXTURES") == "1" {
		if err := os.WriteFile(browserExpected, enc, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(browserExpected)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(want, enc) {
		t.Fatalf("%s is stale: regenerate with CD_REGEN_FIXTURES=1 and update the browser port (%d cases)", browserExpected, len(keys))
	}
	// the fixtures must exercise both outcomes
	errs := 0
	for _, c := range got {
		if c.Error {
			errs++
		}
	}
	if errs == 0 || errs == len(got) {
		t.Fatalf("fixtures should include both readable and rejected files (%d of %d rejected)", errs, len(got))
	}
}
