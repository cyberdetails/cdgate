package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// An RPM-based root filesystem the API has no advisories for (Fedora): the
// packages are listed as unchecked, no request is made, and the result is
// INCOMPLETE with exit code 2 — never PASS.
func TestUncheckedRPMPackagesAreIncomplete(t *testing.T) {
	root := t.TempDir()
	f, err := os.Open("../../internal/rpmdb/testdata/sqlite.db.gz")
	if err != nil {
		t.Fatal(err)
	}
	g, _ := gzip.NewReader(f)
	db, _ := io.ReadAll(g)
	f.Close()
	for p, body := range map[string][]byte{"etc/fedora-release": []byte("Fedora release 40 (Forty)\n"),
		"var/lib/rpm/rpmdb.sqlite": db} {
		full := filepath.Join(root, filepath.FromSlash(p))
		os.MkdirAll(filepath.Dir(full), 0o755)
		if err := os.WriteFile(full, body, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	jsonOut := filepath.Join(t.TempDir(), "out.json")
	var out, errb bytes.Buffer
	// an unreachable API: a request would fail the scan with a different message
	code := run([]string{"scan", root, "--api", "http://127.0.0.1:1", "--json-out", jsonOut}, &out, &errb)
	if code != 2 {
		t.Fatalf("exit %d, stderr %s", code, errb.String())
	}
	if !strings.Contains(out.String(), "RESULT: INCOMPLETE (2 package(s) not checked)") ||
		!strings.Contains(out.String(), "NOT CHECKED: 2 package(s): CyberDetails has no advisories for Fedora:40 yet.") {
		t.Errorf("report:\n%s\nstderr: %s", out.String(), errb.String())
	}
	var j struct {
		Decision  string `json:"decision"`
		Unchecked []struct {
			Name, Version, Arch, Ecosystem string
		} `json:"unchecked_packages"`
	}
	b, _ := os.ReadFile(jsonOut)
	if err := json.Unmarshal(b, &j); err != nil {
		t.Fatal(err)
	}
	if j.Decision != "incomplete" || len(j.Unchecked) != 2 || j.Unchecked[0].Name != "tree" || j.Unchecked[0].Arch != "aarch64" {
		t.Errorf("%s", b)
	}
}
