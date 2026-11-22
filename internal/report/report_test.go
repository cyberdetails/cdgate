package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/ferhatcil/cdgate/internal/api"
	"github.com/ferhatcil/cdgate/internal/model"
	"github.com/ferhatcil/cdgate/internal/sanitize"
	"github.com/ferhatcil/cdgate/internal/scan"
)

func s(v string) *string { return &v }

func TestLinkOnlyToOwnSiteOrGitHubAdvisory(t *testing.T) {
	base := "https://cyberdetails.org"
	if got := Link(base, s("/cve/CVE-2021-44228"), nil); got != base+"/cve/CVE-2021-44228" {
		t.Fatal(got)
	}
	if got := Link(base, nil, s("https://github.com/advisories/GHSA-qqfx-rpxc-ghp4")); got == "" {
		t.Fatal("GHSA link dropped")
	}
	for _, bad := range []string{"https://evil.test/x", "//evil.test", "/cve/../admin", "/cve/CVE-1"} {
		if Link(base, s(bad), nil) != "" {
			t.Fatalf("%s must not become a link", bad)
		}
	}
	if Link(base, nil, s("https://github.com/advisories/GHSA-aaaa-bbbb-cccc")) != "" {
		t.Fatal("GHSA id outside the GHSA alphabet must not become a link")
	}
}

func TestSanitizeRemovesTerminalEscapesAndBidi(t *testing.T) {
	got := sanitize.Text("\x1b]8;;http://evil\x07click\x1b]8;;\x07 a\u202eb\n c", 200)
	if strings.ContainsAny(got, "\x1b\x07\u202e\n") || !strings.Contains(got, "ab c") {
		t.Fatalf("got %q", got)
	}
	if got := sanitize.Text(strings.Repeat("x", 300), 10); len([]rune(got)) != 10 {
		t.Fatalf("not capped: %q", got)
	}
}

func TestTruncatedPackageIsAnnounced(t *testing.T) {
	findings := make([]api.Finding, 3)
	for i := range findings {
		findings[i] = api.Finding{ID: "CVE-2020-000" + string(rune('1'+i)), Kind: "vulnerability",
			Match: "affected", Urgency: "standard"}
	}
	rows := []Row{{
		Package: model.Package{Ecosystem: "ubuntu:22.04", Name: "linux", Version: "5.15.0-25.25"},
		Result: api.PackageResult{Status: "vulnerable", Findings: findings,
			FindingsTotal: 1234, FindingsTruncated: true},
	}}
	var b bytes.Buffer
	Text(&b, "test", "https://cyberdetails.org", "known_exploited", &scan.Result{}, rows)
	if !strings.Contains(b.String(), "linux 5.15.0-25.25 has 1234 findings; the server listed the 3 most urgent") {
		t.Fatalf("truncation note missing:\n%s", b.String())
	}
	rows[0].Result.FindingsTruncated = false
	b.Reset()
	Text(&b, "test", "https://cyberdetails.org", "known_exploited", &scan.Result{}, rows)
	if strings.Contains(b.String(), "most urgent") {
		t.Fatal("note printed for a package that was not truncated")
	}
}

func TestPkgLabelShowsBinaries(t *testing.T) {
	id := func(s string, _ int) string { return s }
	cases := []struct {
		p    model.Package
		want string
	}{
		{model.Package{Name: "glibc", Binaries: []string{"libc-bin", "libc6"}}, "glibc (libc-bin, libc6)"},
		{model.Package{Name: "curl", Binaries: []string{"curl"}}, "curl"},
		{model.Package{Name: "lodash"}, "lodash"},
		{model.Package{Name: "x", Binaries: []string{"a", "b", "c", "d", "e", "f"}}, "x (a, b, c, d +2)"},
	}
	for _, c := range cases {
		if got := pkgLabel(c.p, id); got != c.want {
			t.Errorf("%q, want %q", got, c.want)
		}
	}
}

// Packages the server did not check make the result INCOMPLETE, never PASS,
// and every distinct reason is shown with its own count (a source not used
// for licensing reasons is not "advisories could not be selected").
func TestServerNotCheckedIsIncomplete(t *testing.T) {
	license := "Seal Security advisory data is not used yet (no license for this use); this package was not checked."
	cpe := "Red Hat content sets for this package map to no product (CPE); its advisories cannot be selected."
	rows := []Row{
		{Package: model.Package{Ecosystem: "PyPI", Name: "seal-requests", Version: "2.31.0"},
			Result: api.PackageResult{Status: "not_checked", NotCheckedReason: license}},
		{Package: model.Package{Ecosystem: "PyPI", Name: "seal-urllib3", Version: "2.0.0"},
			Result: api.PackageResult{Status: "not_checked", NotCheckedReason: license}},
		{Package: model.Package{Ecosystem: "Red Hat:9", Name: "bash", Version: "5.1-1.el9"},
			Result: api.PackageResult{Status: "not_checked", NotCheckedReason: cpe}},
		{Package: model.Package{Ecosystem: "Red Hat:9", Name: "zlib", Version: "1.2.11-1.el9"},
			Result: api.PackageResult{Status: "not_checked"}},
	}
	var b bytes.Buffer
	Text(&b, "test", "https://cyberdetails.org", "known_exploited", &scan.Result{}, rows)
	out := b.String()
	for _, want := range []string{
		"RESULT: INCOMPLETE (4 package(s) not checked)",
		"NOT CHECKED: 2 package(s): " + strings.TrimSuffix(license, ".") + ".\n",
		"NOT CHECKED: 1 package(s): " + strings.TrimSuffix(cpe, ".") + ".\n",
		"NOT CHECKED: 1 package(s): the server could not select their advisories.\n",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in report:\n%s", want, out)
		}
	}
	if Incomplete(&scan.Result{}, rows) != 4 {
		t.Fatal("incomplete count")
	}
}

func TestLocalProjectsNote(t *testing.T) {
	var b bytes.Buffer
	Text(&b, "test", "https://cyberdetails.org", "known_exploited", &scan.Result{LocalNotSent: 3}, nil)
	if !strings.Contains(b.String(), "NOTE: 3 of your own project(s)") {
		t.Error(b.String())
	}
	b.Reset()
	Text(&b, "test", "https://cyberdetails.org", "known_exploited", &scan.Result{}, nil)
	if strings.Contains(b.String(), "of your own project") {
		t.Error(b.String())
	}
}
