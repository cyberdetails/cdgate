package ospkg

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/cyberdetails/cdgate/internal/sbom"
)

func decodeFile(t *testing.T, p string) *sbom.Result {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	r, err := sbom.Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// testdata/sbom/trivy_src.tsv: Trivy 00b7394's decoder (lab cdsbomoracle) on
// the same two files: source name|version|release|epoch per package.
func TestSourceFieldsAgainstTrivy(t *testing.T) {
	want := map[string]string{}
	f, _ := os.Open("testdata/sbom/trivy_src.tsv")
	s := bufio.NewScanner(f)
	for s.Scan() {
		x := strings.Split(s.Text(), "\t")
		if x[1] == "ERR" {
			want[x[0]] = "ERR"
			continue
		}
		src := strings.Split(strings.TrimPrefix(x[5], "src="), "|")
		rel := strings.TrimPrefix(src[6], "rel=")
		want[x[0]+" "+x[3]] = strings.Join(src[:4], "|") + " rel=" + rel + " " + src[4]
	}
	f.Close()
	if len(want) != 13 {
		t.Fatalf("oracle rows %d", len(want))
	}
	b, _ := os.ReadFile("testdata/sbom/badepoch_cdx.json")
	if _, err := sbom.Decode(b); err == nil || want["badepoch_cdx.json"] != "ERR" {
		t.Error("an invalid SrcEpoch fails the document, as in Trivy")
	}
	for _, file := range []string{"src_cdx.json", "src_spdx.json", "more_cdx.json", "rpm_cdx.json"} {
		for _, p := range decodeFile(t, "testdata/sbom/"+file).OSPackages {
			n, v, r, e := srcFields(p)
			class := "class="
			if p.ThirdParty {
				class = "class=third-party"
			}
			if got := fmt.Sprintf("%s|%s|%s|%d rel=%s %s", n, v, r, e, p.Release, class); got != want[file+" "+p.Name] {
				t.Errorf("%s %s: %s want %s", file, p.Name, got, want[file+" "+p.Name])
			}
		}
	}
}

func osp(typ, name, version string) sbom.OSPackage {
	return sbom.OSPackage{Type: typ, Name: name, Version: version, SrcEpoch: -1}
}

func rowsOf(r *Result) string {
	var out []string
	for _, p := range r.Packages {
		out = append(out, p.Ecosystem+" "+p.Name+"@"+p.Version+" "+strings.Join(p.Binaries, "+"))
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}

func TestFromSBOMDebApk(t *testing.T) {
	deb := []sbom.OSPackage{
		{Type: "deb", Name: "libc6", Version: "2.36-9", SrcName: "glibc", SrcVersion: "2.36", SrcRelease: "9", SrcEpoch: -1},
		{Type: "deb", Name: "libc-bin", Version: "2.36-9", SrcName: "glibc", SrcVersion: "2.36", SrcRelease: "9", SrcEpoch: -1},
		{Type: "deb", Name: "docker-ce", Version: "24.0", SrcEpoch: -1, ThirdParty: true},
		{Type: "deb", Name: "evil", Version: "1.0\nPackage: injected\nVersion: 9", SrcEpoch: -1},
		{Type: "deb", Name: "evil name", Version: "1.0", SrcEpoch: -1},
		osp("apk", "musl", "1.2.4-r2"),
	}
	r, rest, err := FromSBOM(&sbom.OS{Family: "debian", Name: "12.5"}, deb)
	if err != nil {
		t.Fatal(err)
	}
	if got := rowsOf(r); got != "Debian:12 glibc@2.36-9 libc-bin+libc6" {
		t.Errorf("debian rows %q", got)
	}
	if r.Skipped["third_party"] != 1 || r.Skipped["sbom_field_unusable"] != 2 || len(rest) != 1 || rest[0].Name != "musl" {
		t.Errorf("skipped %v rest %v", r.Skipped, rest)
	}
	// Echo's feed covers third-party packages: kept
	if r, _, _ = FromSBOM(&sbom.OS{Family: "echo", Name: "1"}, deb[2:3]); len(r.Packages) != 1 {
		t.Errorf("echo %+v", r.Packages)
	}
	apk := []sbom.OSPackage{
		{Type: "apk", Name: "libssl3", Version: "3.1.4-r5", SrcName: "openssl", SrcVersion: "3.1.4-r5", SrcEpoch: -1},
		{Type: "apk", Name: "x", Version: "1-r0", SrcEpoch: -1, ThirdParty: true},
		{Type: "apk", Name: "seal-y", Version: "1-r0", SrcEpoch: -1, ThirdParty: true},
	}
	r, _, err = FromSBOM(&sbom.OS{Family: "alpine", Name: "3.19.1"}, apk)
	if err != nil {
		t.Fatal(err)
	}
	// third-party dropped, except Seal's own package on Alpine
	if got := rowsOf(r); got != "Alpine:v3.19 openssl@3.1.4-r5 libssl3, Seal:Alpine seal-y@1-r0 seal-y" {
		t.Errorf("alpine rows %q", got)
	}
}

func TestFromSBOMRPM(t *testing.T) {
	pk := []sbom.OSPackage{
		{Type: "rpm", Name: "acl", Version: "2.3.1", Release: "3.el9", Arch: "x86_64", SrcName: "acl", SrcVersion: "2.3.1",
			SrcRelease: "3.el9", SrcEpoch: -1, ContentSets: []string{"rhel-9-for-x86_64-baseos-rpms"}, NVR: "ubi9-container-9.2-1"},
		{Type: "rpm", Name: "nobi", Version: "1.0", Release: "1.el9", Arch: "x86_64", SrcEpoch: -1},
		{Type: "rpm", Name: "epel-pkg", Version: "1.0", Release: "1.el9", Arch: "x86_64", SrcEpoch: -1, ThirdParty: true},
	}
	r, rest, err := FromSBOM(&sbom.OS{Family: "redhat", Name: "9.2"}, pk)
	if err != nil || len(rest) != 0 {
		t.Fatal(err, rest)
	}
	if len(r.Packages) != 2 || r.Skipped["third_party"] != 1 {
		t.Fatalf("%+v %v", r.Packages, r.Skipped)
	}
	for _, p := range r.Packages {
		switch p.Name {
		case "acl":
			if p.BuildInfo == nil || p.BuildInfo.Nvr != "ubi9-container-9.2-1" || len(p.BuildInfo.ContentSets) != 1 || p.SourcePackage != "acl" {
				t.Errorf("acl %+v", p)
			}
		case "nobi":
			// no source fields: the binary's (release included) name the source RPM
			if p.BuildInfo != nil || p.SourcePackage != "nobi" { // no build info: the server's default repositories
				t.Errorf("nobi %+v", p.BuildInfo)
			}
		}
	}
	// Trivy's OS type names that differ from this package's
	if r, _, err := FromSBOM(&sbom.OS{Family: "azurelinux", Name: "3.0"}, pk[1:2]); err != nil || r.OS.Family != "azure" {
		t.Errorf("azurelinux: %v %+v", err, r)
	}
}

func TestFromSBOMUnusable(t *testing.T) {
	pk := []sbom.OSPackage{osp("deb", "bash", "5.2")}
	if _, rest, err := FromSBOM(nil, pk); err == nil || err.Error() != SBOMNoOS || len(rest) != 1 {
		t.Errorf("no OS: %v %v", err, rest)
	}
	if _, rest, err := FromSBOM(&sbom.OS{Family: "windows", Name: "11"}, pk); err == nil || len(rest) != 1 {
		t.Errorf("unknown family: %v %v", err, rest)
	}
	if r, rest, err := FromSBOM(&sbom.OS{Family: "debian", Name: "12"}, nil); r != nil || rest != nil || err != nil {
		t.Error("nothing to do")
	}
}

// FuzzFromSBOM: an SBOM's fields reach a synthesized package database.
func FuzzFromSBOM(f *testing.F) {
	for _, p := range []string{"testdata/sbom/src_cdx.json", "testdata/sbom/src_spdx.json", "testdata/sbom/rpm_cdx.json"} {
		b, _ := os.ReadFile(p)
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := sbom.Decode(b)
		if err != nil {
			return
		}
		for _, o := range []sbom.OS{{Family: "debian", Name: "12"}, {Family: "alpine", Name: "3.19"}, {Family: "redhat", Name: "9.2"}, {Family: "echo", Name: "1"}} {
			res, _, _ := FromSBOM(&o, r.OSPackages)
			if res == nil {
				continue
			}
			for _, p := range res.Packages {
				if strings.ContainsAny(p.Name+p.Version, "\n\r") {
					t.Fatalf("line break reached a row: %q %q", p.Name, p.Version)
				}
			}
		}
	})
}
