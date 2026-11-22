package ospkg

import (
	"compress/gzip"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/ferhatcil/cdgate/internal/model"
	"github.com/ferhatcil/cdgate/internal/rpmdb"
)

func rpmFixture(t *testing.T, name string) string {
	t.Helper()
	f, err := os.Open("../rpmdb/testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	g, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(g)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestRPMOSDetection(t *testing.T) {
	cases := []struct {
		name string
		fs   memFS
		want string
	}{
		{"rocky-release", memFS{"etc/rocky-release": "Rocky Linux release 9.3 (Blue Onyx)\n"}, "Rocky Linux:9"},
		{"redhat-release names Alma", memFS{"etc/redhat-release": "AlmaLinux release 8.10 (Cerulean Leopard)"}, "AlmaLinux:8"},
		{"RHEL", memFS{"etc/redhat-release": "Red Hat Enterprise Linux release 9.4 (Plow)"}, "Red Hat:9"},
		{"Oracle replaces the RHEL of redhat-release", memFS{"etc/redhat-release": "Red Hat Enterprise Linux Server release 7.9 (Maipo)",
			"etc/oracle-release": "Oracle Linux Server release 7.9"}, "Oracle Linux:7"},
		{"CentOS 7: longest version wins", memFS{"etc/centos-release": "CentOS Linux release 7.9.2009 (Core)",
			"etc/os-release": "ID=\"centos\"\nVERSION_ID=\"7\"\n"}, "CentOS:7"},
		{"CentOS Stream from os-release NAME", memFS{"etc/os-release": "NAME=\"CentOS Stream\"\nID=\"centos\"\nVERSION_ID=\"9\"\n"}, "CentOS Stream:9"},
		{"os-release rhel", memFS{"etc/os-release": "ID=\"rhel\"\nVERSION_ID=\"9.4\"\n"}, "Red Hat:9"},
		{"Amazon Linux 2", memFS{"etc/system-release": "Amazon Linux release 2 (Karoo)\n"}, "Amazon Linux:2"},
		{"Amazon Linux 2023", memFS{"usr/lib/system-release": "Amazon Linux release 2023.6.20241010 (Amazon Linux)\n"}, "Amazon Linux:2023"},
		{"Amazon Linux 1", memFS{"etc/system-release": "Amazon Linux AMI release 2018.03\n"}, "Amazon Linux:1"},
		{"amzn ID alone is not Amazon for Trivy", memFS{"etc/os-release": "ID=\"amzn\"\nVERSION_ID=\"2023\"\n"}, "ERR:operating system   is not supported yet"},
		{"centos-release with a Rocky line is not CentOS", memFS{"etc/centos-release": "Rocky Linux release 9.3"}, "ERR:operating system   is not supported yet"},
		{"openSUSE Leap keeps the full version", memFS{"etc/os-release": "ID=\"opensuse-leap\"\nVERSION_ID=\"15.6\"\n"}, "openSUSE Leap:15.6"},
		{"SLES", memFS{"etc/os-release": "ID=\"sles\"\nVERSION_ID=\"15.6\"\n"}, "SLES:15.6"},
		{"SLE Micro rebrand", memFS{"etc/os-release": "ID=\"sl-micro\"\nVERSION_ID=\"6.0\"\n"}, "SLE Micro:6.0"},
		{"Tumbleweed is one stream", memFS{"etc/os-release": "ID=\"opensuse-tumbleweed\"\nVERSION_ID=\"20261116\"\n"}, "openSUSE Tumbleweed"},
		{"unparsable release line", memFS{"etc/redhat-release": "garbage"}, "ERR:operating system   is not supported yet"},
	}
	for _, c := range cases {
		if got := eco(t, c.fs); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
}

func TestVendorPackage(t *testing.T) {
	for _, c := range []struct {
		p    rpmdb.Package
		want bool
	}{
		{rpmdb.Package{Vendor: "Rocky Enterprise Software Foundation"}, true},
		{rpmdb.Package{Vendor: "Red Hat, Inc."}, true},
		{rpmdb.Package{Vendor: "Fedora Project"}, true},
		{rpmdb.Package{Vendor: "Docker"}, false},
		{rpmdb.Package{Release: "1.amzn2023.0.1"}, true}, // Amazon packages may have no Vendor
		{rpmdb.Package{Release: "1.el9"}, false},
	} {
		if got := vendorPackage(c.p); got != c.want {
			t.Errorf("%+v: %v", c.p, got)
		}
	}
}

func TestAnalyzeRPM(t *testing.T) {
	db := rpmFixture(t, "sqlite.db.gz")
	fs := memFS{
		"etc/rocky-release":          "Rocky Linux release 9.3 (Blue Onyx)",
		"var/lib/rpm/rpmdb.sqlite":   db,
		"usr/share/rpm/rpmdb.sqlite": db, // the same packages twice: listed once
	}
	r, err := Analyze(fs)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Queryable || r.Ecosystem != "Rocky Linux:9" || len(r.Files) != 2 {
		t.Fatalf("%+v", r)
	}
	var got []string
	for _, p := range r.Packages {
		got = append(got, p.Name+" "+p.Version+" "+p.Arch+" "+p.SourcePackage+" "+p.Ecosystem)
	}
	want := "tree 1.8.0-10.el9 aarch64 tree-pkg Rocky Linux:9,words 3.0-39.el9.0.1 noarch words Rocky Linux:9"
	if strings.Join(got, ",") != want {
		t.Errorf("got  %s\nwant %s", strings.Join(got, ","), want)
	}
	files := InstalledFiles(fs)
	if !files["usr/bin/tree"] || !files["usr/share/dict/words"] {
		t.Errorf("rpm installed files missing: %d files", len(files))
	}

	amzn := memFS{"etc/system-release": "Amazon Linux release 2 (Karoo)", "var/lib/rpm/Packages": rpmFixture(t, "bdb.db.gz")}
	if r, err := Analyze(amzn); err != nil || len(r.Packages) != 2 || r.Ecosystem != "Amazon Linux:2" {
		t.Errorf("%+v %v", r, err)
	}
	suse := memFS{"etc/os-release": "ID=\"opensuse-leap\"\nVERSION_ID=\"15.6\"", "usr/lib/sysimage/rpm/Packages.db": rpmFixture(t, "ndb.db.gz")}
	if r, err := Analyze(suse); err != nil || len(r.Packages) != 2 || r.Skipped["third_party"] != 0 {
		t.Errorf("%+v %v", r, err)
	}
	// Rocky packages on a system whose vendor list does not include them do
	// not exist; a non-vendor package is third-party and skipped
	if _, err := Analyze(memFS{"etc/rocky-release": "Rocky Linux release 9.3"}); err == nil {
		t.Error("no rpm database must be an error")
	}
	if _, err := Analyze(memFS{"etc/rocky-release": "Rocky Linux release 9.3", "var/lib/rpm/Packages": "not a database"}); err == nil {
		t.Error("an unreadable rpm database must be an error")
	}
}

func TestHasOSSeesEveryReleaseFile(t *testing.T) {
	for _, r := range rpmReleaseFiles {
		if !HasOS(memFS{r.path: "x release 1"}) {
			t.Errorf("%s alone is not seen as an OS", r.path)
		}
	}
	if HasOS(memFS{"etc/hostname": "x"}) {
		t.Error("no release file is not an OS")
	}
}

func TestRPMThirdPartyAndReleaseEdges(t *testing.T) {
	// thirdparty.db: the SQLite fixture with words' Vendor rewritten to a
	// non-OS vendor of the same length
	fs := memFS{"etc/rocky-release": "Rocky Linux release 9.3", "var/lib/rpm/rpmdb.sqlite": rpmFixture(t, "thirdparty.db.gz")}
	r, err := Analyze(fs)
	if err != nil || len(r.Packages) != 1 || r.Packages[0].Name != "tree" || r.Skipped["third_party"] != 1 {
		t.Fatalf("%+v %v", r, err)
	}
	files := InstalledFiles(fs)
	if !files["usr/bin/tree"] || files["usr/share/dict/words"] {
		t.Error("only vendor packages contribute installed files")
	}
	for name, f := range map[string]memFS{
		"first line unparsable ends the analysis": {"etc/redhat-release": "garbage\nRed Hat Enterprise Linux release 9.4"},
		"Amazon release 2 with four fields":       {"etc/system-release": "Amazon Linux release 2\n"},
	} {
		if got := eco(t, f); !strings.HasPrefix(got, "ERR:") {
			t.Errorf("%s: %s", name, got)
		}
	}
	if eco(t, memFS{"etc/system-release": "Amazon Linux release 2\nAmazon Linux release 2 (Karoo)"}) != "Amazon Linux:2" {
		t.Error("a short line is skipped, the next one counts")
	}
	ok := []rpmdb.Package{{Name: "a", Vendor: "Docker", FilesInvalid: true}, {Name: "b", Vendor: "Red Hat, Inc."}}
	if invalidVendorFiles(ok) != nil {
		t.Error("a third-party package's file list is not checked")
	}
	if invalidVendorFiles(append(ok, rpmdb.Package{Name: "c", Vendor: "Red Hat, Inc.", FilesInvalid: true})) == nil {
		t.Error("a vendor package with an invalid file list fails the database")
	}
}

func TestQueryableAndModularNames(t *testing.T) {
	db := rpmFixture(t, "sqlite.db.gz")
	for rel, want := range map[string]bool{
		"etc/rocky-release":     true,  // Rocky Linux:9
		"etc/almalinux-release": true,  // AlmaLinux:9
		"etc/oracle-release":    true,  // Oracle Linux:9
		"etc/fedora-release":    false, // no Fedora data
	} {
		line := map[string]string{"etc/rocky-release": "Rocky Linux release 9.3", "etc/almalinux-release": "AlmaLinux release 9.4",
			"etc/oracle-release": "Oracle Linux Server release 9.4", "etc/fedora-release": "Fedora release 40 (Forty)"}[rel]
		r, err := Analyze(memFS{rel: line, "var/lib/rpm/rpmdb.sqlite": db})
		if err != nil || r.Queryable != want {
			t.Errorf("%s: queryable %v, want %v (%v)", rel, r != nil && r.Queryable, want, err)
		}
	}
	if r, _ := Analyze(memFS{"etc/system-release": "Amazon Linux release 2 (Karoo)", "var/lib/rpm/Packages": rpmFixture(t, "bdb.db.gz")}); !r.Queryable {
		t.Error("Amazon Linux 2 is queryable")
	}
	if r, _ := Analyze(memFS{"etc/system-release": "Amazon Linux AMI release 2018.03", "var/lib/rpm/Packages": rpmFixture(t, "bdb.db.gz")}); r.Queryable {
		t.Error("Amazon Linux 1 has no data (its source is plain HTTP): unchecked")
	}
	mod := rpmdb.Package{Name: "npm", ModularityLabel: "nodejs:18:9030020231120082734:rhel9"}
	if queryName("rocky", mod) != "nodejs:18::npm" || queryName("alma", mod) != "nodejs:18::npm" ||
		queryName("redhat", mod) != "nodejs:18::npm" || queryName("centos", mod) != "nodejs:18::npm" ||
		queryName("amazon", mod) != "npm" || queryName("oracle", mod) != "npm" {
		t.Error("modular names: Rocky, AlmaLinux, Red Hat and CentOS only")
	}
	for _, c := range []struct{ name, label, want string }{
		{"npm", "nodejs:12:8030020201124152102:229f0a1c", "nodejs:12::npm"},
		{"python38-babel", "python38:3.8:8050020211117154524:b8f6c8f5", "python38:3.8::python38-babel"},
		{"bash", "", "bash"},
		{"x", "onlyname", "x"},
		{"x", "a:b", "x"},
	} {
		if got := modularName(c.name, c.label); got != c.want {
			t.Errorf("modularName(%q, %q) = %q", c.name, c.label, got)
		}
	}
}

type biFS struct {
	memFS
	bi    *model.BuildInfo
	known bool
}

func (b biFS) RPMBuildInfo(string, string, string) (*model.BuildInfo, bool) { return b.bi, b.known }

// Red Hat and CentOS packages carry their layer's build information; a layer
// whose build information is unknown leaves its packages unchecked; other
// families ignore it.
func TestRedHatBuildInfo(t *testing.T) {
	db := rpmFixture(t, "sqlite.db.gz")
	bi := &model.BuildInfo{ContentSets: []string{"rhel-9-for-x86_64-baseos-rpms"}}
	fs := memFS{"etc/redhat-release": "Red Hat Enterprise Linux release 9.4 (Plow)", "var/lib/rpm/rpmdb.sqlite": db}
	r, err := Analyze(biFS{fs, bi, true})
	if err != nil || !r.Queryable || r.Ecosystem != "Red Hat:9" || len(r.Packages) != 2 || r.Packages[0].BuildInfo != bi {
		t.Fatalf("redhat: %+v %v", r, err)
	}
	r, _ = Analyze(biFS{fs, nil, false})
	if len(r.Packages) != 0 || len(r.Unchecked) != 2 || r.Unchecked[0].UncheckedReason != BuildInfoUnknown {
		t.Fatalf("unknown build info: %+v", r)
	}
	r, _ = Analyze(biFS{memFS{"etc/centos-release": "CentOS Linux release 7.9.2009 (Core)", "var/lib/rpm/rpmdb.sqlite": db}, bi, true})
	if !r.Queryable || r.Ecosystem != "CentOS:7" || r.Packages[0].BuildInfo != bi {
		t.Fatalf("centos: %+v", r)
	}
	r, _ = Analyze(biFS{memFS{"etc/rocky-release": "Rocky Linux release 9.3", "var/lib/rpm/rpmdb.sqlite": db}, bi, false})
	if len(r.Packages) != 2 || r.Packages[0].BuildInfo != nil || len(r.Unchecked) != 0 {
		t.Fatalf("rocky ignores build info: %+v", r)
	}
	r, _ = Analyze(biFS{memFS{"etc/redhat-release": "Red Hat Enterprise Linux release 10.0", "var/lib/rpm/rpmdb.sqlite": db}, bi, true})
	if r.Queryable {
		t.Error("RHEL 10 has no data: unchecked")
	}
}

func TestSUSEQueryable(t *testing.T) {
	for eco, want := range map[string]bool{"SLES:15.6": true, "SLES:12": true, "SLE Micro:6.0": true,
		"openSUSE Leap:15.6": true, "openSUSE Tumbleweed": true, "SLES:15.8": false, "openSUSE Leap:15.7": false} {
		if queryableRPM[eco] != want {
			t.Errorf("%s: queryable %v", eco, !want)
		}
	}
	if r, _ := Analyze(memFS{"etc/os-release": "ID=\"opensuse-tumbleweed\"\nVERSION_ID=\"20261116\"\n",
		"usr/lib/sysimage/rpm/Packages.db": rpmFixture(t, "ndb.db.gz")}); r == nil || !r.Queryable {
		t.Error("Tumbleweed is queryable")
	}
}

// Photon OS: advisories are looked up by the source package (Trivy pkg.SrcName);
// one row per (source, version, arch) with its binaries; full release.
func TestPhotonSourceNames(t *testing.T) {
	db := rpmFixture(t, "sqlite.db.gz") // tree (src tree-pkg), words (src words)
	r, err := Analyze(memFS{"etc/os-release": "ID=photon\nVERSION_ID=5.0\n", "var/lib/rpm/rpmdb.sqlite": db})
	if err != nil || !r.Queryable || r.Ecosystem != "Photon OS:5.0" || len(r.Packages) != 2 {
		t.Fatalf("%+v %v", r, err)
	}
	got := map[string][]string{}
	for _, p := range r.Packages {
		got[p.Name] = p.Binaries
	}
	if len(got["tree-pkg"]) != 1 || got["tree-pkg"][0] != "tree" || len(got["words"]) != 1 {
		t.Errorf("source rows: %v", got)
	}
	if r, _ := Analyze(memFS{"etc/os-release": "ID=photon\nVERSION_ID=6.0\n", "var/lib/rpm/rpmdb.sqlite": db}); r.Queryable {
		t.Error("Photon 6.0 has no data")
	}
}

// Photon rows from synthetic rpm rows: two binaries of one source share a row;
// a package without a source RPM is skipped (Trivy looks it up under "").
func TestPhotonRowsFromRPMRows(t *testing.T) {
	res := &Result{OS: OS{Family: "photon", Name: "5.0"}, Ecosystem: "Photon OS:5.0", Skipped: map[string]int{}}
	v := "VMware, Inc."
	rpmPackages(memFS{}, res, "var/lib/rpm/rpmdb.sqlite", []rpmdb.Package{
		{Name: "openssl", Version: "3.0.14", Release: "1.ph5", Arch: "x86_64", SourceRpm: "openssl-3.0.14-1.ph5.src.rpm", Vendor: v},
		{Name: "openssl-libs", Version: "3.0.14", Release: "1.ph5", Arch: "x86_64", SourceRpm: "openssl-3.0.14-1.ph5.src.rpm", Vendor: v},
		{Name: "gpg-pubkey", Version: "1", Release: "1", Arch: "", SourceRpm: "", Vendor: v},
	})
	if len(res.Packages) != 1 || res.Packages[0].Name != "openssl" ||
		strings.Join(res.Packages[0].Binaries, ",") != "openssl,openssl-libs" || res.Skipped["photon_no_source_rpm"] != 1 {
		t.Fatalf("%+v %v", res.Packages, res.Skipped)
	}
}

// Azure Linux / CBL-Mariner: source name and SOURCE version (binary epoch,
// source RPM version-release), release cut to major.minor (Trivy osver.Minor).
func TestAzureSourceVersion(t *testing.T) {
	res := &Result{OS: OS{Family: "azure", Name: "3.0.20240824"}, Ecosystem: "Azure Linux:3.0", Skipped: map[string]int{}}
	v := "Microsoft Corporation"
	rpmPackages(memFS{}, res, "var/lib/rpm/rpmdb.sqlite", []rpmdb.Package{
		{Name: "openssl-libs", Version: "3.3.3", Release: "1.azl3", Epoch: 1, Arch: "x86_64", SourceRpm: "openssl-3.3.3-2.azl3.src.rpm", Vendor: v},
		{Name: "openssl", Version: "3.3.3", Release: "1.azl3", Epoch: 1, Arch: "x86_64", SourceRpm: "openssl-3.3.3-2.azl3.src.rpm", Vendor: v},
		{Name: "bash", Version: "5.2", Release: "1.azl3", Arch: "x86_64", SourceRpm: "bash-5.2-1.azl3.src.rpm", Vendor: v},
	})
	got := map[string]string{}
	for _, p := range res.Packages {
		got[p.Name] = p.Version + " " + strings.Join(p.Binaries, ",")
	}
	if got["openssl"] != "1:3.3.3-2.azl3 openssl,openssl-libs" || got["bash"] != "5.2-1.azl3 bash" {
		t.Errorf("%v", got)
	}
	for in, want := range map[OS]string{{Family: "azure", Name: "3.0.20240824"}: "Azure Linux:3.0",
		{Family: "mariner", Name: "2.0.20240117"}: "CBL-Mariner:2.0", {Family: "mariner", Name: "1.0"}: "CBL-Mariner:1.0"} {
		if e, err := Ecosystem(in); err != nil || e != want || !queryableRPM[e] {
			t.Errorf("%+v: %s %v", in, e, err)
		}
	}
	if queryableRPM["Azure Linux:2.0"] {
		t.Error("Azure Linux 2.0 has no data")
	}
}

func TestAzureMarinerDetection(t *testing.T) {
	db := rpmFixture(t, "sqlite.db.gz") // tree (src tree-pkg), words
	for rel, want := range map[string]string{"ID=azurelinux\nVERSION_ID=\"3.0.20240824\"\n": "Azure Linux:3.0",
		"ID=mariner\nVERSION_ID=\"2.0.20240117\"\n": "CBL-Mariner:2.0"} {
		r, err := Analyze(memFS{"etc/os-release": rel, "var/lib/rpm/rpmdb.sqlite": db})
		if err != nil || r.Ecosystem != want || !r.Queryable {
			t.Fatalf("%s: %+v %v", want, r, err)
		}
		names := map[string]bool{}
		for _, p := range r.Packages {
			names[p.Name] = true
		}
		if !names["tree-pkg"] || names["tree"] {
			t.Errorf("%s: source names expected, got %v", want, names)
		}
	}
}

// Seal Security RPMs: matched by source name and FormatSrcVersion under the
// Red Hat version their release names; never dropped as third-party.
func TestSealRPM(t *testing.T) {
	res := &Result{OS: OS{Family: "oracle", Name: "8.9"}, Ecosystem: "Oracle Linux:8", Skipped: map[string]int{}}
	rpmPackages(memFS{}, res, "var/lib/rpm/rpmdb.sqlite", []rpmdb.Package{
		{Name: "seal-openssl", Epoch: 1, Version: "1.1.1k", Release: "6.el8_5+sp1", Arch: "x86_64",
			SourceRpm: "seal-openssl-1.1.1k-6.el8_5+sp1.src.rpm", Vendor: "Seal Security"},
		{Name: "seal-openssl-libs", Epoch: 1, Version: "1.1.1k", Release: "6.el8_5+sp1", Arch: "x86_64",
			SourceRpm: "seal-openssl-1.1.1k-6.el8_5+sp1.src.rpm", Vendor: "Seal Security"},
		{Name: "seal-curl", Version: "7.61.1", Release: "34.el10_0", Arch: "x86_64",
			SourceRpm: "seal-curl-7.61.1-34.el10_0.src.rpm", Vendor: "Seal Security"},
		{Name: "seal-zlib", Version: "1.2.11", Release: "25.el8", Arch: "x86_64", Vendor: "Seal Security"},
		{Name: "bash", Version: "4.4.20", Release: "4.el8", Arch: "x86_64", SourceRpm: "bash-4.4.20-4.el8.src.rpm",
			Vendor: "Oracle America"},
		{Name: "docker-ce", Version: "24.0", Release: "1.el8", Arch: "x86_64", SourceRpm: "docker-ce-24.0-1.el8.src.rpm",
			Vendor: "Docker"},
	})
	got := map[string]string{}
	for _, p := range res.Packages {
		got[p.Ecosystem+" "+p.Name] = p.Version + " " + strings.Join(p.Binaries, ",")
	}
	want := map[string]string{
		"Seal:Red Hat:8 seal-openssl": "1:1.1.1k-6.el8_5+sp1 seal-openssl,seal-openssl-libs",
		"Oracle Linux:8 bash":         "4.4.20-4.el8 ",
	}
	if len(got) != len(want) {
		t.Errorf("%v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: %q want %q", k, got[k], v)
		}
	}
	why := map[string]string{}
	for _, p := range res.Unchecked {
		why[p.Name] = p.UncheckedReason
	}
	if why["seal-curl"] != SealNoRelease || why["seal-zlib"] != SealNoSource || res.Skipped["third_party"] != 1 {
		t.Errorf("unchecked %v skipped %v", why, res.Skipped)
	}
	if sealRelease("9.el10_0.1") != "10" || sealRelease("3.el8+sp1") != "8" || sealRelease("1.fc39") != "" {
		t.Error("releaseVersion")
	}
}

// RapidFort curated RPM images: every package (no vendor filter), by source
// name and source version, binaries listed; precedence over Seal.
func TestRapidFortRPM(t *testing.T) {
	res := &Result{OS: OS{Family: "redhat", Name: "9.4"}, Ecosystem: "RapidFort:RedHat:9", Skipped: map[string]int{}}
	rapidfortRPM(res, "var/lib/rpm/rpmdb.sqlite", []rpmdb.Package{
		{Name: "openssl-libs", Epoch: 1, Version: "3.0.7", Release: "27.el9.rf1", Arch: "x86_64",
			SourceRpm: "openssl-3.0.7-27.el9.rf1.src.rpm", Vendor: "RapidFort"},
		{Name: "openssl", Epoch: 1, Version: "3.0.7", Release: "27.el9.rf1", Arch: "x86_64",
			SourceRpm: "openssl-3.0.7-27.el9.rf1.src.rpm", Vendor: "RapidFort"},
		{Name: "seal-curl", Version: "7.76.1", Release: "29.el9+sp1", Arch: "x86_64",
			SourceRpm: "seal-curl-7.76.1-29.el9+sp1.src.rpm", Vendor: "Seal Security"},
		{Name: "nosrc", Version: "1.0", Release: "1.el9", Arch: "noarch"},
		{Name: "nosrc-epoch", Epoch: 2, Version: "1.0", Release: "1.el9", Arch: "noarch"},
	})
	got := map[string]string{}
	for _, p := range res.Packages {
		got[p.Name] = p.Ecosystem + " " + p.Version + " " + strings.Join(p.Binaries, ",")
	}
	want := map[string]string{
		"openssl":   "RapidFort:RedHat:9 1:3.0.7-27.el9.rf1 openssl,openssl-libs",
		"seal-curl": "RapidFort:RedHat:9 7.76.1-29.el9+sp1 seal-curl",
		"nosrc":     "RapidFort:RedHat:9 1.0-1.el9 nosrc",
	}
	if len(got) != len(want) {
		t.Errorf("%v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: %q want %q", k, got[k], v)
		}
	}
	if len(res.Unchecked) != 1 || res.Unchecked[0].UncheckedReason != RapidFortNoSource {
		t.Errorf("unchecked %+v", res.Unchecked)
	}
}

// Distroless rpmqa manifest: Trivy's own rpmqa_test.go cases (v0.76.2) plus the
// rules that fail the whole file. The rows feed the Azure Linux source-row
// rule; no vendor filter applies to them.
func TestRpmqaManifest(t *testing.T) {
	happy := "mariner-release\t2.0-12.cm2\t1653816591\t1653753130\tMicrosoft Corporation\t(none)\t580\tnoarch\t0\tmariner-release-2.0-12.cm2.src.rpm\n" +
		"filesystem\t1.1-9.cm2\t1653816591\t1653628924\tMicrosoft Corporation\t(none)\t7596\tx86_64\t0\tfilesystem-1.1-9.cm2.src.rpm\n" +
		"glibc\t2.35-2.cm2\t1653816591\t1653628955\tMicrosoft Corporation\t(none)\t10855265\tx86_64\t0\tglibc-2.35-2.cm2.src.rpm\n" +
		"ca-certificates-base\t3.0.0-8.azl3\t1748892790\t1735838940\tMicrosoft Corporation\t(none)\t130628\tnoarch\t1\tca-certificates-3.0.0-8.azl3.src.rpm"
	got, err := parseRpmqa([]byte(happy))
	if err != nil || len(got) != 4 {
		t.Fatalf("%v %v", got, err)
	}
	c := got[3]
	if c.Name != "ca-certificates-base" || c.Version != "3.0.0" || c.Release != "8.azl3" || c.Epoch != 1 ||
		c.Arch != "noarch" || c.SourceRpm != "ca-certificates-3.0.0-8.azl3.src.rpm" || !c.FromRpmqa || c.Vendor != "" {
		t.Errorf("%+v", c)
	}
	if got[0].Epoch != 0 || got[0].Version != "2.0" || got[0].Release != "12.cm2" {
		t.Errorf("%+v", got[0])
	}
	// CRLF: bufio.ScanLines drops the "\r", as in Trivy.
	if g, err := parseRpmqa([]byte(strings.ReplaceAll(happy, "\n", "\r\n"))); err != nil || len(g) != 4 || g[0].SourceRpm != "mariner-release-2.0-12.cm2.src.rpm" {
		t.Errorf("crlf: %v %v", g, err)
	}
	bad := map[string]string{
		"trivy sad path": "filesystem\t1.1-7.cm1\t1653164283\t1599428094",
		"empty line":     "glibc\t2.35-2.cm2\t1\t1\tM\t(none)\t1\tx86_64\t0\tglibc-2.35-2.cm2.src.rpm\n\n",
		"three-part ver": "glibc\t2.35-2-1.cm2\t1\t1\tM\t(none)\t1\tx86_64\t0\tglibc-2.35-2.cm2.src.rpm",
		"no hyphen ver":  "glibc\t2.35\t1\t1\tM\t(none)\t1\tx86_64\t0\tglibc-2.35-2.cm2.src.rpm",
		"none source":    "gpg-pubkey\t1-1\t1\t1\tM\t(none)\t1\t(none)\t0\t(none)",
		"bad epoch":      "glibc\t2.35-2.cm2\t1\t1\tM\t(none)\t1\tx86_64\t(none)\tglibc-2.35-2.cm2.src.rpm",
		"eleven fields":  "glibc\t2.35-2.cm2\t1\t1\tM\t(none)\t1\tx86_64\t0\tglibc-2.35-2.cm2.src.rpm\textra",
		"too long line":  strings.Repeat("a", 70000) + "\t2.35-2.cm2\t1\t1\tM\t(none)\t1\tx86_64\t0\tglibc-2.35-2.cm2.src.rpm",
	}
	for name, in := range bad {
		if g, err := parseRpmqa([]byte(in)); err == nil {
			t.Errorf("%s: want an error, got %v", name, g)
		}
	}
	// Go's strconv.Atoi: a sign is accepted ("+1"), as in Trivy.
	if g, err := parseRpmqa([]byte("a\t1-1\t1\t1\tM\t(none)\t1\tx86_64\t+1\ta-1-1.src.rpm")); err != nil || g[0].Epoch != 1 {
		t.Errorf("%v %v", g, err)
	}
}

// End to end through Analyze: a CBL-Mariner distroless root (os-release + the
// manifest, no rpm database) gives source rows under CBL-Mariner:2.0; a
// non-vendor VENDOR field does not drop a row (Trivy reads no vendor there);
// a broken manifest is an error, never an empty clean list.
func TestRpmqaDistroless(t *testing.T) {
	m := "openssl-libs\t1.1.1k-30.cm2\t1\t1\tSomeone Else\t(none)\t1\tx86_64\t0\topenssl-1.1.1k-30.cm2.src.rpm\n" +
		"openssl\t1.1.1k-30.cm2\t1\t1\tMicrosoft Corporation\t(none)\t1\tx86_64\t0\topenssl-1.1.1k-30.cm2.src.rpm\n" +
		"tzdata\t2024a-1.cm2\t1\t1\tMicrosoft Corporation\t(none)\t1\tnoarch\t0\ttzdata-2024a-1.cm2.src.rpm\n"
	osr := "ID=mariner\nVERSION_ID=\"2.0.20240117\"\n"
	r, err := Analyze(memFS{"etc/os-release": osr, RpmqaPath: m})
	if err != nil || r.Ecosystem != "CBL-Mariner:2.0" || !r.Queryable || len(r.Files) != 1 || r.Files[0] != RpmqaPath {
		t.Fatalf("%+v %v", r, err)
	}
	got := map[string]string{}
	for _, p := range r.Packages {
		got[p.Name] = p.Version + " " + strings.Join(p.Binaries, ",")
	}
	if len(got) != 2 || got["openssl"] != "1.1.1k-30.cm2 openssl,openssl-libs" || got["tzdata"] != "2024a-1.cm2 tzdata" || r.Skipped["third_party"] != 0 {
		t.Errorf("%v %v", got, r.Skipped)
	}
	if _, err := Analyze(memFS{"etc/os-release": osr, RpmqaPath: m + "broken\n"}); err == nil {
		t.Error("a broken manifest must be an error")
	}
	// Beside a readable rpm database too: the broken manifest still fails the
	// scan instead of leaving the database's rows as a silently short list.
	db := rpmFixture(t, "sqlite.db.gz")
	if r, err := Analyze(memFS{"etc/os-release": osr, "var/lib/rpm/rpmdb.sqlite": db, RpmqaPath: m + "broken\n"}); err == nil {
		t.Errorf("a broken manifest beside an rpm database must be an error: %+v", r)
	}
	if !contains(Paths, RpmqaPath) {
		t.Error("image and rootfs readers must fetch the manifest")
	}
}
