package ospkg

import (
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
)

type memFS map[string]string

func (m memFS) Get(p string) ([]byte, bool) {
	v, ok := m[p]
	return []byte(v), ok
}

func (m memFS) List(dir string) []string {
	var out []string
	for k := range m {
		if strings.HasPrefix(k, dir) && !strings.Contains(k[len(dir):], "/") {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func eco(t *testing.T, f memFS) string {
	t.Helper()
	o, err := DetectOS(f)
	if err != nil {
		t.Fatal(err)
	}
	e, err := Ecosystem(o)
	if err != nil {
		return "ERR:" + err.Error()
	}
	return e
}

func TestOSDetection(t *testing.T) {
	cases := []struct {
		name string
		fs   memFS
		want string
	}{
		{"debian: major from debian_version", memFS{"etc/debian_version": "12.8\n"}, "Debian:12"},
		{"ubuntu overrides debian_version (bookworm/sid)", memFS{
			"etc/debian_version": "bookworm/sid\n", "etc/os-release": "ID=ubuntu\nVERSION_ID=\"22.04\"\n"}, "Ubuntu:22.04"},
		{"ubuntu from lsb-release", memFS{"etc/debian_version": "bullseye/sid", "etc/lsb-release": "DISTRIB_ID=Ubuntu\nDISTRIB_RELEASE=20.04\n"}, "Ubuntu:20.04"},
		{"ubuntu ESM only where Trivy has ESM data", memFS{"etc/os-release": "ID=ubuntu\nVERSION_ID=20.04",
			"var/lib/ubuntu-advantage/status.json": `{"services":[{"name":"esm-infra","status":"enabled"}]}`}, "Ubuntu:20.04-ESM"},
		{"ubuntu ESM enabled on 22.04 reads 22.04", memFS{"etc/os-release": "ID=ubuntu\nVERSION_ID=22.04",
			"var/lib/ubuntu-advantage/status.json": `{"services":[{"name":"esm-infra","status":"enabled"}]}`}, "Ubuntu:22.04"},
		{"alpine minor", memFS{"etc/alpine-release": "3.21.3\n"}, "Alpine:v3.21"},
		{"alpine repo names a newer release", memFS{"etc/alpine-release": "3.21.3", "etc/apk/repositories": "https://dl-cdn.alpinelinux.org/alpine/v3.21/main\nhttps://dl-cdn.alpinelinux.org/alpine/v3.22/community\n"}, "Alpine:v3.22"},
		{"alpine edge repo", memFS{"etc/alpine-release": "3.23_alpha20251016", "etc/apk/repositories": "https://dl-cdn.alpinelinux.org/alpine/edge/main\n"}, "Alpine:edge"},
		{"edge after a numbered repo line wins", memFS{"etc/alpine-release": "3.21.3", "etc/apk/repositories": "https://dl-cdn.alpinelinux.org/alpine/v3.21/main\nhttps://dl-cdn.alpinelinux.org/alpine/edge/testing\n"}, "Alpine:edge"},
		{"ESM disabled is not ESM", memFS{"etc/os-release": "ID=ubuntu\nVERSION_ID=20.04",
			"var/lib/ubuntu-advantage/status.json": `{"services":[{"name":"esm-infra","status":"disabled"}]}`}, "Ubuntu:20.04"},
		{"os-release ID=debian alone is not an OS for Trivy", memFS{"etc/os-release": "ID=debian\nVERSION_ID=12"},
			"ERR:operating system   is not supported yet"},
		{"debian testing has no release data", memFS{"etc/debian_version": "trixie/sid"}, "ERR:operating system debian trixie/sid is not supported yet"},
		{"longest version of one family wins", memFS{"etc/os-release": "ID=alpine\nVERSION_ID=3.20", "etc/alpine-release": "3.20.10"}, "Alpine:v3.20"},
	}
	for _, c := range cases {
		if got := eco(t, c.fs); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
	if _, err := DetectOS(memFS{"etc/alpine-release": "3.20", "etc/apk/repositories": "https://x.org/alpine/v3.20/main\nhttps://x.org/postmarketos/v24/main\n"}); err == nil {
		t.Error("mixed distributions in repositories must be an error")
	}
}

const status = `Package: libssl3
Status: install ok installed
Maintainer: Debian OpenSSL Team <pkg-openssl-devel@alioth-lists.debian.net>
Architecture: amd64
Source: openssl (3.0.9-1)
Version: 3.0.9-1+b1
Description: Secure Sockets Layer toolkit
 continuation line: needed

Package: bsdutils
Status: install ok installed
Source: util-linux (2.36.1-8+deb11u1)
Version: 1:2.36.1-8+deb11u1

Package: zlib1g
Status: install ok installed
Version: 0:1.2.13.dfsg-1

Package: oldpkg
Status: deinstall ok config-files
Version: 1.0-1

Package: nginx
Status: install ok installed
Maintainer: NGINX Packaging <nginx-packaging@f5.com>
Version: 1.27.5-1~bookworm

Package: gh
Status: install ok installed
Maintainer: GitHub
Version: 2.40.0

Package: broken
this line has no colon
Version: 1.0-1

Package: badver
Status: install ok installed
Version: abc

Package: twice
Version: 2.0-1
Version: 9.9-9
`

func TestDpkg(t *testing.T) {
	skipped := map[string]int{}
	got := parseDpkg([]byte(status), skipped, false, false)
	want := []pkgInfo{
		{"libssl3", "3.0.9-1+b1", "openssl", "3.0.9-1", "amd64"},
		{"bsdutils", "1:2.36.1-8+deb11u1", "util-linux", "2.36.1-8+deb11u1", ""},
		{"zlib1g", "0:1.2.13.dfsg-1", "zlib1g", "1.2.13.dfsg-1", ""}, // epoch 0 dropped (Trivy formatVersion)
		{"twice", "2.0-1", "twice", "2.0-1", ""},                     // repeated field: first value (MIMEHeader.Get)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
	if skipped["not_installed"] != 1 || skipped["third_party"] != 2 || skipped["malformed_paragraph"] != 1 ||
		skipped["invalid_version"] != 1 {
		t.Errorf("skipped %v", skipped)
	}
	if !ThirdParty("NGINX Packaging <nginx-packaging@f5.com>") || ThirdParty("GitHubber") || !ThirdParty("GitHub") {
		t.Error("third-party rule")
	}
}

func TestApk(t *testing.T) {
	db := "P:busybox\nV:1.36.1-r29\no:busybox\n\nP:ssl_client\nV:1.36.1-r29\no:busybox\n\n" +
		"P:early\no:early\nV:1.0-r0\n\nP:noorigin\nV:2.0-r0\n\nP:busybox\nV:1.36.1-r29\no:busybox\n"
	skipped := map[string]int{}
	got := parseApk([]byte(db), skipped, false)
	want := []pkgInfo{
		{"busybox", "1.36.1-r29", "busybox", "1.36.1-r29", ""},
		{"ssl_client", "1.36.1-r29", "busybox", "1.36.1-r29", ""},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v", got)
	}
	if skipped["no_origin"] != 2 { // early (o: before V:) and noorigin
		t.Errorf("skipped %v", skipped)
	}
}

func TestAnalyzeGroupsBinariesAndReadsStatusDir(t *testing.T) {
	fs := memFS{
		"etc/debian_version":                    "12.15",
		"var/lib/dpkg/status.d/libssl3":         "Package: libssl3\nSource: openssl (3.0.17-1~deb12u2)\nVersion: 3.0.17-1~deb12u2\n",
		"var/lib/dpkg/status.d/openssl":         "Package: openssl\nVersion: 3.0.17-1~deb12u2\n",
		"var/lib/dpkg/status.d/libssl3.md5sums": "abc  usr/lib/x.so\n",
	}
	r, err := Analyze(fs)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(r.Files, ",") != "var/lib/dpkg/status.d/libssl3,var/lib/dpkg/status.d/openssl" {
		t.Errorf("md5sums must not be read as a status file: %v", r.Files)
	}
	if r.Ecosystem != "Debian:12" || len(r.Packages) != 1 {
		t.Fatalf("%+v", r)
	}
	p := r.Packages[0]
	if p.Name != "openssl" || p.Version != "3.0.17-1~deb12u2" || !reflect.DeepEqual(p.Binaries, []string{"libssl3", "openssl"}) {
		t.Errorf("%+v", p)
	}
	if _, err := Analyze(memFS{"etc/debian_version": "12"}); err == nil {
		t.Error("no package database must be an error")
	}
}

func TestInstalledFiles(t *testing.T) {
	fs := memFS{
		"var/lib/dpkg/status": "Package: python3-yaml\nStatus: install ok installed\nArchitecture: amd64\nVersion: 6.0-3\n\n" +
			"Package: libc6\nStatus: install ok installed\nArchitecture: amd64\nVersion: 2.36-9\n\n" +
			"Package: nodejs\nStatus: install ok installed\nMaintainer: Nodesource <support@nodesource.com>\nVersion: 20.0.0-1\n\n" +
			"Package: gone\nStatus: deinstall ok config-files\nVersion: 1.0-1\n",
		"var/lib/dpkg/info/python3-yaml.md5sums":   "abc  usr/lib/python3/dist-packages/PyYAML-6.0.dist-info/METADATA\nbad line\n",
		"var/lib/dpkg/info/libc6:amd64.md5sums":    "abc  lib/x86_64-linux-gnu/libc.so.6\n",
		"var/lib/dpkg/info/nodejs.md5sums":         "abc  usr/lib/node_modules/npm/package.json\n",
		"var/lib/dpkg/info/gone.md5sums":           "abc  usr/share/gone\n",
		"var/lib/dpkg/status.d/base-files":         "Package: base-files\nVersion: 12.4\n",
		"var/lib/dpkg/status.d/base-files.md5sums": "abc  etc/debian_version\n",
		"var/lib/dpkg/status.d/tzdata":             "Package: tzdata\nVersion: 2024a-0+deb12u1\n",
		"var/lib/dpkg/status.d/tz.md5sums":         "abc  usr/share/zoneinfo/UTC\n", // named after no package: not used
		"lib/apk/db/installed":                     "P:py3-yaml\nV:6.0-r0\nF:usr/lib/python3.12/site-packages/PyYAML-6.0.dist-info\nR:METADATA\nR:RECORD\nF:usr/bin\nR:x\n",
	}
	got := InstalledFiles(fs)
	want := []string{
		"etc/debian_version", "lib/x86_64-linux-gnu/libc.so.6", "usr/bin/x",
		"usr/lib/python3.12/site-packages/PyYAML-6.0.dist-info/METADATA",
		"usr/lib/python3.12/site-packages/PyYAML-6.0.dist-info/RECORD",
		"usr/lib/python3/dist-packages/PyYAML-6.0.dist-info/METADATA",
	}
	var keys []string
	for k := range got {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if strings.Join(keys, "\n") != strings.Join(want, "\n") {
		t.Errorf("got\n%s\nwant\n%s", strings.Join(keys, "\n"), strings.Join(want, "\n"))
	}
}

// Wolfi/Chainguard: apk database, one rolling stream; a package without an
// origin is matched by its own name (Trivy srcName fallback), unlike Alpine.
func TestWolfiChainguardApk(t *testing.T) {
	db := "P:openssl\nV:3.3.0-r0\no:openssl\n\nP:libcrypto3\nV:3.3.0-r0\no:openssl\n\nP:wolfi-baselayout\nV:20230201-r1\n\n"
	for id, eco := range map[string]string{"wolfi": "Wolfi", "chainguard": "Chainguard"} {
		r, err := Analyze(memFS{"etc/os-release": "ID=" + id + "\nVERSION_ID=20230201\n", "lib/apk/db/installed": db})
		if err != nil || r.Ecosystem != eco || !r.Queryable {
			t.Fatalf("%s: %+v %v", id, r, err)
		}
		got := map[string]string{}
		for _, p := range r.Packages {
			got[p.Name] = p.Version + " " + strings.Join(p.Binaries, ",")
		}
		if got["openssl"] != "3.3.0-r0 libcrypto3,openssl" || got["wolfi-baselayout"] != "20230201-r1 wolfi-baselayout" {
			t.Errorf("%s: %v", id, got)
		}
	}
	r, _ := Analyze(memFS{"etc/os-release": "ID=alpine\nVERSION_ID=3.20.3\n", "lib/apk/db/installed": db})
	for _, p := range r.Packages {
		if p.Name == "wolfi-baselayout" {
			t.Error("Alpine does not match a package without an origin")
		}
	}
}

// Bottlerocket: os-release and software inventory under the target sys-root;
// binary package name, epoch:version-release (Trivy formatVersion).
func TestBottlerocket(t *testing.T) {
	osr := "NAME=Bottlerocket\nID=bottlerocket\nVERSION_ID=1.34.0\n"
	inv := `{"Content":[
	 {"Name":"glibc","Version":"2.43","Release":"1.1781747852.5f13b929.br1","Epoch":"1","InstalledTime":"2026-06-19T00:28:59Z"},
	 {"Name":"kernel-6.1","Version":"6.1.172","Release":"1.br1","Epoch":"0","InstalledTime":"2026-06-19T00:28:59Z"},
	 {"Name":"runc","Version":"1.3.5","Release":"","Epoch":""},
	 {"Name":"","Version":"1","Release":"1","Epoch":"0"},
	 {"Name":"empty","Version":"","Release":"","Epoch":"0"}]}`
	const x86 = "x86_64-bottlerocket-linux-gnu/sys-root/usr/"
	const arm = "aarch64-bottlerocket-linux-gnu/sys-root/usr/"
	fs := memFS{x86 + "lib/os-release": osr, x86 + "share/bottlerocket/application-inventory.json": inv,
		arm + "share/bottlerocket/application-inventory.json": inv}
	if !HasOS(fs) {
		t.Fatal("sys-root os-release is a root filesystem")
	}
	r, err := Analyze(fs)
	if err != nil || r.Ecosystem != "Bottlerocket" || !r.Queryable || r.OS.Name != "1.34.0" {
		t.Fatalf("%+v %v", r, err)
	}
	got := map[string]string{}
	for _, p := range r.Packages {
		got[p.Name] = p.Version + " " + strings.Join(p.Binaries, ",")
	}
	want := map[string]string{"glibc": "1:2.43-1.1781747852.5f13b929.br1 glibc", "kernel-6.1": "6.1.172-1.br1 kernel-6.1",
		"runc": "1.3.5 runc"}
	if len(got) != len(want) {
		t.Errorf("%v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: %q, want %q", k, got[k], v)
		}
	}
	if r.Skipped["no_name"] != 2 || r.Skipped["invalid_version"] != 2 || len(r.Files) != 2 {
		t.Errorf("skipped %v files %v", r.Skipped, r.Files)
	}
	for ad, bozuk := range map[string]string{
		"epoch":  `{"Content":[{"Name":"a","Version":"1","Epoch":"x"}]}`,
		"time":   `{"Content":[{"Name":"a","Version":"1","InstalledTime":"yesterday"}]}`,
		"syntax": `{"Content":[`,
	} {
		if _, err := Analyze(memFS{x86 + "lib/os-release": osr, x86 + "share/bottlerocket/application-inventory.json": bozuk}); err == nil {
			t.Errorf("%s: an unreadable inventory must not scan clean", ad)
		}
	}
	if _, err := Analyze(memFS{x86 + "lib/os-release": osr}); err == nil {
		t.Error("no inventory: must not scan clean")
	}
	if _, err := Analyze(memFS{"etc/os-release": "ID=alpine\nVERSION_ID=3.20.3\n", x86 + "lib/os-release": osr,
		"lib/apk/db/installed": "P:a\nV:1-r0\no:a\n\n"}); err == nil || !strings.Contains(err.Error(), "conflicting") {
		t.Errorf("conflicting families: %v", err)
	}
	if _, err := Analyze(memFS{"etc/os-release": osr, x86 + "lib/os-release": osr,
		x86 + "share/bottlerocket/application-inventory.json": inv}); err != nil {
		t.Errorf("same family in both: %v", err)
	}
}

// Echo: dpkg, one bucket, third-party packages kept (Trivy echo FilterPackages);
// MinimOS: apk like Wolfi; CoreOS: Trivy matches nothing, here unsupported.
func TestEchoMinimOSCoreOS(t *testing.T) {
	status := "Package: gh\nStatus: install ok installed\nMaintainer: GitHub\nVersion: 2.40.0+echo1\n\n" +
		"Package: libssl3\nStatus: install ok installed\nMaintainer: Debian\nSource: openssl (3.0.15-1~deb12u1)\nVersion: 3.0.15-1~deb12u1\n\n"
	fs := memFS{"etc/os-release": "ID=echo\nVERSION_ID=1\n", "etc/debian_version": "12.8\n", "var/lib/dpkg/status": status}
	r, err := Analyze(fs)
	if err != nil || r.Ecosystem != "Echo" || !r.Queryable {
		t.Fatalf("%+v %v", r, err)
	}
	got := map[string]string{}
	for _, p := range r.Packages {
		got[p.Name] = p.Version
	}
	if got["gh"] != "2.40.0+echo1" || got["openssl"] != "3.0.15-1~deb12u1" || r.Skipped["third_party"] != 0 {
		t.Errorf("echo: %v %v", got, r.Skipped)
	}
	fs["etc/os-release"] = "ID=debian\nVERSION_ID=12\n"
	r, _ = Analyze(fs)
	if r.Ecosystem != "Debian:12" || r.Skipped["third_party"] != 1 {
		t.Errorf("debian still drops third-party packages: %+v", r)
	}
	r, err = Analyze(memFS{"etc/os-release": "ID=minimos\nVERSION_ID=\"20241031\"\n",
		"lib/apk/db/installed": "P:busybox\nV:1.37.0-r0\n\n"})
	if err != nil || r.Ecosystem != "MinimOS" || len(r.Packages) != 1 || r.Packages[0].Name != "busybox" {
		t.Errorf("minimos: %+v %v", r, err)
	}
	_, err = Analyze(memFS{"etc/os-release": "ID=coreos\nVERSION_ID=3.15.4\n"})
	var u ErrUnsupported
	if !errors.As(err, &u) || u.Family != "coreos" {
		t.Errorf("coreos must be reported unsupported, not scanned clean: %v", err)
	}
}

// Seal Security dpkg/apk packages get their own rows (Ubuntu uses Seal's
// Debian bucket) and are kept even with a third-party maintainer.
func TestSealDpkgApk(t *testing.T) {
	// libssl3t64: binary without the prefix, source with it; maintainer
	// "GitHub" is a third-party marker, which a Seal package survives.
	status := "Package: libssl3t64\nStatus: install ok installed\nMaintainer: GitHub\nSource: seal-openssl (3.0.13-0ubuntu3.4+sp1)\nVersion: 3.0.13-0ubuntu3.4+sp1\n\n" +
		"Package: libssl3\nStatus: install ok installed\nMaintainer: Ubuntu Developers\nSource: openssl (3.0.13-0ubuntu3.4)\nVersion: 3.0.13-0ubuntu3.4\n\n" +
		"Package: gh\nStatus: install ok installed\nMaintainer: GitHub\nVersion: 2.40.0\n\n"
	r, err := Analyze(memFS{"etc/os-release": "ID=ubuntu\nVERSION_ID=24.04\n", "var/lib/dpkg/status": status})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, p := range r.Packages {
		got[p.Ecosystem+" "+p.Name] = p.Version
	}
	if got["Seal:Debian seal-openssl"] != "3.0.13-0ubuntu3.4+sp1" || got["Ubuntu:24.04 openssl"] != "3.0.13-0ubuntu3.4" ||
		len(got) != 2 || r.Skipped["third_party"] != 1 {
		t.Errorf("%v %v", got, r.Skipped)
	}
	r, _ = Analyze(memFS{"etc/os-release": "ID=alpine\nVERSION_ID=3.20.3\n",
		"lib/apk/db/installed": "P:seal-busybox\nV:1.36.1-r005341001\no:seal-busybox\n\nP:musl\nV:1.2.5-r0\no:musl\n\n"})
	got = map[string]string{}
	for _, p := range r.Packages {
		got[p.Ecosystem+" "+p.Name] = p.Version
	}
	if got["Seal:Alpine seal-busybox"] != "1.36.1-r005341001" || got["Alpine:v3.20 musl"] != "1.2.5-r0" {
		t.Errorf("%v", got)
	}
	// Seal only on Trivy's supported families: Echo keeps it in its own feed.
	r, _ = Analyze(memFS{"etc/os-release": "ID=echo\nVERSION_ID=1\n", "var/lib/dpkg/status": status})
	for _, p := range r.Packages {
		if p.Ecosystem != "Echo" {
			t.Errorf("echo: %v", p)
		}
	}
}

// Root.io: one marked package turns every OS package of the image into a
// Root.io query (before Seal); third-party packages still dropped but they
// count for detection.
func TestRootio(t *testing.T) {
	st := func(extra string) string {
		return "Package: libssl3\nStatus: install ok installed\nMaintainer: Debian\nSource: openssl (3.0.15-1~deb12u1.root.io.1)\nVersion: 3.0.15-1~deb12u1.root.io.1\n\n" +
			"Package: bash\nStatus: install ok installed\nMaintainer: Debian\nVersion: 5.2.15-2+b7\n\n" +
			"Package: seal-curl\nStatus: install ok installed\nMaintainer: GitHub\nVersion: 7.88.1-10+sp1\n\n" + extra
	}
	r, err := Analyze(memFS{"etc/os-release": "ID=debian\nVERSION_ID=12\n", "etc/debian_version": "12.8\n",
		"var/lib/dpkg/status": st("")})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, p := range r.Packages {
		got[p.Name] = p.Ecosystem + " " + p.Version
	}
	want := map[string]string{"openssl": "Root.io:Debian:12 3.0.15-1~deb12u1.root.io.1", "bash": "Root.io:Debian:12 5.2.15-2+b7"}
	if len(got) != 2 || got["openssl"] != want["openssl"] || got["bash"] != want["bash"] || r.Skipped["third_party"] != 1 {
		t.Errorf("%v %v", got, r.Skipped)
	}
	// marker only on a third-party package: still a Root.io environment
	third := "Package: libssl3\nStatus: install ok installed\nMaintainer: Debian\nSource: openssl (3.0.15-1~deb12u1)\nVersion: 3.0.15-1~deb12u1\n\n" +
		"Package: gh\nStatus: install ok installed\nMaintainer: GitHub\nVersion: 2.40.0.root.io.1\n\n"
	r, _ = Analyze(memFS{"etc/os-release": "ID=ubuntu\nVERSION_ID=22.04\n", "var/lib/dpkg/status": third})
	if len(r.Packages) != 1 || r.Packages[0].Ecosystem != "Root.io:Ubuntu:22.04" {
		t.Errorf("third-party marker: %+v", r.Packages)
	}
	r, _ = Analyze(memFS{"etc/os-release": "ID=alpine\nVERSION_ID=3.20.3\n",
		"lib/apk/db/installed": "P:busybox\nV:1.36.1-r00071\no:busybox\n\nP:musl\nV:1.2.5-r0\no:musl\n\n"})
	for _, p := range r.Packages {
		if p.Ecosystem != "Root.io:Alpine:3.20" {
			t.Errorf("alpine: %+v", p)
		}
	}
	r, _ = Analyze(memFS{"etc/os-release": "ID=alpine\nVERSION_ID=3.20.3\n",
		"lib/apk/db/installed": "P:busybox\nV:1.36.1-r29\no:busybox\n\n"})
	if r.Packages[0].Ecosystem != "Alpine:v3.20" {
		t.Errorf("-r29 is not a Root.io marker: %+v", r.Packages)
	}
	if !rootioAlpine.MatchString("1.36.1-r10071") || !rootioAlpine.MatchString("1.36.1-r100712") { // unanchored, as in Trivy
		t.Error("Trivy's -r\\d007\\d matches -r10071 too")
	}
}

// RapidFort curated dpkg/apk images: marker file, every package kept, before
// Root.io; ecosystem version trimmed like Trivy.
func TestRapidFort(t *testing.T) {
	status := "Package: libssl3\nStatus: install ok installed\nMaintainer: Ubuntu\nSource: openssl (3.0.2-0ubuntu1.10+rf1)\nVersion: 3.0.2-0ubuntu1.10+rf1\n\n" +
		"Package: openssl\nStatus: install ok installed\nMaintainer: Ubuntu\nVersion: 3.0.2-0ubuntu1.10+rf1\n\n" +
		"Package: gh\nStatus: install ok installed\nMaintainer: GitHub\nVersion: 2.40.0.root.io.1\n\n"
	fs := memFS{"etc/os-release": "ID=ubuntu\nVERSION_ID=22.04\n", "var/lib/dpkg/status": status, RapidFortMarker: ""}
	r, err := Analyze(fs)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, p := range r.Packages {
		got[p.Name] = p.Ecosystem + " " + strings.Join(p.Binaries, ",")
	}
	if got["openssl"] != "RapidFort:Ubuntu:22.04 libssl3,openssl" || got["gh"] != "RapidFort:Ubuntu:22.04 gh" ||
		len(got) != 2 || r.Skipped["third_party"] != 0 {
		t.Errorf("%v %v", got, r.Skipped)
	}
	delete(fs, RapidFortMarker)
	r, _ = Analyze(fs)
	for _, p := range r.Packages {
		if !strings.HasPrefix(p.Ecosystem, "Root.io:") {
			t.Errorf("without the marker the Root.io marker decides: %+v", p)
		}
	}
	r, _ = Analyze(memFS{"etc/os-release": "ID=alpine\nVERSION_ID=3.20.3\n", RapidFortMarker: "{}",
		"lib/apk/db/installed": "P:busybox\nV:1.36.1-r29\n\n"})
	if len(r.Packages) != 1 || r.Packages[0].Ecosystem != "RapidFort:Alpine:3.20" || r.Packages[0].Name != "busybox" {
		t.Errorf("alpine without origin: %+v", r.Packages)
	}
	if e := rapidfortEcosystem(OS{Family: "amazon", Name: "2023.6.20241010"}, memFS{RapidFortMarker: ""}); e != "RapidFort:Amazon:2023" {
		t.Error(e)
	}
	if e := rapidfortEcosystem(OS{Family: "amazon", Name: "2 (Karoo)"}, memFS{RapidFortMarker: ""}); e != "RapidFort:Amazon:2" {
		t.Error(e)
	}
	if e := rapidfortEcosystem(OS{Family: "redhat", Name: "9.4"}, memFS{RapidFortMarker: ""}); e != "RapidFort:RedHat:9" {
		t.Error(e)
	}
	if e := rapidfortEcosystem(OS{Family: "centos", Name: "7.9"}, memFS{RapidFortMarker: ""}); e != "" {
		t.Error("centos is not a RapidFort family:", e)
	}
	// too many binaries: unchecked, never cut short
	var b strings.Builder
	for i := 0; i <= MaxRapidFortBinaries; i++ {
		fmt.Fprintf(&b, "Package: texlive-%d\nStatus: install ok installed\nSource: texlive-base (2022.20230122-3)\nVersion: 2022.20230122-3\n\n", i)
	}
	r, err = Analyze(memFS{"etc/os-release": "ID=debian\nVERSION_ID=12\n", "etc/debian_version": "12.8\n",
		"var/lib/dpkg/status": b.String(), RapidFortMarker: ""})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Packages) != 0 || len(r.Unchecked) != 1 || r.Unchecked[0].UncheckedReason != RapidFortTooManyBinaries {
		t.Errorf("limit: %d packages, unchecked %v", len(r.Packages), len(r.Unchecked))
	}
}

// usr-merged images (current Wolfi, apk-tools 3) keep the apk database under
// usr/ — Trivy's apk analyzer reads both paths (v0.76.2 requiredFiles). Rows
// stay one per source package when both files list the same package, and the
// usr/ file's F:/R: entries count as installed files (language package
// exclusion), as in Trivy.
func TestApkUsrMerged(t *testing.T) {
	db := "P:busybox\nV:1.37.0-r30\no:busybox\nF:usr/bin\nR:busybox\n\nP:wolfi-baselayout\nV:20230201-r24\no:wolfi-baselayout\n\n"
	wolfi := "ID=wolfi\nVERSION_ID=20230201\n"
	r, err := Analyze(memFS{"etc/os-release": wolfi, "usr/lib/apk/db/installed": db})
	if err != nil || len(r.Files) != 1 || r.Files[0] != "usr/lib/apk/db/installed" || len(r.Packages) != 2 {
		t.Fatalf("%+v %v", r, err)
	}
	r, err = Analyze(memFS{"etc/os-release": wolfi, "lib/apk/db/installed": db, "usr/lib/apk/db/installed": db})
	if err != nil || len(r.Files) != 2 || r.Files[0] != "lib/apk/db/installed" || len(r.Packages) != 2 {
		t.Fatalf("both paths: %+v %v", r, err)
	}
	for _, p := range r.Packages {
		if len(p.Binaries) != 1 {
			t.Errorf("a package listed in both files must stay one row: %+v", p)
		}
	}
	if !InstalledFiles(memFS{"etc/os-release": wolfi, "usr/lib/apk/db/installed": db})["usr/bin/busybox"] {
		t.Error("usr/lib/apk/db/installed must give installed files")
	}
	// Two different files: both are read (append, not replace).
	r, err = Analyze(memFS{"etc/os-release": wolfi, "lib/apk/db/installed": "P:a\nV:1-r0\no:a\n\n", "usr/lib/apk/db/installed": "P:b\nV:1-r0\no:b\n\n"})
	if err != nil || len(r.Packages) != 2 {
		t.Errorf("both files' packages: %+v %v", r, err)
	}
	// Root.io's Alpine marker is found in the usr/ database too.
	r, _ = Analyze(memFS{"etc/os-release": "ID=alpine\nVERSION_ID=3.20.3\n",
		"usr/lib/apk/db/installed": "P:busybox\nV:1.36.1-r00071\no:busybox\n\n"})
	if len(r.Packages) != 1 || r.Packages[0].Ecosystem != "Root.io:Alpine:3.20" {
		t.Errorf("root.io usr-merged: %+v", r.Packages)
	}
	alp := "ID=alpine\nVERSION_ID=3.22.1\n"
	if r, err := Analyze(memFS{"etc/os-release": alp, "usr/lib/apk/db/installed": db}); err != nil || r.Ecosystem != "Alpine:v3.22" || len(r.Packages) != 2 {
		t.Errorf("alpine usr-merged: %+v %v", r, err)
	}
	for _, p := range ApkPaths {
		if !contains(Paths, p) {
			t.Errorf("image and rootfs readers must fetch %s", p)
		}
	}
}
