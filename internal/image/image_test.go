package image

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

type ent struct {
	name, body string
	typ        byte
	link       string
	mode       int64
}

func tarOf(t *testing.T, es []ent) []byte {
	t.Helper()
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	for _, e := range es {
		typ := e.typ
		if typ == 0 {
			typ = tar.TypeReg
		}
		mode := e.mode
		if mode == 0 {
			mode = 0o644
		}
		h := &tar.Header{Name: e.name, Mode: mode, Size: int64(len(e.body)), Typeflag: typ, Linkname: e.link}
		if typ != tar.TypeReg {
			h.Size = 0
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if typ == tar.TypeReg {
			tw.Write([]byte(e.body))
		}
	}
	tw.Close()
	return b.Bytes()
}

func gz(b []byte) []byte {
	var o bytes.Buffer
	w := gzip.NewWriter(&o)
	w.Write(b)
	w.Close()
	return o.Bytes()
}

func save(t *testing.T, layers [][]byte, manifest any) string {
	t.Helper()
	var outer []ent
	var names []string
	for i, l := range layers {
		n := "blobs/sha256/layer" + string(rune('a'+i))
		names = append(names, n)
		outer = append(outer, ent{name: n, body: string(l)})
	}
	if manifest == nil {
		manifest = []map[string]any{{"RepoTags": []string{"test:1"}, "Layers": names}}
	}
	m, _ := json.Marshal(manifest)
	outer = append([]ent{{name: "manifest.json", body: string(m)}}, outer...)
	p := filepath.Join(t.TempDir(), "img.tar")
	if err := os.WriteFile(p, tarOf(t, outer), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLayersWhiteoutsAndSafety(t *testing.T) {
	base := tarOf(t, []ent{
		{name: "etc/debian_version", body: "11.3\n"},
		{name: "etc/os-release", body: "ID=ubuntu\nVERSION_ID=22.04\n"}, // replaced by a symlink above
		{name: "./var/lib/dpkg/status", body: "Package: old\nVersion: 1-1\n"},
		{name: "var/lib/dpkg/status.d/a", body: "Package: a\nVersion: 1-1\n"},
		{name: "var/lib/dpkg/status.d/b", body: "Package: b\nVersion: 1-1\n"},
		{name: "lib/apk/db/installed", body: "P:x\n"},
		{name: "usr/share/doc/big", body: strings.Repeat("x", 1000)}, // not wanted: not kept
	})
	top := gz(tarOf(t, []ent{
		{name: "var/lib/dpkg/status", body: "Package: new\nVersion: 2-1\n"}, // later layer wins
		{name: "var/lib/dpkg/status.d/.wh..wh..opq", body: ""},              // opaque: a, b gone
		{name: "var/lib/dpkg/status.d/c", body: "Package: c\nVersion: 1-1\n"},
		{name: "lib/apk/db/.wh.installed", body: ""}, // whiteout
		{name: "etc/os-release", typ: tar.TypeSymlink, link: "../usr/lib/os-release"},
		{name: "../../etc/lsb-release", body: "DISTRIB_ID=Ubuntu\nDISTRIB_RELEASE=22.04\n"}, // climbs out: ignored
	}))
	im, err := Open(save(t, [][]byte{base, top}, nil))
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := im.Get("var/lib/dpkg/status"); string(b) != "Package: new\nVersion: 2-1\n" {
		t.Errorf("status: %q", b)
	}
	if got := im.List("var/lib/dpkg/status.d/"); strings.Join(got, ",") != "var/lib/dpkg/status.d/c" {
		t.Errorf("status.d after opaque dir: %v", got)
	}
	for _, p := range []string{"lib/apk/db/installed", "etc/os-release", "etc/lsb-release", "usr/share/doc/big"} {
		if _, ok := im.Get(p); ok {
			t.Errorf("%s must not be present", p)
		}
	}
	if im.Layers != 2 || im.Tags[0] != "test:1" {
		t.Errorf("meta %+v", im)
	}
}

func TestRejectsBadArchives(t *testing.T) {
	l := tarOf(t, []ent{{name: "etc/debian_version", body: "12"}})
	cases := map[string]string{
		"two images": save(t, [][]byte{l}, []map[string]any{{"Layers": []string{"blobs/sha256/layera"}},
			{"Layers": []string{"blobs/sha256/layera"}}}),
		"missing layer":  save(t, [][]byte{l}, []map[string]any{{"Layers": []string{"blobs/sha256/nope"}}}),
		"climbing layer": save(t, [][]byte{l}, []map[string]any{{"Layers": []string{"../x"}}}),
		"not a manifest": save(t, [][]byte{l}, map[string]any{"x": 1}),
	}
	for name, p := range cases {
		if _, err := Open(p); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	if _, err := Open(save(t, [][]byte{{0x28, 0xb5, 0x2f, 0xfd, 0, 0}}, nil)); err == nil || !strings.Contains(err.Error(), "zstd") {
		t.Errorf("zstd layer: %v", err)
	}
	nm := filepath.Join(t.TempDir(), "x.tar")
	os.WriteFile(nm, tarOf(t, []ent{{name: "a", body: "b"}}), 0o600)
	if _, err := Open(nm); err == nil || !strings.Contains(err.Error(), "manifest.json") {
		t.Errorf("no manifest: %v", err)
	}
}

func TestCleanRejectsPathsOutsideRoot(t *testing.T) {
	for in, want := range map[string]string{
		"./var/lib/dpkg/status": "var/lib/dpkg/status", "/etc/os-release": "etc/os-release",
		"etc/../etc/os-release": "etc/os-release", "../etc/os-release": "", "..": "",
		"a/../../etc/passwd": "", "": "", "./": "", "etc/x\x00y": "",
	} {
		got, ok := clean(in)
		if (want == "") == ok || got != want {
			t.Errorf("clean(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
}

func TestLanguageFilesAndGoBinaries(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	gobin, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	exec := func(name string, body []byte) ent { return ent{name: name, body: string(body), mode: 0o755} }
	base := tarOf(t, []ent{
		{name: "app/node_modules/lodash/package.json", body: `{"name":"lodash","version":"4.17.20"}`},
		{name: "app/node_modules/gone/package.json", body: `{"name":"gone","version":"1.0.0"}`},
		{name: "app/README.md", body: "not kept"},
		exec("usr/bin/tool", gobin),
		exec("usr/bin/old", gobin),
		exec("usr/bin/script", []byte("#!/bin/sh\necho not a binary at all\n")),
		{name: "usr/bin/notexec", body: string(gobin)}, // no exec bit: not read
		{name: "var/lib/dpkg/info/libc6.md5sums", body: "abc  lib/libc.so.6\n"},
		{name: "var/lib/dpkg/info/libc6.list", body: "/lib/libc.so.6\n"},
		exec("opt/bin/replaced", gobin),
		{name: "srv/node_modules/a/package.json", body: `{"name":"a","version":"1.0.0"}`},
		{name: "srv/node_modules/b/package.json", body: `{"name":"b","version":"1.0.0"}`},
	})
	top := tarOf(t, []ent{
		{name: "usr/bin/.wh.old"},
		{name: "app/node_modules", typ: tar.TypeSymlink, link: "/elsewhere"}, // replaces the whole directory
		{name: "app/node_modules2/x/package.json", body: `{"name":"x","version":"1.0.0"}`},
		{name: "opt/bin/replaced", typ: tar.TypeDir}, // a file replaced by a directory
		{name: "srv/.wh.node_modules"},               // a whole directory deleted
	})
	im, err := Open(save(t, [][]byte{base, top}, nil))
	if err != nil {
		t.Fatal(err)
	}
	var md []string
	for p := range im.Metadata() {
		md = append(md, p)
	}
	sort.Strings(md)
	if strings.Join(md, ",") != "app/node_modules2/x/package.json,var/lib/dpkg/info/libc6.md5sums" {
		t.Errorf("metadata %v", md)
	}
	bins := im.GoBinaries()
	if len(bins) != 1 || bins["usr/bin/tool"] == nil || bins["usr/bin/tool"].Info.GoVersion != runtime.Version() {
		t.Errorf("go binaries %v", bins)
	}
	total := 0
	for _, b := range im.files {
		total += len(b)
	}
	if im.keptBytes != total { // replaced and deleted files are not counted
		t.Errorf("kept bytes %d, files now %d", im.keptBytes, total)
	}
	if im.execRead != 3 { // tool, old, replaced; the script and the 0644 file are not read
		t.Errorf("executables read in full: %d", im.execRead)
	}
	if im.under["app/node_modules"] != 0 || im.under["app"] != 1 || im.under["usr/bin"] != 1 || im.under["srv"] != 0 ||
		im.under["opt/bin"] != 0 {
		t.Errorf("directory counters %v", im.under)
	}
}

func rpmDB(t *testing.T, name string) string {
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
	var b bytes.Buffer
	if _, err := b.ReadFrom(g); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

const ubi8Dockerfile = "FROM x\nLABEL com.redhat.component=\"ubi8-container\" \\\n      architecture=\"x86_64\"\n"

// Trivy applier lookupOriginLayerForPkg + lookupBuildInfo.
func TestRedHatBuildInfoPerLayer(t *testing.T) {
	sqlite, bdb := rpmDB(t, "sqlite.db.gz"), rpmDB(t, "bdb.db.gz")
	df := ent{name: "root/buildinfo/Dockerfile-ubi8-8.1-408", body: ubi8Dockerfile}
	cm := ent{name: "root/buildinfo/content_manifests/x.json", body: `{"content_sets":["rhel-8-for-x86_64-appstream-rpms__8"]}`}
	open := func(layers ...[]ent) *Image {
		var ls [][]byte
		for _, l := range layers {
			ls = append(ls, gz(tarOf(t, l)))
		}
		im, err := Open(save(t, ls, nil))
		if err != nil {
			t.Fatal(err)
		}
		return im
	}
	get := func(im *Image, n, v, r string) (*Image, string, bool) {
		bi, known := im.RPMBuildInfo(n, v, r)
		if bi == nil {
			return im, "<nil>", known
		}
		return im, bi.Nvr + "-" + bi.Arch + "|" + strings.Join(bi.ContentSets, ","), known
	}
	// Base layer packages take the second layer's build information.
	im := open([]ent{{name: "var/lib/rpm/rpmdb.sqlite", body: sqlite}}, []ent{df})
	if _, got, known := get(im, "tree", "1.8.0", "10.el9"); got != "ubi8-container-8.1-408-x86_64|" || !known {
		t.Errorf("base layer: %s %v", got, known)
	}
	// A later layer without its own build information: the nearest earlier one.
	im = open([]ent{{name: "var/lib/rpm/rpmdb.sqlite", body: sqlite}}, []ent{df, cm},
		[]ent{{name: "etc/x", body: "y"}}, []ent{{name: "var/lib/rpm/Packages", body: bdb}})
	if _, got, _ := get(im, "tree", "1.6.0", "10.amzn2.0.1"); got != "ubi8-container-8.1-408-x86_64|rhel-8-for-x86_64-appstream-rpms__8" {
		t.Errorf("later layer: %s", got)
	}
	// The first layer whose database holds the package is its origin, even if
	// a later layer rewrites the database.
	if _, got, _ := get(im, "words", "3.0", "39.el9.0.1"); got != "ubi8-container-8.1-408-x86_64|rhel-8-for-x86_64-appstream-rpms__8" {
		t.Errorf("origin: %s", got)
	}
	// A layer's own build information wins; a single-layer image without any has none.
	im = open([]ent{{name: "var/lib/rpm/rpmdb.sqlite", body: sqlite}, cm})
	if _, got, _ := get(im, "tree", "1.8.0", "10.el9"); got != "-|rhel-8-for-x86_64-appstream-rpms__8" {
		t.Errorf("own: %s", got)
	}
	im = open([]ent{{name: "var/lib/rpm/rpmdb.sqlite", body: sqlite}})
	if _, got, known := get(im, "tree", "1.8.0", "10.el9"); got != "<nil>" || !known {
		t.Errorf("none: %s", got)
	}
	// A package in no layer's database: none.
	if _, got, _ := get(im, "tree", "9", "9"); got != "<nil>" {
		t.Errorf("unknown package: %s", got)
	}
	// An unreadable Dockerfile makes the answer unknown, never "no build info".
	bad := ent{name: "root/buildinfo/Dockerfile-x-1-2", body: "FROM x\nARG A=1\nLABEL com.redhat.component=c architecture=a\n"}
	im = open([]ent{{name: "var/lib/rpm/rpmdb.sqlite", body: sqlite}}, []ent{bad})
	if _, _, known := get(im, "tree", "1.8.0", "10.el9"); known {
		t.Error("unreadable Dockerfile must be unknown")
	}
	// Build information files are per layer: a later layer deleting them does
	// not remove the earlier layer's (Trivy analyses each layer's own files).
	im = open([]ent{{name: "var/lib/rpm/rpmdb.sqlite", body: sqlite}, cm},
		[]ent{{name: "root/buildinfo/.wh.content_manifests"}})
	if _, got, _ := get(im, "tree", "1.8.0", "10.el9"); got != "-|rhel-8-for-x86_64-appstream-rpms__8" {
		t.Errorf("whiteout: %s", got)
	}
}

// The origin layer's own unreadable Dockerfile: unknown even in a one-layer image.
func TestRedHatBuildInfoOwnLayerUnknown(t *testing.T) {
	bad := ent{name: "root/buildinfo/Dockerfile-x-1-2", body: "FROM x\nARG A=1\n"}
	im, err := Open(save(t, [][]byte{gz(tarOf(t, []ent{{name: "var/lib/rpm/rpmdb.sqlite", body: rpmDB(t, "sqlite.db.gz")}, bad}))}, nil))
	if err != nil {
		t.Fatal(err)
	}
	if _, known := im.RPMBuildInfo("tree", "1.8.0", "10.el9"); known {
		t.Error("unknown")
	}
}

// Java archives are parsed per layer and only the result kept; whiteouts and
// replacements remove them like any other file.
func TestJarsPerLayer(t *testing.T) {
	jar := func(g, a, v string) string {
		var buf bytes.Buffer
		w := zip.NewWriter(&buf)
		f, _ := w.Create("META-INF/maven/" + g + "/" + a + "/pom.properties")
		f.Write([]byte("groupId=" + g + "\nartifactId=" + a + "\nversion=" + v + "\n"))
		w.Close()
		return buf.String()
	}
	base := tarOf(t, []ent{
		{name: "app/lib/log4j-core-2.14.1.jar", body: jar("org.apache.logging.log4j", "log4j-core", "2.14.1")},
		{name: "app/lib/gone-1.0.jar", body: jar("g", "gone", "1.0")},
		{name: "app/lib/replaced-1.0.jar", body: jar("g", "replaced", "1.0")},
		{name: "app/APP.WAR", body: jar("g", "war", "3.0")}, // extension in any case
	})
	top := tarOf(t, []ent{
		{name: "app/lib/.wh.gone-1.0.jar"},
		{name: "app/lib/replaced-1.0.jar", body: "plain text now"},
	})
	im, err := Open(save(t, [][]byte{base, top}, nil))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for p, j := range im.Jars() {
		names := []string{}
		for _, k := range j.Packages {
			names = append(names, k.Name+"@"+k.Version)
		}
		got[p] = strings.Join(names, ",") + "|" + j.Err
	}
	want := map[string]string{
		"app/lib/log4j-core-2.14.1.jar": "org.apache.logging.log4j:log4j-core@2.14.1|",
		"app/lib/replaced-1.0.jar":      "|zip error: zip: not a valid zip file",
		"app/APP.WAR":                   "g:war@3.0|",
	}
	if len(got) != len(want) {
		t.Errorf("%v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: %q want %q", k, got[k], v)
		}
	}
}

func TestJarTooLarge(t *testing.T) {
	old := maxJarBytes
	maxJarBytes = 10
	defer func() { maxJarBytes = old }()
	im, err := Open(save(t, [][]byte{tarOf(t, []ent{{name: "app/big.jar", body: "more than ten bytes"}})}, nil))
	if err != nil {
		t.Fatal(err)
	}
	if j := im.Jars()["app/big.jar"]; j == nil || !j.TooLarge {
		t.Errorf("%+v", j)
	}
}

// Executables are read for cargo-auditable data as well as Go build
// information; a whiteout removes the result.
func TestRustBinariesPerLayer(t *testing.T) {
	var dep bytes.Buffer
	w := zlib.NewWriter(&dep)
	w.Write([]byte(`{"packages":[{"name":"memchr","version":"2.7.1","source":"crates.io"}]}`))
	w.Close()
	wasm := append([]byte("\x00asm\x01\x00\x00\x00"), 0, byte(1+7+dep.Len()), 7)
	wasm = append(append(wasm, ".dep-v0"...), dep.Bytes()...)
	base := tarOf(t, []ent{
		{name: "usr/bin/app.wasm", body: string(wasm), mode: 0o755},
		{name: "usr/bin/gone.wasm", body: string(wasm), mode: 0o755},
		{name: "usr/share/noexec.wasm", body: string(wasm)}, // not executable: not read
	})
	top := tarOf(t, []ent{{name: "usr/bin/.wh.gone.wasm"}})
	im, err := Open(save(t, [][]byte{base, top}, nil))
	if err != nil {
		t.Fatal(err)
	}
	rs := im.RustBinaries()
	if len(rs) != 1 || rs["usr/bin/app.wasm"] == nil || len(rs["usr/bin/app.wasm"].Packages) != 1 ||
		rs["usr/bin/app.wasm"].Packages[0] != [2]string{"memchr", "2.7.1"} {
		t.Errorf("%+v", rs)
	}
}
