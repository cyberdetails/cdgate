package langpkg

import (
	"archive/zip"
	"bytes"
	"os"
	"reflect"
	"runtime"
	"runtime/debug"
	"sort"
	"strings"
	"testing"
)

type memSource struct {
	files map[string][]byte
	bins  map[string]*GoBinary
	jars  map[string]*Jar
	rust  map[string]*RustBinary
}

func (m memSource) Metadata() map[string][]byte          { return m.files }
func (m memSource) GoBinaries() map[string]*GoBinary     { return m.bins }
func (m memSource) Jars() map[string]*Jar                { return m.jars }
func (m memSource) RustBinaries() map[string]*RustBinary { return m.rust }

func TestClassify(t *testing.T) {
	cases := []struct {
		p    string
		perm int64
		want Kind
	}{
		{"app/node_modules/lodash/package.json", 0o644, NodePkg},
		{"package.json", 0o644, NodePkg},
		{"usr/lib/python3/site-packages/requests-2.25.0.dist-info/METADATA", 0o644, PythonPkg},
		{"usr/lib/python3/site-packages/x.dist-info/RECORD", 0o644, 0},
		{"opt/METADATA", 0o644, 0}, // METADATA outside a dist-info is not a package
		{"usr/lib/python2.7/foo.egg-info", 0o644, PythonPkg},
		{"usr/lib/python2.7/foo.egg-info/PKG-INFO", 0o644, PythonPkg},
		{"usr/lib/python2.7/foo.egg-info/METADATA", 0o644, PythonPkg},
		{"x/foo.egg/EGG-INFO/PKG-INFO", 0o644, PythonPkg},
		{"x/foo-1.0-py3.egg", 0o644, PythonEgg},
		{"usr/lib/ruby/gems/3.3.0/specifications/rake-13.0.6.gemspec", 0o644, GemSpec},
		{"specifications/rake.gemspec", 0o644, 0}, // Trivy's regexp needs a "/" before
		{"app/vendor/composer/installed.json", 0o644, ComposerVendor},
		{"usr/bin/caddy", 0o755, GoExe},
		{"usr/bin/caddy", 0o700, GoExe},
		{"usr/bin/data", 0o644, 0},
		{"Program Files/x.exe", 0o644, GoExe},
		{"bin/package.json", 0o755, NodePkg | GoExe},
	}
	for _, c := range cases {
		if got := Classify(c.p, c.perm); got != c.want {
			t.Errorf("Classify(%q, %o) = %b, want %b", c.p, c.perm, got, c.want)
		}
	}
}

func egg(t *testing.T, name, body string) []byte {
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	f, err := w.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	f.Write([]byte(body))
	w.Close()
	return b.Bytes()
}

func names(ps []string) string { sort.Strings(ps); return strings.Join(ps, ",") }

func TestAnalyze(t *testing.T) {
	src := memSource{files: map[string][]byte{
		"a/node_modules/lodash/package.json":                    []byte(`{"name":"lodash","version":"4.17.20","license":{"weird":1}}`),
		"a/node_modules/@babel/core/package.json":               []byte(`{"name":"@babel/core","version":"7.0.0"}`),
		"a/node_modules/rxjs/ajax/package.json":                 []byte(`{"main":"../index.js"}`), // subpath helper: no version
		"a/node_modules/bad/package.json":                       []byte(`{"name":"Bad Name!","version":"1.0.0"}`),
		"a/node_modules/deps/package.json":                      []byte(`{"name":"deps","version":"1.0.0","dependencies":["x"]}`),
		"a/node_modules/nover/package.json":                     []byte(`{"name":"nover"}`), // Trivy: not a package
		"a/node_modules/trail/package.json":                     []byte(`{"name":"trail","version":"2.0.0"} trailing`),
		"site/requests-2.25.0.dist-info/METADATA":               []byte("Metadata-Version: 2.1\nName: requests\nVersion: 2.25.0\n\nlong description: Name: other\n"),
		"site/PyYAML-6.0.dist-info/METADATA":                    []byte("Name: PyYAML\nVersion: 6.0\n"),
		"site/old.egg-info":                                     []byte("Name: oldpkg\nVersion: 0.1\n"),
		"site/broken.dist-info/METADATA":                        []byte("Name: broken\n"),
		"site/proto.dist-info/METADATA":                         []byte("Name: proto\nVersion: 1.0\nBad Key\xff: x\n"),
		"site/z-1.0-py3.egg":                                    egg(t, "EGG-INFO/PKG-INFO", "Name: zegg\nVersion: 1.0\n"),
		"site/empty-1.0-py3.egg":                                egg(t, "README", "x"),
		"g/specifications/rake-13.0.6.gemspec":                  []byte("Gem::Specification.new do |s|\n  s.name = \"rake\".freeze\n  s.version = \"13.0.6\"\nend\n"),
		"g/specifications/dot.gemspec":                          []byte(".name = 'dot'\n.version = '1.0'\n"), // no Gem::Specification.new
		"g/specifications/nov.gemspec":                          []byte("s.name = \"x\"\ns.version = \"1\"\n"),
		"g/specifications/spec.gemspec":                         []byte("Gem::Specification.new do |spec|\n spec.name = 'thor'\n spec.version = '1.2.1'\n spec.version = '1.2.2'\nend\n"),
		"v/composer/installed.json":                             []byte(`{"packages":[{"name":"guzzlehttp/guzzle","version":"7.4.0"},{"name":"guzzlehttp/guzzle","version":"9"}],"packages-dev":[{"name":"phpunit/phpunit","version":"9.5.0"}]}`),
		"v1/composer/installed.json":                            []byte(`[{"name":"old/style","version":"1.0.0"}]`),
		"var/lib/dpkg/status":                                   []byte("Package: x\n"), // OS file: no language kind
		"usr/lib/python3/dist-packages/yaml.dist-info/METADATA": []byte("Name: PyYAML\nVersion: 5.4\n"),
	}, bins: map[string]*GoBinary{}}
	sys := map[string]bool{"usr/lib/python3/dist-packages/yaml.dist-info/METADATA": true}
	r := Analyze(src, sys)
	var got []string
	for _, p := range r.Packages {
		got = append(got, p.Ecosystem+":"+p.Name+"@"+p.Version)
	}
	want := []string{
		"Packagist:guzzlehttp/guzzle@7.4.0", "Packagist:phpunit/phpunit@9.5.0",
		"PyPI:PyYAML@6.0", "PyPI:oldpkg@0.1", "PyPI:proto@1.0", "PyPI:requests@2.25.0", "PyPI:zegg@1.0",
		"RubyGems:rake@13.0.6", "RubyGems:thor@1.2.2",
		"npm:@babel/core@7.0.0", "npm:lodash@4.17.20", "npm:trail@2.0.0",
	}
	if names(got) != names(want) {
		t.Errorf("packages\n got %s\nwant %s", names(got), names(want))
	}
	wantSkip := map[string]int{"installed_by_os_package": 1, "node_package_json_unreadable": 2,
		"python_metadata_unreadable": 1, "gemspec_unreadable": 2, "composer_installed_json_unreadable": 1}
	if !reflect.DeepEqual(r.Skipped, wantSkip) {
		t.Errorf("skipped %v, want %v", r.Skipped, wantSkip)
	}
	for _, p := range r.Packages {
		if p.Source == "" {
			t.Errorf("%s has no source", p.Name)
		}
	}
}

func TestGoBinaryFromTestExecutable(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	if !GoExeCandidate(b[:16]) {
		t.Fatal("test executable not recognised as an executable format")
	}
	g := ReadGoBinary(b)
	if g == nil || g.Info.GoVersion != runtime.Version() {
		t.Fatalf("build info: %+v", g)
	}
	r := Analyze(memSource{bins: map[string]*GoBinary{"usr/bin/x": g, "usr/bin/sys": g}}, map[string]bool{"usr/bin/sys": true})
	if len(r.Packages) == 0 || r.Packages[0].Name != "stdlib" || r.Packages[0].Version != StdlibVersion(runtime.Version()) ||
		r.Packages[0].Ecosystem != "Go" || r.Packages[0].Source != "usr/bin/x" {
		t.Fatalf("%+v", r.Packages)
	}
	for _, p := range r.Packages {
		if p.Source == "usr/bin/sys" {
			t.Error("binary installed by an OS package must be skipped")
		}
	}
	if ReadGoBinary([]byte("\x7fELF not really an elf file at all")) != nil || ReadGoBinary(nil) != nil {
		t.Error("non-Go input must give nil")
	}
	if GoExeCandidate([]byte("#!/bin/sh\necho hi there")) || GoExeCandidate([]byte("\x7fELF")) {
		t.Error("script / short header is not a candidate")
	}
}

func TestGoBinaryPackages(t *testing.T) {
	exe, _ := os.Executable()
	b, _ := os.ReadFile(exe)
	g := ReadGoBinary(b)
	if g == nil {
		t.Skip("no build info")
	}
	cp := *g.Info
	cp.Deps = nil
	cp.GoVersion = "go1.22.3 X:boringcrypto"
	cp.Main.Path = "example.com/app"
	gb := &GoBinary{Info: &cp, MainVersion: ""}
	pk, unknown := goBinary(gb)
	if !unknown || len(pk) != 1 || pk[0] != [2]string{"stdlib", "v1.22.3"} {
		t.Errorf("%v %v", pk, unknown)
	}
	cp.Deps = []*debug.Module{
		{Path: "golang.org/x/net", Version: "v0.10.0"},
		{Path: "github.com/old/mod", Version: "v1.0.0", Replace: &debug.Module{Path: "github.com/fork/mod", Version: "v1.0.1"}},
		{Path: "local/dev", Version: "(devel)"},
		nil,
		{Path: "", Version: "v1.0.0"},
	}
	if pk, _ = goBinary(gb); len(pk) != 3 || pk[1] != [2]string{"golang.org/x/net", "v0.10.0"} ||
		pk[2] != [2]string{"github.com/fork/mod", "v1.0.1"} {
		t.Errorf("deps: %v", pk)
	}
	cp.Deps = nil
	gb.MainVersion = "v1.4.0"
	if pk, unknown = goBinary(gb); unknown || len(pk) != 2 || pk[1] != [2]string{"example.com/app", "v1.4.0"} {
		t.Errorf("%v %v", pk, unknown)
	}
	if StdlibVersion("go1.21.0-X:loopvar") != "v1.21.0" {
		t.Error("StdlibVersion -X: suffix")
	}
}
