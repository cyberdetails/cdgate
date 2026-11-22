package sbom

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

var trivyEco = map[string]string{"npm": "npm", "pypi": "PyPI", "maven": "Maven", "golang": "Go", "gem": "RubyGems",
	"cargo": "crates.io", "nuget": "NuGet", "composer": "Packagist", "hex": "Hex", "pub": "Pub", "julia": "Julia",
	"conda": "conda", "bitnami": "Bitnami", "cocoapods": "CocoaPods", "swift": "Swift", "conan": "Conan", "k8s": "Kubernetes"}

// testdata/trivy_expected.tsv is the output of Trivy 00b7394's own pkg/sbom
// decoder on the same files (lab tool cdsbomoracle). Roots are compared as
// packages here (Trivy matches them; cdgate only does not send them), and
// Trivy's packages without a version are left out (they match nothing).
func TestAgainstTrivy(t *testing.T) {
	want := map[string][]string{}
	errs := map[string]bool{}
	f, err := os.Open("testdata/trivy_expected.tsv")
	if err != nil {
		t.Fatal(err)
	}
	s := bufio.NewScanner(f)
	for s.Scan() {
		x := strings.Split(s.Text(), "\t")
		if x[1] == "ERR" {
			errs[x[0]] = true
			continue
		}
		if x[4] == "" {
			continue
		}
		eco := x[2]
		if x[1] == "lang" {
			eco = trivyEco[eco]
		}
		want[x[0]] = append(want[x[0]], x[1]+" "+eco+" "+x[3]+" "+x[4])
	}
	f.Close()
	files, _ := filepath.Glob("testdata/edge_*")
	files = append(files, "testdata/bitnami_component.spdx")
	for _, p := range files {
		name := filepath.Base(p)
		b, _ := os.ReadFile(p)
		got, err := decodeAll(b)
		switch {
		case name == "edge_cdx.xml":
			if !errors.Is(err, ErrNotRead) {
				t.Errorf("%s: %v", name, err) // Trivy does not read CycloneDX XML either
			}
		case errs[name]:
			if err == nil {
				t.Errorf("%s: Trivy fails, decoded %v", name, got)
			}
		case err != nil:
			t.Errorf("%s: %v", name, err)
		default:
			w := want[name]
			sort.Strings(w)
			if strings.Join(got, "|") != strings.Join(w, "|") {
				t.Errorf("%s:\n got  %v\n want %v", name, got, w)
			}
		}
	}
}

// decodeAll: every package with roots included, as "class ecosystem name version".
func decodeAll(b []byte) ([]string, error) {
	var d *bom
	var err error
	switch f := Detect(b); f {
	case CycloneDXJSON:
		d, err = decodeCycloneDX(b)
	case SPDXJSON:
		d, err = decodeSPDX(b)
	case SPDXTagValue:
		d, err = decodeSPDXTagValue(b)
	case CycloneDXXML:
		return nil, ErrNotRead
	default:
		return nil, errors.New("unknown")
	}
	if err != nil {
		return nil, err
	}
	for _, c := range d.comps {
		c.root = false
	}
	r, err := d.packages()
	if err != nil {
		return nil, err
	}
	var out []string
	for _, k := range append(r.Packages, r.Unchecked...) {
		out = append(out, "lang "+k.Ecosystem+" "+k.Name+" "+k.Version)
	}
	for _, o := range r.OSPackages {
		v := o.Version // Trivy's oracle prints the purl version (RPM release joined)
		if o.Release != "" {
			v += "-" + o.Release
		}
		out = append(out, "os "+o.Type+" "+o.Name+" "+v)
	}
	sort.Strings(out)
	return out, nil
}

func TestDecodeRootsAndReasons(t *testing.T) {
	b, _ := os.ReadFile("testdata/edge_cdx_mix.json")
	r, err := Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	var sent []string
	for _, p := range r.Packages {
		sent = append(sent, p.Ecosystem+":"+p.Name+"@"+p.Version)
	}
	sort.Strings(sent)
	// the root (pkg:npm/myapp) is counted, never sent
	if r.LocalNotSent != 1 || strings.Contains(strings.Join(sent, ","), "myapp") || r.Format != CycloneDXJSON {
		t.Errorf("%d %v", r.LocalNotSent, sent)
	}
	why := map[string]string{}
	for _, u := range r.Unchecked {
		why[u.Ecosystem] = u.UncheckedReason
	}
	if why["conda"] != ReasonConda || why["CocoaPods"] != "" || len(why) != 2 ||
		len(r.OSPackages) != 1 || r.OSPackages[0].Name != "bash" || r.OSPackages[0].Version != "5.2-1" {
		t.Errorf("%v", why)
	}
	if r.Skipped != 3 { // no purl, pkg:generic, no version
		t.Errorf("skipped %d", r.Skipped)
	}
	// a Bitnami root is the published component itself: kept
	b, _ = os.ReadFile("testdata/bitnami_component.spdx")
	if r, err = Decode(b); err != nil || r.LocalNotSent != 0 || len(r.Packages) != 6 || r.Packages[0].Ecosystem != "Bitnami" {
		t.Errorf("bitnami: %v %+v", err, r)
	}
}

func TestDetect(t *testing.T) {
	for in, want := range map[string]string{
		`{"bomFormat":"CycloneDX"}`:                          CycloneDXJSON,
		`{"SPDXID":"SPDXRef-DOCUMENT"}`:                      SPDXJSON,
		`<bom xmlns="http://cyclonedx.org/schema/bom/1.5"/>`: CycloneDXXML,
		"SPDXVersion: SPDX-2.3\nx":                           SPDXTagValue,
		`{"bomFormat":"cyclonedx"}`:                          "",
		`{"SPDXID":"SPDXRef-X"}`:                             "",
		`not an sbom`:                                        "",
	} {
		if got := Detect([]byte(in)); got != want {
			t.Errorf("%q: %q want %q", in, got, want)
		}
	}
}

// Rules of packageurl-go v0.1.7 FromString.
func TestParsePURL(t *testing.T) {
	ok := map[string]PURL{
		"pkg:npm/%40babel/core@7.0.0":                                           {Type: "npm", Namespace: "@babel", Name: "core", Version: "7.0.0"},
		"PKG:PyPI/Flask_X@2.0.0":                                                {Type: "pypi", Name: "flask-x", Version: "2.0.0"},
		"pkg://golang/GitHub.com/Foo/Bar@v1.2.3":                                {Type: "golang", Namespace: "github.com/foo", Name: "bar", Version: "v1.2.3"},
		"pkg:maven/org.springframework/spring-core@5.3.27?type=jar&classifier=": {Type: "maven", Namespace: "org.springframework", Name: "spring-core", Version: "5.3.27"},
		"pkg:bitnami/Redis@7.2.0?arch=amd64":                                    {Type: "bitnami", Name: "redis", Version: "7.2.0"},
		"pkg:cocoapods/GoogleUtilities@7.5.2#NSData%2Bzlib/":                    {Type: "cocoapods", Name: "GoogleUtilities", Version: "7.5.2", Subpath: "NSData+zlib"},
		"pkg:julia/Foo@1.0.0?uuid=x":                                            {Type: "julia", Name: "Foo", Version: "1.0.0"},
		"pkg:huggingface/a/B@ABC":                                               {Type: "huggingface", Namespace: "a", Name: "B", Version: "abc"},
	}
	for in, want := range ok {
		got, err := ParsePURL(in)
		if err != nil {
			t.Errorf("%s: %v", in, err)
			continue
		}
		if got.Type != want.Type || got.Namespace != want.Namespace || got.Name != want.Name ||
			got.Version != want.Version || got.Subpath != want.Subpath {
			t.Errorf("%s: %+v", in, got)
		}
	}
	for _, in := range []string{
		"npm/x@1", "pkg:npm", "pkg:npm/@scope", "pkg:pypi/@x", "pkg:npm/x?a=1&a=2", "pkg:npm/x?a;b=1",
		"pkg:npm/x?1a=1", "pkg:1npm/x", "pkg:julia/Foo@1.0.0", "pkg:julia/ns/Foo?uuid=1", "pkg:swift/x@1",
		"pkg:npm/x#a/../b", "pkg:npm/%zz", "pkg:chrome-extension/abc", "pkg:cpan/lower/x", "pkg:otp/ns/x",
	} {
		if _, err := ParsePURL(in); err == nil {
			t.Errorf("%s accepted", in)
		}
	}
	// an empty qualifier value is the key omitted (and not a duplicate)
	if p, err := ParsePURL("pkg:npm/x?a=&a=1"); err != nil || p.Qualifiers["a"] != "1" {
		t.Errorf("empty qualifier: %+v %v", p, err)
	}
}

// FuzzDecode: SBOMs are untrusted input.
func FuzzDecode(f *testing.F) {
	for _, p := range []string{"testdata/edge_cdx_mix.json", "testdata/edge_spdx_mix.json", "testdata/bitnami_component.spdx",
		"testdata/tv/ok_text.spdx", "testdata/tv/fileok.spdx"} {
		b, _ := os.ReadFile(p)
		f.Add(b)
	}
	f.Add([]byte("pkg:npm/%40a/b@1?x=y#z"))
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = Decode(b)
		_, _ = ParsePURL(string(b))
	})
}

func spdxTestDoc(ver string, pkgs, rels string) []byte {
	return []byte(`{"SPDXID":"SPDXRef-DOCUMENT","spdxVersion":"` + ver + `","packages":[` + pkgs + `],"relationships":[` + rels + `]}`)
}

func names(t *testing.T, b []byte) string {
	t.Helper()
	r, err := Decode(b)
	if err != nil {
		t.Fatalf("%s: %v", b, err)
	}
	var out []string
	for _, k := range append(r.Packages, r.Unchecked...) {
		out = append(out, k.Name+"@"+k.Version)
	}
	for _, o := range r.OSPackages {
		out = append(out, o.Name+"@"+o.Version)
	}
	sort.Strings(out)
	return strings.Join(out, ",") + fmt.Sprintf(" root=%d skip=%d", r.LocalNotSent, r.Skipped)
}

// Rules checked against Trivy 00b7394 / tools-golang v0.5.7 / cyclonedx-go.
func TestTrivyRules(t *testing.T) {
	pm := func(id, name, cat, purl string) string {
		return `{"SPDXID":"SPDXRef-` + id + `","name":"` + name + `","externalRefs":[{"referenceCategory":"` + cat +
			`","referenceType":"purl","referenceLocator":"` + purl + `"}]}`
	}
	cases := map[string]struct {
		in   []byte
		want string
	}{
		// 2.1 is read; only 2.2/2.3 readers turn PACKAGE_MANAGER into PACKAGE-MANAGER
		"2.1 underscore": {spdxTestDoc("SPDX-2.1", pm("a", "a", "PACKAGE_MANAGER", "pkg:npm/a@1"), ""), " root=0 skip=1"},
		"2.2 underscore": {spdxTestDoc("SPDX-2.2", pm("a", "a", "PACKAGE_MANAGER", "pkg:npm/a@1"), ""), "a@1 root=0 skip=0"},
		"2.1 dash":       {spdxTestDoc("SPDX-2.1", pm("a", "a", "PACKAGE-MANAGER", "pkg:npm/a@1"), ""), "a@1 root=0 skip=0"},
		// a purl under another category is not the package's purl
		"security purl": {spdxTestDoc("SPDX-2.3", pm("a", "a", "SECURITY", "pkg:npm/a@1"), ""), " root=0 skip=1"},
		// OperatingSystem SPDXIDs are the OS, not packages
		"os element": {spdxTestDoc("SPDX-2.3", pm("OperatingSystem-x", "debian", "PACKAGE-MANAGER", "pkg:npm/os@1"), ""), " root=0 skip=0"},
		// only DOCUMENT DESCRIBES x names the root
		"describes not from document": {spdxTestDoc("SPDX-2.3", pm("a", "a", "PACKAGE-MANAGER", "pkg:npm/a@1")+","+pm("b", "b", "PACKAGE-MANAGER", "pkg:npm/b@1"),
			`{"spdxElementId":"SPDXRef-a","relationshipType":"DESCRIBES","relatedSpdxElement":"SPDXRef-b"}`), "a@1,b@1 root=0 skip=0"},
		// CycloneDX: an empty Type keeps the application a package; a Trivy-namespaced Type makes it a container
		"empty Type": {[]byte(`{"bomFormat":"CycloneDX","components":[{"type":"application","name":"x","purl":"pkg:npm/x@1","properties":[{"name":"Type","value":""}]}]}`), "x@1 root=0 skip=0"},
		"trivy Type": {[]byte(`{"bomFormat":"CycloneDX","components":[{"type":"application","name":"x","purl":"pkg:npm/x@1","properties":[{"name":"aquasecurity:trivy:Type","value":"npm"}]}]}`), " root=0 skip=0"},
		// a platform without purl is neither a package nor a skipped package
		"platform": {[]byte(`{"bomFormat":"CycloneDX","components":[{"type":"platform","name":"p"},{"type":"library","name":"l"}]}`), " root=0 skip=1"},
		// the first OS component (document order) owns the OS packages. Trivy walks a
		// map and picks one at random: in the lab run it took the second and failed
		// with "multiple types of OS packages"; with the first it would not.
		"first OS": {[]byte(`{"bomFormat":"CycloneDX","components":[{"type":"operating-system","bom-ref":"os1","name":"debian"},` +
			`{"type":"operating-system","bom-ref":"os2","name":"alpine"},{"type":"library","bom-ref":"d","name":"bash","purl":"pkg:deb/debian/bash@5"},` +
			`{"type":"library","bom-ref":"a","name":"musl","purl":"pkg:apk/alpine/musl@1"}],"dependencies":[{"ref":"os1","dependsOn":["d"]}]}`), "bash@5,musl@1 root=0 skip=0"},
	}
	for name, c := range cases {
		if got := names(t, c.in); got != c.want {
			t.Errorf("%s: %q want %q", name, got, c.want)
		}
	}
	for name, b := range map[string][]byte{
		"empty element id": spdxTestDoc("SPDX-2.3", pm("", "a", "PACKAGE-MANAGER", "pkg:npm/a@1"), ""),
		"empty doc ref":    spdxTestDoc("SPDX-2.3", "", `{"spdxElementId":"DocumentRef-:SPDXRef-a","relationshipType":"CONTAINS","relatedSpdxElement":"SPDXRef-b"}`),
	} {
		if _, err := Decode(b); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// purl edge cases: a scoped npm name without version; "." in a subpath
	if p, err := ParsePURL("pkg:npm/@scope/name"); err != nil || p.Namespace != "@scope" || p.Name != "name" || p.Version != "" {
		t.Errorf("scoped without version: %+v %v", p, err)
	}
	if _, err := ParsePURL("pkg:npm/x#a/./b"); err == nil {
		t.Error("subpath with . accepted")
	}
}

// testdata/tv: tag-value edge cases; trivy_expected.tsv is Trivy's own decoder
// on them (lab cdsbomoracle): the same packages, or a failure where it fails.
func TestTagValueAgainstTrivy(t *testing.T) {
	want := map[string][]string{}
	fails := map[string]bool{}
	f, _ := os.Open("testdata/tv/trivy_expected.tsv")
	s := bufio.NewScanner(f)
	for s.Scan() {
		x := strings.Split(s.Text(), "\t")
		if x[1] == "ERR" {
			fails[x[0]] = true
			continue
		}
		eco := x[2]
		if x[1] == "lang" {
			eco = trivyEco[eco]
		}
		want[x[0]] = append(want[x[0]], x[1]+" "+eco+" "+x[3]+" "+x[4])
	}
	f.Close()
	files, _ := filepath.Glob("testdata/tv/*.spdx")
	if len(files) != 21 {
		t.Fatalf("%d files", len(files))
	}
	for _, p := range files {
		name := filepath.Base(p)
		b, _ := os.ReadFile(p)
		got, err := decodeAll(b)
		switch {
		case fails[name]:
			if err == nil {
				t.Errorf("%s: Trivy fails, decoded %v", name, got)
			}
		case err != nil:
			t.Errorf("%s: %v", name, err)
		default:
			w := want[name]
			sort.Strings(w)
			if strings.Join(got, "|") != strings.Join(w, "|") {
				t.Errorf("%s:\n got  %v\n want %v", name, got, w)
			}
		}
	}
	// the SPDX source information is read from tag-value too
	b, _ := os.ReadFile("testdata/tv/ok_text.spdx")
	r, err := Decode(b)
	if err != nil || r.Format != SPDXTagValue || r.OS == nil || r.OS.Name != "12.5" || len(r.OSPackages) != 1 ||
		r.OSPackages[0].InfoSrcName != "glibc" || r.OSPackages[0].InfoSrcVersion != "2.36-9" {
		t.Errorf("%v %+v", err, r)
	}
}
