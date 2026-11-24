package langpkg

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"github.com/cyberdetails/cdgate/internal/sbom"
	"sort"
	"strings"
	"testing"
)

func depJSON(t testing.TB, js string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	w.Write([]byte(js))
	w.Close()
	return buf.Bytes()
}

// elfWith builds a minimal little-endian ELF64 file with one named section.
func elfWith(name string, data []byte) []byte {
	shstr := append([]byte("\x00.shstrtab\x00"+name+"\x00"), 0)
	const ehsize, shentsize = 64, 64
	dataOff := ehsize
	strOff := dataOff + len(data)
	shOff := (strOff + len(shstr) + 7) &^ 7
	b := make([]byte, shOff+3*shentsize)
	copy(b, "\x7FELF\x02\x01\x01")
	le := binary.LittleEndian
	le.PutUint16(b[16:], 2)  // ET_EXEC
	le.PutUint16(b[18:], 62) // EM_X86_64
	le.PutUint32(b[20:], 1)
	le.PutUint64(b[40:], uint64(shOff))
	le.PutUint16(b[52:], ehsize)
	le.PutUint16(b[58:], shentsize)
	le.PutUint16(b[60:], 3) // shnum
	le.PutUint16(b[62:], 1) // shstrndx
	copy(b[dataOff:], data)
	copy(b[strOff:], shstr)
	sh := func(i int, nameOff, typ uint32, off, size int) {
		s := b[shOff+i*shentsize:]
		le.PutUint32(s[0:], nameOff)
		le.PutUint32(s[4:], typ)
		le.PutUint64(s[24:], uint64(off))
		le.PutUint64(s[32:], uint64(size))
		le.PutUint64(s[48:], 1)
	}
	sh(1, 1, 3, strOff, len(shstr))  // .shstrtab, SHT_STRTAB
	sh(2, 11, 1, dataOff, len(data)) // name, SHT_PROGBITS
	return b
}

// peWith builds a minimal PE file with one named section.
func peWith(name string, data []byte) []byte {
	const peOff = 0x40
	coff := peOff + 4
	sec := coff + 20
	dataOff := sec + 40
	b := make([]byte, dataOff+len(data))
	copy(b, "MZ")
	le := binary.LittleEndian
	le.PutUint32(b[0x3c:], peOff)
	copy(b[peOff:], "PE\x00\x00")
	le.PutUint16(b[coff:], 0x8664)
	le.PutUint16(b[coff+2:], 1) // one section, no optional header
	n := make([]byte, 8)
	copy(n, name)
	copy(b[sec:], n)
	le.PutUint32(b[sec+8:], uint32(len(data)))  // VirtualSize
	le.PutUint32(b[sec+16:], uint32(len(data))) // SizeOfRawData
	le.PutUint32(b[sec+20:], uint32(dataOff))   // PointerToRawData
	copy(b[dataOff:], data)
	return b
}

// machoWith builds a minimal 64-bit little-endian Mach-O with one section.
func machoWith(name string, data []byte) []byte {
	const hdr, seg, sect = 32, 72, 80
	dataOff := hdr + seg + sect
	b := make([]byte, dataOff+len(data))
	le := binary.LittleEndian
	le.PutUint32(b[0:], 0xfeedfacf)
	le.PutUint32(b[4:], 0x01000007) // x86_64
	le.PutUint32(b[12:], 2)         // MH_EXECUTE
	le.PutUint32(b[16:], 1)
	le.PutUint32(b[20:], seg+sect)
	c := b[hdr:]
	le.PutUint32(c[0:], 0x19) // LC_SEGMENT_64
	le.PutUint32(c[4:], seg+sect)
	copy(c[8:], "__DATA")
	le.PutUint64(c[32:], uint64(len(data)))
	le.PutUint64(c[40:], uint64(dataOff))
	le.PutUint64(c[48:], uint64(len(data)))
	le.PutUint32(c[64:], 1) // nsects
	s := b[hdr+seg:]
	copy(s[0:16], name)
	copy(s[16:32], "__DATA")
	le.PutUint64(s[40:], uint64(len(data)))
	le.PutUint32(s[48:], uint32(dataOff))
	copy(b[dataOff:], data)
	return b
}

func wasmWith(name string, data []byte) []byte {
	b := append([]byte{}, wasmHeader...)
	b = append(b, 1, 2, 0x60, 0) // a type section first (skipped)
	body := append(binary.AppendUvarint(nil, uint64(len(name))), name...)
	body = append(body, data...)
	b = append(b, 0)
	b = binary.AppendUvarint(b, uint64(len(body)))
	return append(b, body...)
}

const depFixture = `{"packages":[{"name":"app","version":"0.1.0","source":"local","root":true},` +
	`{"name":"cc","version":"1.0.83","source":"crates.io","kind":"build"},` +
	`{"name":"serde","version":"1.0.193","source":"crates.io","kind":"runtime"},` +
	`{"name":"libc","version":"0.2.150","source":"crates.io"},` +
	`{"name":"devonly","version":"1.0.0","source":"crates.io","kind":"dev"}]}` // not runtime: dropped

func TestReadRustBinary(t *testing.T) {
	want := "app@0.1.0,serde@1.0.193,libc@0.2.150"
	dep := depJSON(t, depFixture)
	for fmt, b := range map[string][]byte{
		"elf": elfWith(".dep-v0", dep), "elf-legacy": elfWith(".rust-deps-v0", dep),
		"pe": peWith(".dep-v0", dep), "pe-legacy": peWith("rdep-v0", dep),
		"macho": machoWith(".dep-v0", dep), "macho-legacy": machoWith("rust-deps-v0", dep),
		"wasm": wasmWith(".dep-v0", dep),
	} {
		if !RustExeCandidate(b) {
			t.Errorf("%s: not a candidate", fmt)
		}
		rb := ReadRustBinary(b)
		if rb == nil || rb.Err != "" {
			t.Errorf("%s: %+v", fmt, rb)
			continue
		}
		var got []string
		for _, p := range rb.Packages {
			got = append(got, p[0]+"@"+p[1])
		}
		if s := join(got); s != want {
			t.Errorf("%s: %s", fmt, s)
		}
	}
	// not Rust: nothing; Rust section that does not read: an error
	for fmt, b := range map[string][]byte{
		"elf-other":          elfWith(".data", dep),
		"wasm-other":         wasmWith("name", dep),
		"pe-legacy-elf-name": peWith(".rust-deps-v0"[:8], dep),
		"wasm-legacy":        wasmWith("rust-deps-v0", dep), // wasm has no legacy name
		"text":               []byte("#!/bin/sh\necho hello world\n"),
	} {
		if rb := ReadRustBinary(b); rb != nil {
			t.Errorf("%s: %+v", fmt, rb)
		}
	}
	for fmt, b := range map[string][]byte{
		"raw":  elfWith(".dep-v0", []byte(depFixture)),
		"json": elfWith(".dep-v0", depJSON(t, `{"packages":[1]}`)),
		"bomb": elfWith(".dep-v0", depJSON(t, `{"packages":[],"x":"`+string(bytes.Repeat([]byte("a"), maxRustDepJSON))+`"}`)),
	} {
		if rb := ReadRustBinary(b); rb == nil || rb.Err == "" {
			t.Errorf("%s: want an error, got %+v", fmt, rb)
		}
	}
	if RustExeCandidate([]byte("short")) || RustExeCandidate([]byte("#!/bin/sh\necho hello\n")) {
		t.Error("candidate rules")
	}
}

// go-rustaudit reads every wasm length from a 4-byte window and treats a
// zero-byte read at the end of the file as an error.
func TestWasmBounds(t *testing.T) {
	dep := depJSON(t, depFixture)
	ok := wasmWith(".dep-v0", dep)
	for name, b := range map[string][]byte{
		"truncated":     ok[:len(ok)-1],
		"name past end": append(append([]byte{}, wasmHeader...), 0, 5, 0x7f, 0, 0, 0),
		"5-byte length": append(append([]byte{}, wasmHeader...), 1, 0x80, 0x80, 0x80, 0x80, 0x01, 0, 0, 0),
		"no room":       append(append([]byte{}, wasmHeader...), 0, 1, 1),
	} {
		if _, err := wasmDepSection(b); err != errUnknownExe {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := wasmDepSection(append(append([]byte{}, wasmHeader...), 1, 4, 0, 0, 0, 0)); err != errNotRust {
		t.Errorf("clean end: %v", err)
	}
}

func join(s []string) string {
	var b bytes.Buffer
	for i, x := range s {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(x)
	}
	return b.String()
}

func TestAnalyzeRust(t *testing.T) {
	lock := "version = 3\n\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\n\n" +
		"[[package]]\nname = \"regex\"\nversion = \"1.10.2\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n"
	src := memSource{
		files: map[string][]byte{"srv/Cargo.lock": []byte(lock), "srv/bad/Cargo.lock": []byte("[[package]]\nname = \"x\"\n" + string(bytes.Repeat([]byte("a"), 5<<20)))},
		rust: map[string]*RustBinary{
			"usr/bin/rg":     {Packages: [][2]string{{"ripgrep", "14.1.0"}, {"memchr", "2.7.1"}}},
			"usr/bin/broken": {Err: "failed to unmarshal JSON"},
			"usr/bin/osrg":   {Packages: [][2]string{{"x", "1"}}},
		},
	}
	r := Analyze(src, map[string]bool{"usr/bin/osrg": true})
	got := map[string]string{}
	for _, p := range r.Packages {
		got[p.Name] = p.Ecosystem + " " + p.Version + " " + p.Source
	}
	want := map[string]string{
		"ripgrep": "crates.io 14.1.0 usr/bin/rg", "memchr": "crates.io 2.7.1 usr/bin/rg",
		"regex": "crates.io 1.10.2 srv/Cargo.lock",
	}
	if len(got) != len(want) {
		t.Errorf("%v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: %q want %q", k, got[k], v)
		}
	}
	if r.Skipped["rust_binary_unreadable"] != 1 || r.Skipped["installed_by_os_package"] != 1 || r.Skipped["Cargo.lock_unreadable"] != 1 {
		t.Errorf("skipped %v", r.Skipped)
	}
	if Classify("a/Cargo.lock", 0)&ImageLock == 0 || Classify("a/Cargo.toml", 0)&ImageLock != 0 {
		t.Error("classify")
	}
}

func TestRustBinaryEdges(t *testing.T) {
	// decompressed JSON one byte over the cap, valid only if truncated there
	js := `{"packages":[]}`
	pad := string(bytes.Repeat([]byte(" "), maxRustDepJSON+1-len(js)))
	if rb := ReadRustBinary(elfWith(".dep-v0", depJSON(t, pad+js+"   "))); rb == nil || rb.Err == "" {
		t.Errorf("over the cap: %+v", rb)
	}
	// a non-custom section of any id is skipped before the dependency section
	dep := depJSON(t, depFixture)
	w := wasmWith(".dep-v0", dep)
	w = append(append(append([]byte{}, wasmHeader...), 3, 4, 0xff, 0xff, 0xff, 0x7f), w[len(wasmHeader):]...) // read as a name length it would not fit
	if rb := ReadRustBinary(w); rb == nil || len(rb.Packages) != 3 {
		t.Errorf("section id 3: %+v", rb)
	}
	hdr := func(b ...byte) []byte { return append(append([]byte{}, wasmHeader...), b...) }
	for name, b := range map[string][]byte{
		// .dep-v0 with no data at the very end: go-rustaudit's zero-byte ReadAt at EOF fails
		"empty data at end": append(hdr(0, 8, 7), ".dep-v0"...),
		// fewer than 4 bytes left for a length
		"short length window": hdr(1, 1, 0),
	} {
		if _, err := wasmDepSection(b); err != errUnknownExe {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// FuzzBinaryArchives: Java archives and cargo-auditable executables are
// untrusted binary input; neither reader may panic.
func FuzzBinaryArchives(f *testing.F) {
	dep := depJSON(f, depFixture)
	for _, b := range [][]byte{elfWith(".dep-v0", dep), peWith(".dep-v0", dep), machoWith(".dep-v0", dep), wasmWith(".dep-v0", dep)} {
		f.Add(b)
	}
	f.Add(mkzipF(f))
	f.Fuzz(func(t *testing.T, b []byte) {
		_ = RustExeCandidate(b)
		_ = ReadRustBinary(b)
		_, _ = wasmDepSection(b)
		_ = ReadJar(b, "lib/a-1.0.jar")
		_, _ = parseManifestMainSection(bytes.NewReader(b))
	})
}

// The dependency files Trivy still reads in image mode; lock files of the
// other ecosystems stay off, as in Trivy.
func TestImageLockFiles(t *testing.T) {
	for p, want := range map[string]bool{
		"a/Cargo.lock": true, "a/packages.lock.json": true, "a/packages.config": true,
		"app/pwsh.deps.json": true, "src/Directory.Packages.props": true, "x/PACKAGES.PROPS": true,
		"a/package-lock.json": false, "a/yarn.lock": false, "a/Gemfile.lock": false, "a/go.mod": false,
		"a/composer.lock": false, "a/poetry.lock": false, "a/Directory.Build.props": false,
	} {
		if got := Classify(p, 0)&ImageLock != 0; got != want {
			t.Errorf("%s: %v", p, got)
		}
	}
	r := Analyze(memSource{files: map[string][]byte{
		"srv/app.deps.json": []byte(`{"libraries":{"app/1.0.0":{"type":"project"},"Dapper/2.1.0":{"type":"package"}}}`),
		"srv/Cargo.lock":    []byte("[[package]]\nname = \"own\"\nversion = \"0.1.0\"\n"),
	}}, nil)
	if r.LocalNotSent != 2 || len(r.Packages) != 1 || r.Packages[0].Ecosystem != "NuGet" {
		t.Errorf("%d %+v", r.LocalNotSent, r.Packages)
	}
}

// Julia manifests read their Project.toml from the kept files; conda
// environment records are listed unchecked (Trivy matches none).
func TestJuliaAndConda(t *testing.T) {
	for p, want := range map[string]Kind{
		"app/Manifest.toml": ImageLock,
		"app/Project.toml":  Sibling,
		"opt/conda/envs/py/conda-meta/openssl-3.1.4-h0.json": CondaMeta,
		"opt/conda/conda-meta/zlib-1.2.13-h0.json":           0, // base installation: Trivy's regex needs envs/
		"opt/conda/envs/py/conda-meta/onedash-1.json":        0,
		"opt/conda/envs/py/conda-meta/history":               0,
	} {
		if got := Classify(p, 0) & (ImageLock | Sibling | CondaMeta); got != want {
			t.Errorf("%s: %v want %v", p, got, want)
		}
	}
	man := "julia_version = \"1.10.4\"\nmanifest_format = \"2.0\"\n[[deps.A]]\nuuid = \"a\"\nversion = \"1.0.0\"\n[[deps.B]]\nuuid = \"b\"\nversion = \"2.0.0\"\n"
	c := "opt/conda/envs/py/conda-meta/"
	r := Analyze(memSource{files: map[string][]byte{
		"app/Manifest.toml":         []byte(man),
		"app/Project.toml":          []byte("[deps]\nA = \"a\"\n"),
		"other/Manifest.toml":       []byte(man), // no Project.toml: everything
		c + "openssl-3.1.4-h0.json": []byte(`{"name":"openssl","version":"3.1.4"}`),
		c + "trail-1.0-0.json":      []byte(`{"name":"trail","version":"1.0"} garbage`),
		c + "nover-1-0.json":        []byte(`{"name":"nover"}`),
	}}, nil)
	got := map[string]int{}
	for _, p := range r.Packages {
		got[p.Ecosystem+" "+p.Name+"@"+p.Version+" "+p.Source]++
	}
	want := map[string]int{"Julia A@1.0.0 app/Manifest.toml": 1, "Julia A@1.0.0 other/Manifest.toml": 1, "Julia B@2.0.0 other/Manifest.toml": 1}
	if len(got) != len(want) {
		t.Errorf("%v", got)
	}
	for k := range want {
		if got[k] != 1 {
			t.Errorf("missing %s in %v", k, got)
		}
	}
	var conda []string
	for _, u := range r.Unchecked {
		if u.Ecosystem == "conda" && u.UncheckedReason == CondaUnchecked {
			conda = append(conda, u.Name+"@"+u.Version)
		}
	}
	sort.Strings(conda)
	if strings.Join(conda, ",") != "openssl@3.1.4,trail@1.0" || r.Skipped["conda_meta_unreadable"] != 1 {
		t.Errorf("conda %v %v", conda, r.Skipped)
	}
}

// SBOM documents in an image (Trivy's sbom analyzer): read with internal/sbom;
// a format Trivy reads but this scanner does not is listed unchecked.
func TestSBOMFilesInImage(t *testing.T) {
	for p, want := range map[string]bool{
		"opt/bitnami/nginx/.spdx-nginx.spdx": true, "a/b.spdx.json": true, "a/b.cdx": true, "a/b.cdx.json": true,
		"a/b.SPDX": false, "a/b.json": false, "x/y.dist-info/sboms/z.cdx.json": false,
	} {
		if got := Classify(p, 0)&SBOMFile != 0; got != want {
			t.Errorf("%s: %v", p, got)
		}
	}
	cdx := `{"bomFormat":"CycloneDX","metadata":{"component":{"type":"application","name":"me","purl":"pkg:npm/me@1.0.0"}},` +
		`"components":[{"type":"library","name":"lodash","purl":"pkg:npm/lodash@4.17.20"},` +
		`{"type":"library","name":"redis","purl":"pkg:bitnami/redis@7.2.0"},{"type":"library","name":"g","purl":"pkg:generic/g@1"}]}`
	r := Analyze(memSource{files: map[string][]byte{
		"opt/app/bom.cdx.json":     []byte(cdx),
		"opt/app/bom.cdx":          []byte(`<bom xmlns="http://cyclonedx.org/schema/bom/1.5"/>`),
		"opt/app/broken.spdx.json": []byte(`{"SPDXID":"SPDXRef-DOCUMENT","spdxVersion":"SPDX-9"}`),
		"usr/share/os.cdx.json":    []byte(cdx),
	}}, map[string]bool{"usr/share/os.cdx.json": true})
	got := map[string]bool{}
	for _, k := range r.Packages {
		got[k.Ecosystem+" "+k.Name+" "+k.Version+" "+k.Source] = true
	}
	if len(got) != 2 || !got["npm lodash 4.17.20 opt/app/bom.cdx.json"] || !got["Bitnami redis 7.2.0 opt/app/bom.cdx.json"] {
		t.Errorf("packages %+v", r.Packages)
	}
	why := map[string]string{}
	for _, u := range r.Unchecked {
		why[u.Ecosystem+" "+u.Source] = u.UncheckedReason
	}
	if why["sbom opt/app/bom.cdx"] != sbom.ReasonFormat || len(why) != 1 {
		t.Errorf("unchecked %v", why)
	}
	osdoc := `{"bomFormat":"CycloneDX","components":[{"type":"library","name":"bash","purl":"pkg:deb/debian/bash@5.2"}]}`
	if r2 := Analyze(memSource{files: map[string][]byte{"x/os.cdx.json": []byte(osdoc)}}, nil); len(r2.SBOMOS) != 1 || r2.SBOMOS[0].Name != "bash" {
		t.Errorf("SBOM OS packages: %+v", r2.SBOMOS)
	}
	if r.LocalNotSent != 1 || r.Skipped["sbom_component_skipped"] != 1 || r.Skipped["sbom_unreadable"] != 1 || r.Skipped["installed_by_os_package"] != 1 {
		t.Errorf("%d %v", r.LocalNotSent, r.Skipped)
	}
}
