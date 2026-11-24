package main

import (
	"bytes"
	"github.com/cyberdetails/cdgate/internal/ospkg"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSBOMResult(t *testing.T) {
	dir := t.TempDir()
	cdx := filepath.Join(dir, "app.cdx.json")
	os.WriteFile(cdx, []byte(`{"bomFormat":"CycloneDX","components":[{"type":"library","name":"lodash","purl":"pkg:npm/lodash@4.17.20"},`+
		`{"type":"library","name":"bash","purl":"pkg:deb/debian/bash@5.2"},{"type":"library","name":"nover","purl":"pkg:npm/nover"}]}`), 0o644)
	res, err := sbomResult(cdx)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Packages) != 1 || res.Packages[0].Source != "app.cdx.json" || len(res.Unchecked) != 1 || !res.SBOM ||
		len(res.Files) != 1 || res.Files[0].Kind != "cyclonedx-json" || len(res.Unsupported) != 1 {
		t.Errorf("%+v", res)
	}
	xml := filepath.Join(dir, "a.cdx")
	os.WriteFile(xml, []byte(`<bom xmlns="http://cyclonedx.org/schema/bom/1.5"/>`), 0o644)
	if _, err := sbomResult(xml); err == nil || !strings.Contains(err.Error(), "cyclonedx-xml") {
		t.Errorf("CycloneDX XML: %v", err) // Trivy does not read it either
	}
	tv := filepath.Join(dir, "a.spdx")
	os.WriteFile(tv, []byte("SPDXVersion: SPDX-2.3\nSPDXID: SPDXRef-DOCUMENT\nCreator: Tool: x\n"+
		"PackageName: lodash\nSPDXID: SPDXRef-a\nExternalRef: PACKAGE-MANAGER purl pkg:npm/lodash@4.17.20\n"), 0o644)
	if r, err := sbomResult(tv); err != nil || len(r.Packages) != 1 || r.Files[0].Kind != "spdx-tag-value" {
		t.Errorf("tag-value: %v %+v", err, r)
	}
	link := filepath.Join(dir, "link.json")
	os.Symlink(cdx, link)
	if _, err := sbomResult(link); err == nil {
		t.Error("symbolic link read")
	}
	if _, err := sbomResult(dir); err == nil {
		t.Error("directory read")
	}
	big := filepath.Join(dir, "big.json")
	f, _ := os.Create(big)
	f.Truncate(MaxSBOMBytes + 1)
	f.Close()
	if _, err := sbomResult(big); err == nil || !strings.Contains(err.Error(), "larger") {
		t.Errorf("size cap: %v", err)
	}
	// the command: header says sbom, an unreadable file is exit 2
	var out, errb bytes.Buffer
	if code := run([]string{"sbom", xml, "--api", "http://127.0.0.1:1"}, &out, &errb); code != 2 {
		t.Errorf("exit %d", code)
	}
}

// OS packages of an SBOM are queried with the SBOM's OS, like an image's.
func TestSBOMResultOS(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "img.cdx.json")
	os.WriteFile(f, []byte(`{"bomFormat":"CycloneDX","components":[`+
		`{"type":"operating-system","bom-ref":"os","name":"debian","version":"12.5"},`+
		`{"type":"library","bom-ref":"a","name":"libc6","purl":"pkg:deb/debian/libc6@2.36-9","properties":[`+
		`{"name":"aquasecurity:trivy:SrcName","value":"glibc"},{"name":"aquasecurity:trivy:SrcVersion","value":"2.36"},`+
		`{"name":"aquasecurity:trivy:SrcRelease","value":"9"}]},`+
		`{"type":"library","bom-ref":"b","name":"rpmpkg","purl":"pkg:rpm/redhat/rpmpkg@1-1.el9"}],`+
		`"dependencies":[{"ref":"os","dependsOn":["a","b"]}]}`), 0o644)
	res, err := sbomResult(f)
	if err != nil {
		t.Fatal(err)
	}
	if res.OS == nil || res.OS.Family != "debian" || len(res.Packages) != 1 || res.Packages[0].Ecosystem != "Debian:12" ||
		res.Packages[0].Name != "glibc" || res.Packages[0].Version != "2.36-9" || res.Packages[0].Source != "img.cdx.json" {
		t.Fatalf("%+v %+v", res.OS, res.Packages)
	}
	if len(res.Unchecked) != 1 || res.Unchecked[0].Name != "rpmpkg" || !strings.Contains(res.Unchecked[0].UncheckedReason, "another type") {
		t.Errorf("%+v", res.Unchecked)
	}
}

// A distribution without advisories here (Fedora) and a Seal RPM whose
// release names no Red Hat version are listed unchecked, as for an image.
func TestSBOMResultUncheckedOS(t *testing.T) {
	dir := t.TempDir()
	write := func(name, fam, ver, comps string) string {
		f := filepath.Join(dir, name)
		os.WriteFile(f, []byte(`{"bomFormat":"CycloneDX","components":[{"type":"operating-system","bom-ref":"os","name":"`+fam+
			`","version":"`+ver+`"},`+comps+`],"dependencies":[{"ref":"os","dependsOn":["a"]}]}`), 0o644)
		return f
	}
	res, err := sbomResult(write("f.json", "fedora", "40", `{"type":"library","bom-ref":"a","name":"bash","purl":"pkg:rpm/fedora/bash@5.2-1.fc40?arch=x86_64"}`))
	if err != nil || len(res.Packages) != 0 || len(res.Unchecked) != 1 || res.Unchecked[0].Name != "bash" {
		t.Errorf("fedora: %v %+v %+v", err, res.Packages, res.Unchecked)
	}
	res, err = sbomResult(write("s.json", "redhat", "9.2", `{"type":"library","bom-ref":"a","name":"seal-openssl","purl":"pkg:rpm/redhat/seal-openssl@3.0-1.sp1?arch=x86_64"}`))
	if err != nil || len(res.Unchecked) != 1 || res.Unchecked[0].UncheckedReason != ospkg.SealNoRelease {
		t.Errorf("seal: %v %+v %+v", err, res.Packages, res.Unchecked)
	}
}

func TestRootfsResult(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "etc"), 0o755)
	os.WriteFile(filepath.Join(root, "etc/os-release"), []byte("ID=alpine\nVERSION_ID=3.19.1\n"), 0o644)
	os.MkdirAll(filepath.Join(root, "lib/apk/db"), 0o755)
	os.WriteFile(filepath.Join(root, "lib/apk/db/installed"), []byte("P:musl\nV:1.2.4-r2\no:musl\n\n"), 0o644)
	os.MkdirAll(filepath.Join(root, "app/node_modules/x"), 0o755)
	os.WriteFile(filepath.Join(root, "app/node_modules/x/package.json"), []byte(`{"name":"x","version":"1.0.0"}`), 0o644)
	res, err := rootfsResult(root)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, p := range res.Packages {
		got[p.Ecosystem+" "+p.Name+"@"+p.Version] = true
	}
	if !res.RootFS || res.OS == nil || res.OS.Family != "alpine" || !got["Alpine:v3.19 musl@1.2.4-r2"] || !got["npm x@1.0.0"] || len(got) != 2 {
		t.Errorf("%+v %v", res.OS, got)
	}
	var out bytes.Buffer
	if code := run([]string{"rootfs", filepath.Join(root, "etc/os-release")}, &out, &out); code != 2 {
		t.Errorf("a file: exit %d", code)
	}
}

// Language packages installed by an OS package are the OS package's (Trivy's
// system-file filter), in a root filesystem as in an image.
func TestRootfsSystemFiles(t *testing.T) {
	root := t.TempDir()
	put := func(p, b string) {
		os.MkdirAll(filepath.Dir(filepath.Join(root, p)), 0o755)
		os.WriteFile(filepath.Join(root, p), []byte(b), 0o644)
	}
	put("etc/os-release", "ID=debian\nVERSION_ID=\"12\"\n")
	put("etc/debian_version", "12.5\n")
	put("var/lib/dpkg/status", "Package: python3-yaml\nStatus: install ok installed\nVersion: 6.0-3\nSource: pyyaml\nArchitecture: amd64\n\n")
	put("var/lib/dpkg/info/python3-yaml.md5sums", "d41d8cd98f00b204e9800998ecf8427e  usr/lib/python3/dist-packages/PyYAML-6.0.dist-info/METADATA\n")
	put("usr/lib/python3/dist-packages/PyYAML-6.0.dist-info/METADATA", "Metadata-Version: 2.1\nName: PyYAML\nVersion: 6.0\n")
	put("opt/venv/lib/python3.11/site-packages/requests-2.31.0.dist-info/METADATA", "Metadata-Version: 2.1\nName: requests\nVersion: 2.31.0\n")
	res, err := rootfsResult(root)
	if err != nil {
		t.Fatal(err)
	}
	var py []string
	for _, p := range res.Packages {
		if p.Ecosystem == "PyPI" {
			py = append(py, p.Name)
		}
	}
	if len(py) != 1 || py[0] != "requests" {
		t.Errorf("PyPI %v", py)
	}
}
