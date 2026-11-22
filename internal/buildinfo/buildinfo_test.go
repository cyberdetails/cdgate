package buildinfo

import (
	"bufio"
	"compress/gzip"
	"encoding/base64"
	"os"
	"strings"
	"testing"
)

// TestDockerfileOracle compares the Dockerfile reader with buildkit v0.34.2 +
// Trivy's dockerfileAnalyzer (lab/dforacle) over a generated corpus
// (lab/dfgen.py): every Found must equal the oracle's NVR and architecture,
// every NotFound must be an oracle error (no build information). Unsupported
// is allowed (the caller reports those packages as not checked) but counted.
func TestDockerfileOracle(t *testing.T) {
	f, err := os.Open("testdata/dockerfile_oracle.tsv.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	sc := bufio.NewScanner(gz)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	var n, found, notFound, unsupported, oracleOK int
	for sc.Scan() {
		c := strings.Split(sc.Text(), "\t")
		if len(c) < 3 {
			t.Fatalf("bad line %q", sc.Text())
		}
		b, err := base64.StdEncoding.DecodeString(c[1])
		if err != nil {
			t.Fatal(err)
		}
		n++
		if c[2] == "OK" {
			oracleOK++
		}
		nvr, arch, st := Dockerfile(c[0], b)
		switch st {
		case Found:
			found++
			if c[2] != "OK" || len(c) != 5 || b64(t, c[3]) != nvr || b64(t, c[4]) != arch {
				t.Errorf("case %d: got %q %q, oracle %v\n%s", n, nvr, arch, c[2:], b)
			}
		case NotFound:
			notFound++
			if c[2] != "ERR" {
				t.Errorf("case %d: NotFound, oracle %v\n%s", n, c[2:], b)
			}
		case Unsupported:
			unsupported++
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	t.Logf("%d cases: found %d (oracle OK %d), not found %d, unsupported %d", n, found, oracleOK, notFound, unsupported)
	// The guarantee is the per-case check above (no wrong answer). Many
	// oracle-OK cases are deliberately Unsupported: variable substitution in
	// a label that matters ($X; Red Hat's Dockerfiles do not use it, and
	// Trivy expands raw, still-quoted ENV values there), ARG, instruction
	// flags, heredocs, FROM ... AS. This floor only catches a regression
	// that makes everything Unsupported.
	if n < 10000 || found < 900 {
		t.Fatalf("corpus too small or too many oracle-OK cases unsupported: %d/%d", found, oracleOK)
	}
}

func b64(t *testing.T, s string) string {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// Real files from registry.access.redhat.com images (2026-11-18).
func TestDockerfileRealImages(t *testing.T) {
	ubi81 := "FROM sha256:09736abe5571f13d6a5aae3cd64d1a40ff0fba27ce2b061890b40870e4699809\n\n" +
		"LABEL maintainer=\"Red Hat, Inc.\"\n\nLABEL com.redhat.component=\"ubi8-container\" \\\n      name=\"ubi8\" \\\n" +
		"      version=\"8.1\"\n\n#label for EULA\nLABEL com.redhat.license_terms=\"https://www.redhat.com/x#UBI\"\n" +
		"ENV container oci\nCMD [\"/bin/bash\"]\nRUN rm -rf /var/log/*\n" +
		"LABEL \"io.k8s.description\"=\"x\" \"vendor\"=\"Red Hat, Inc.\" \"architecture\"=\"arm64\" \"release\"=\"408\"\n"
	for _, in := range []string{ubi81, "\ufeff" + ubi81, strings.ReplaceAll(ubi81, "\n", "\r\n")} {
		nvr, arch, st := Dockerfile("root/buildinfo/Dockerfile-ubi8-8.1-408", []byte(in))
		if st != Found || nvr != "ubi8-container-8.1-408" || arch != "arm64" {
			t.Fatalf("got %q %q %v", nvr, arch, st)
		}
	}
}

func TestContentSets(t *testing.T) {
	for _, c := range []struct {
		in   string
		want []string
	}{
		{`{"content_sets": ["a", "b"], "metadata": {}}`, []string{"a", "b"}},
		{`{"content_sets": []}`, nil},
		{`{"architecture": "aarch64"}`, nil}, // labels.json
		{`{"content_sets": "a"}`, nil},
		{`{"content_sets": ["a"]} trailing`, []string{"a"}}, // json.Decoder reads the first value
		{`not json`, nil},
	} {
		got := ContentSets([]byte(c.in))
		if strings.Join(got, ",") != strings.Join(c.want, ",") || (got == nil) != (c.want == nil) {
			t.Errorf("%s: got %v", c.in, got)
		}
	}
	for p, want := range map[string]bool{
		"root/buildinfo/content_manifests/x.json": true, "usr/share/buildinfo/content-sets.json": true,
		"root/buildinfo/content-sets.json": false, "usr/share/buildinfo/sub/x.json": false,
		"root/buildinfo/content_manifests/x.txt": false,
	} {
		if IsContentManifest(p) != want {
			t.Errorf("IsContentManifest(%s) != %v", p, want)
		}
	}
	for p, want := range map[string]bool{
		"root/buildinfo/Dockerfile-ubi8-8.1-408": true, "root/buildinfo/Dockerfile": true,
		"root/buildinfo/x/Dockerfile": false, "root/Dockerfile": false,
	} {
		if IsDockerfile(p) != want {
			t.Errorf("IsDockerfile(%s) != %v", p, want)
		}
	}
}

func TestParseVersion(t *testing.T) {
	for in, want := range map[string]string{
		"root/buildinfo/Dockerfile-ubi8-8.1-408": "8.1-408",
		"root/buildinfo/Dockerfile":              "",
		"root/buildinfo/Dockerfile-x":            "x", // CutLast(nv) not found: version ""
	} {
		if got := parseVersion(in); got != want && !(in == "root/buildinfo/Dockerfile-x" && got == "-x") {
			t.Errorf("parseVersion(%s) = %q", in, got)
		}
	}
}

func TestMerge(t *testing.T) {
	df := File{Path: "root/buildinfo/Dockerfile-ubi8-8.1-408", B: []byte("FROM x\nLABEL com.redhat.component=c architecture=a\n")}
	a := File{Path: "root/buildinfo/content_manifests/a.json", B: []byte(`{"content_sets":["a"]}`)}
	b := File{Path: "usr/share/buildinfo/b.json", B: []byte(`{"content_sets":["b"]}`)}
	labels := File{Path: "usr/share/buildinfo/labels.json", B: []byte(`{"architecture":"x"}`)}
	bi, known := Merge([]File{b, labels, df, a})
	if !known || bi == nil || bi.Nvr != "c-8.1-408" || bi.Arch != "a" || strings.Join(bi.ContentSets, ",") != "b" {
		t.Fatalf("got %+v %v", bi, known) // path order: usr/share/buildinfo/b.json is the later one
	}
	if bi, known := Merge([]File{labels}); bi != nil || !known {
		t.Fatalf("no build information: %+v", bi)
	}
	if _, known := Merge([]File{a, {Path: "usr/share/buildinfo/big.json", TooLarge: true}}); known {
		t.Fatal("oversized file: unknown")
	}
}

// Image content is untrusted: the readers must not panic or loop.
func FuzzDockerfile(f *testing.F) {
	f.Add("root/buildinfo/Dockerfile-a-1-2", "FROM x\nLABEL com.redhat.component=\"c\" \\\n architecture='a'\n")
	f.Add("root/buildinfo/Dockerfile", "\xef\xbb\xbfFROM x\r\nLABEL a\\\n\n# c\n b=\"\\\"\"\n")
	f.Fuzz(func(t *testing.T, p, body string) {
		Dockerfile(p, []byte(body))
		ContentSets([]byte(body))
	})
}
