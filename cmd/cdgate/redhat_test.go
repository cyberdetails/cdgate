package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A Red Hat layer whose build information Dockerfile this scanner cannot read
// (ARG) leaves its packages unchecked: no request, INCOMPLETE, exit 2, and the
// reason is printed — in an image and in a root filesystem alike.
func TestRedHatUnreadableBuildInfoIsIncomplete(t *testing.T) {
	f, err := os.Open("../../internal/rpmdb/testdata/sqlite.db.gz")
	if err != nil {
		t.Fatal(err)
	}
	g, _ := gzip.NewReader(f)
	db, _ := io.ReadAll(g)
	f.Close()
	files := map[string][]byte{
		"etc/redhat-release":                []byte("Red Hat Enterprise Linux release 9.4 (Plow)\n"),
		"var/lib/rpm/rpmdb.sqlite":          db,
		"root/buildinfo/Dockerfile-x-9.4-1": []byte("FROM x\nARG A=1\nLABEL com.redhat.component=x architecture=x86_64\n"),
	}
	// image: one layer, docker save layout
	var layer bytes.Buffer
	tw := tar.NewWriter(&layer)
	for p, b := range files {
		tw.WriteHeader(&tar.Header{Name: p, Mode: 0o644, Size: int64(len(b)), Typeflag: tar.TypeReg})
		tw.Write(b)
	}
	tw.Close()
	var outer bytes.Buffer
	ow := tar.NewWriter(&outer)
	m, _ := json.Marshal([]map[string]any{{"RepoTags": []string{"rh:1"}, "Layers": []string{"l.tar"}}})
	for _, e := range []struct {
		n string
		b []byte
	}{{"manifest.json", m}, {"l.tar", layer.Bytes()}} {
		ow.WriteHeader(&tar.Header{Name: e.n, Mode: 0o644, Size: int64(len(e.b)), Typeflag: tar.TypeReg})
		ow.Write(e.b)
	}
	ow.Close()
	img := filepath.Join(t.TempDir(), "img.tar")
	os.WriteFile(img, outer.Bytes(), 0o600)
	// root filesystem
	root := t.TempDir()
	for p, b := range files {
		full := filepath.Join(root, filepath.FromSlash(p))
		os.MkdirAll(filepath.Dir(full), 0o755)
		os.WriteFile(full, b, 0o644)
	}
	for _, args := range [][]string{{"image", img}, {"scan", root}} {
		var out, errb bytes.Buffer
		code := run(append(args, "--api", "http://127.0.0.1:1"), &out, &errb)
		if code != 2 || !strings.Contains(out.String(), "RESULT: INCOMPLETE (2 package(s) not checked)") ||
			!strings.Contains(out.String(), "NOT CHECKED: 2 package(s): the image's Red Hat build information") {
			t.Errorf("%s: exit %d\n%s\nstderr: %s", args[0], code, out.String(), errb.String())
		}
	}
}
