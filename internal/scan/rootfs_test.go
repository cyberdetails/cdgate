package scan

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func writeMode(t *testing.T, p string, b []byte, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, b, mode); err != nil {
		t.Fatal(err)
	}
}

func keys[V any](m map[string]V) string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

// trivy rootfs: image analyzers over a directory; walker skips "**/.git" and
// the top-level proc, sys and dev, never follows links, skips unreadable dirs.
func TestOpenRootFS(t *testing.T) {
	root := t.TempDir()
	pkg := []byte(`{"name":"lodash","version":"4.17.20"}`)
	writeMode(t, filepath.Join(root, "app/node_modules/lodash/package.json"), pkg, 0o644) // lock-file scans skip node_modules
	writeMode(t, filepath.Join(root, "app/.git/x/package.json"), pkg, 0o644)
	writeMode(t, filepath.Join(root, "proc/1/package.json"), pkg, 0o644)
	writeMode(t, filepath.Join(root, "srv/proc/package.json"), pkg, 0o644) // only the top-level proc
	writeMode(t, filepath.Join(root, "app/package-lock.json"), []byte(`{"lockfileVersion":3}`), 0o644)
	exe, _ := os.Executable()
	gobin, _ := os.ReadFile(exe)
	writeMode(t, filepath.Join(root, "usr/bin/tool"), gobin, 0o755)
	writeMode(t, filepath.Join(root, "usr/share/tool.noexec"), gobin, 0o644) // no exec bit: not read
	var jar bytes.Buffer
	w := zip.NewWriter(&jar)
	f, _ := w.Create("META-INF/maven/g/a/pom.properties")
	f.Write([]byte("groupId=g\nartifactId=a\nversion=1.0\n"))
	w.Close()
	writeMode(t, filepath.Join(root, "opt/a-1.0.jar"), jar.Bytes(), 0o644)
	os.Symlink(filepath.Join(root, "app"), filepath.Join(root, "link"))
	os.Symlink("/etc/passwd", filepath.Join(root, "usr/lib/package.json"))
	locked := filepath.Join(root, "locked")
	writeMode(t, filepath.Join(locked, "package.json"), pkg, 0o644)
	os.Chmod(locked, 0)
	defer os.Chmod(locked, 0o755)

	r, err := OpenRootFS(root)
	if err != nil {
		t.Fatal(err)
	}
	if got := keys(r.Metadata()); got != "app/node_modules/lodash/package.json,srv/proc/package.json" {
		t.Errorf("metadata %s", got)
	}
	if got := keys(r.GoBinaries()); got != "usr/bin/tool" {
		t.Errorf("go binaries %s", got)
	}
	if j := r.Jars()["opt/a-1.0.jar"]; j == nil || len(j.Packages) != 1 || j.Packages[0].Name != "g:a" {
		t.Errorf("jars %v", r.Jars())
	}
	if _, err := OpenRootFS(filepath.Join(root, "app/package-lock.json")); err == nil {
		t.Error("a file is not a root filesystem")
	}
}
