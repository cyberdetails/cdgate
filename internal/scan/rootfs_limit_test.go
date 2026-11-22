package scan

import (
	"os"
	"path/filepath"
	"testing"
)

// An rpm database larger than the 8 MiB lockfile-sibling limit is read in a
// root filesystem (ubi9's is 14.6 MB); the limit stays for lockfile siblings.
func TestRootFilesReadOSDatabaseLargerThanSiblingLimit(t *testing.T) {
	root := t.TempDir()
	big := make([]byte, MaxManifestBytes+1)
	for _, p := range []string{"var/lib/rpm/rpmdb.sqlite", "package.json"} {
		full := filepath.Join(root, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, big, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	rf := rootFiles{siblings{root: root, dir: root}}
	if b, ok := rf.Get("var/lib/rpm/rpmdb.sqlite"); !ok || len(b) != len(big) {
		t.Fatalf("rpm database not read: %v %d", ok, len(b))
	}
	if _, err := rf.s.Read("package.json"); err == nil {
		t.Fatal("sibling manifests keep the 8 MiB limit")
	}
}
