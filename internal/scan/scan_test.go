package scan

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cyberdetails/cdgate/internal/parse"
)

func write(t *testing.T, p, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestWalkFindsLockfilesAndSkipsInstalledTrees(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "py", "requirements.txt"), "django==3.2.0\n")
	write(t, filepath.Join(root, "node_modules", "x", "package-lock.json"), `{"lockfileVersion":3,"packages":{"node_modules/y":{"version":"1.0.0"}}}`)
	write(t, filepath.Join(root, ".git", "requirements.txt"), "secret==1.0\n")
	write(t, filepath.Join(root, "java", "pom.xml"), "<project/>")
	res, err := Dir(root, parse.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Packages) != 1 || res.Packages[0].Name != "django" || res.Packages[0].Source != "py/requirements.txt" {
		t.Fatalf("unexpected packages: %+v", res.Packages)
	}
	if len(res.Unsupported) != 1 || res.Unsupported[0].Path != "java/pom.xml" {
		t.Fatalf("pom.xml must be reported as not analysed: %+v", res.Unsupported)
	}
}

func TestSymlinksAreNeverFollowed(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	write(t, filepath.Join(outside, "requirements.txt"), "outside==1.0\n")
	if err := os.Symlink(filepath.Join(outside, "requirements.txt"), filepath.Join(root, "requirements.txt")); err != nil {
		t.Skip("symlinks not supported here")
	}
	if err := os.Symlink(outside, filepath.Join(root, "linkdir")); err != nil {
		t.Skip("symlinks not supported here")
	}
	res, err := Dir(root, parse.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Packages) != 0 || len(res.Files) != 0 {
		t.Fatalf("a symlink was followed: %+v", res)
	}
}

func TestOversizedFileIsReportedNotRead(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "requirements.txt")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(MaxFileBytes + 1); err != nil {
		t.Fatal(err)
	}
	f.Close()
	res, err := Dir(root, parse.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Files) != 1 || res.Files[0].Error == "" || len(res.Packages) != 0 {
		t.Fatalf("oversized file must be an error, got %+v", res.Files)
	}
}

func TestBrokenLockfileIsAnErrorNotEmpty(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "package-lock.json"), "{ not json")
	res, err := Dir(root, parse.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Files) != 1 || res.Files[0].Error == "" {
		t.Fatalf("broken lockfile must carry an error: %+v", res.Files)
	}
}

func TestSingleFileArgument(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "go.mod")
	write(t, p, "module m\nrequire github.com/a/b v1.0.0\n")
	res, err := Dir(p, parse.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Packages) != 1 || res.Packages[0].Ecosystem != "Go" {
		t.Fatalf("got %+v", res.Packages)
	}
}

func TestRootFilesystemOSPackages(t *testing.T) {
	root := t.TempDir()
	mk := func(p, body string) {
		full := filepath.Join(root, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mk("usr/lib/os-release", "ID=ubuntu\nVERSION_ID=\"22.04\"\n")
	mk("etc/debian_version", "bookworm/sid\n")
	mk("var/lib/dpkg/status", "Package: libssl3\nStatus: install ok installed\nSource: openssl\nVersion: 3.0.2-0ubuntu1.18\n")
	// as in real images, etc/os-release is a symlink; it is never followed
	if err := os.Symlink("../usr/lib/os-release", filepath.Join(root, "etc", "os-release")); err != nil {
		t.Fatal(err)
	}
	// a link out of the tree must not be read either
	if err := os.MkdirAll(filepath.Join(root, "etc", "apk"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/passwd", filepath.Join(root, "etc", "lsb-release")); err != nil {
		t.Fatal(err)
	}
	res, err := Dir(root, parse.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if res.OS == nil || res.OS.Family != "ubuntu" || res.OS.Name != "22.04" {
		t.Fatalf("os: %+v", res.OS)
	}
	if len(res.Packages) != 1 || res.Packages[0].Ecosystem != "Ubuntu:22.04" || res.Packages[0].Name != "openssl" ||
		res.Packages[0].Version != "3.0.2-0ubuntu1.18" || res.Packages[0].Binaries[0] != "libssl3" {
		t.Fatalf("packages: %+v", res.Packages)
	}
}

func TestLocalProjectsCounted(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "rs", "Cargo.lock"), "[[package]]\nname = \"own\"\nversion = \"0.1.0\"\n")
	write(t, filepath.Join(root, "net", "app.deps.json"), `{"libraries":{"app/1.0.0":{"type":"project"},"Dapper/2.1.0":{"type":"package"}}}`)
	res, err := Dir(root, parse.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if res.LocalNotSent != 2 || len(res.Packages) != 1 || res.Packages[0].Name != "Dapper" {
		t.Fatalf("%d %+v", res.LocalNotSent, res.Packages)
	}
}
