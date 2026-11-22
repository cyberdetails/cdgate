package ospkg

import "testing"

// FuzzOSFiles: the package databases and release files of an image are
// untrusted; parsing must never panic.
func FuzzOSFiles(f *testing.F) {
	f.Add([]byte(status), []byte("P:a\nV:1-r0\no:a\n"), []byte("ID=ubuntu\nVERSION_ID=22.04\n"))
	f.Add([]byte("Package: x\nSource: y (\nVersion: 1:\n"), []byte("o:\nV:\n"), []byte("https://x/alpine/v3.2/\n"))
	f.Fuzz(func(t *testing.T, dpkg, apk, rel []byte) {
		sk := map[string]int{}
		parseDpkg(dpkg, sk, false, true)
		parseApk(apk, sk, true)
		fs := memFS{"etc/os-release": string(rel), "etc/debian_version": string(rel), "etc/alpine-release": string(rel),
			"etc/apk/repositories": string(rel), "var/lib/dpkg/status": string(dpkg), "lib/apk/db/installed": string(apk),
			"var/lib/ubuntu-advantage/status.json": string(rel)}
		if o, err := DetectOS(fs); err == nil {
			_, _ = Ecosystem(o)
		}
		_, _ = Analyze(fs)
	})
}
