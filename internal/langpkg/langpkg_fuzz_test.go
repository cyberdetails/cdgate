package langpkg

import "testing"

// FuzzParsers: every file read from an image is untrusted; no parser may
// panic. ReadGoBinary gets the input as an executable, the ldflags reader
// as a build setting.
func FuzzParsers(f *testing.F) {
	f.Add([]byte(`{"name":"a","version":"1.0.0"}`))
	f.Add([]byte("Name: x\nVersion: 1\n"))
	f.Add([]byte("Gem::Specification.new do |s|\n s.name = 'a'\n s.version = '1'\nend\n"))
	f.Add([]byte(`{"packages":[{"name":"a/b","version":"1"}]}`))
	f.Add([]byte("-s -w -X 'main.version=1.0.0' -X a=b,c=d --x -h"))
	f.Add([]byte("\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x3e\x00"))
	f.Add([]byte("PK\x03\x04"))
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _, _ = nodePkg(b)
		_, _, _ = pythonMetadata(b)
		_, _, _, _ = pythonEgg(b)
		_, _, _ = gemspec(b)
		_, _ = composerInstalled(b)
		_ = GoExeCandidate(b)
		_ = ReadGoBinary(b)
		_ = elfSymbolVersion(b, "m")
		if args, err := shellSplit(string(b)); err == nil {
			_, _ = xFlags(args)
		}
		_ = semverValid(string(b))
		_ = isPseudoVersion(string(b))
		Analyze(memSource{files: map[string][]byte{"x/package.json": b, "y.dist-info/METADATA": b, "z.egg": b,
			"a/specifications/b.gemspec": b, "installed.json": b}}, nil)
	})
}
