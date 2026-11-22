package parse

import (
	"bytes"
	"testing"
)

// Every parser must return (possibly an error) and never panic on arbitrary
// input: lockfiles in a pull request are attacker-controlled. Run longer with
//
//	go test ./internal/parse -run=^$ -fuzz=FuzzParsers -fuzztime=60s
func FuzzParsers(f *testing.F) {
	seeds := []string{
		`{"lockfileVersion":3,"packages":{"node_modules/a":{"version":"1.0.0"}}}`,
		`{"lockfileVersion":1,"dependencies":{"a":{"version":"1","dependencies":{"b":{"version":"2"}}}}}`,
		"Django==3.2.0\n", "[[package]]\nname = \"a\"\nversion = \"1\"\nsource = \"x\"\n",
		"module m\nrequire (\n\ta v1.0.0\n)\n", "GEM\n  specs:\n    a (1.0)\n",
		`<packages><package id="a" version="1"/></packages>`, "a:b:1=x\n",
		"a@^1:\n  version \"1.0.0\"\n", "packages:\n  /a@1.0.0:\n    dev: true\n",
		`{"packages":[{"name":"a","version":"1"}]}`, `{"dependencies":{"x":{"a":{"type":"Direct","resolved":"1"}}}}`,
		`{"default":{"a":{"version":"==1"}}}`, "", "{", "\x00\x01",
		`{"runtimeTarget":{"name":"t"},"targets":{"t":{"a/1":{"runtime":{}}}},"libraries":{"a/1":{"type":"package"}}}`,
		`<Project><ItemGroup><PackageVersion Include="a" Version="1"/></ItemGroup></Project>`,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		local := 0
		for _, k := range byName {
			_, _ = k.Parse(bytes.NewReader(data), Options{IncludeDev: true, LocalProjects: &local})
		}
		// suffix-matched kinds are not in byName
		_, _ = parseDepsJSON(bytes.NewReader(data), Options{LocalProjects: &local})
		_, _ = parsePackagesProps(bytes.NewReader(data), Options{})
	})
}
