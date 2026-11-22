package parse

import (
	"strings"
	"testing"

	"github.com/ferhatcil/cdgate/internal/model"
)

func names(ps []model.Package) []string {
	var out []string
	for _, p := range ps {
		out = append(out, p.Name+"@"+p.Version)
	}
	return out
}

func run(t *testing.T, file, body string, opt Options) []string {
	t.Helper()
	k, ok := Lookup(file)
	if !ok {
		t.Fatalf("no parser for %s", file)
	}
	ps, err := k.Parse(strings.NewReader(body), opt)
	if err != nil {
		t.Fatalf("%s: %v", file, err)
	}
	return names(ps)
}

func eq(t *testing.T, got, want []string) {
	t.Helper()
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("got  %v\nwant %v", got, want)
	}
}

func TestNpmLockV3(t *testing.T) {
	body := `{"lockfileVersion":3,"packages":{
	 "":{"name":"app","dependencies":{"lodash":"4.17.15"},"devDependencies":{"jest":"1"}},
	 "node_modules/lodash":{"version":"4.17.15"},
	 "node_modules/a/node_modules/lodash":{"version":"3.10.1"},
	 "node_modules/@babel/core":{"version":"7.0.0"},
	 "node_modules/jest":{"version":"1.0.0","dev":true},
	 "node_modules/opt":{"version":"2.0.0","devOptional":true},
	 "node_modules/local":{"link":true}}}`
	eq(t, run(t, "package-lock.json", body, Options{}),
		[]string{"@babel/core@7.0.0", "lodash@3.10.1", "lodash@4.17.15"})
	eq(t, run(t, "package-lock.json", body, Options{IncludeDev: true}),
		[]string{"@babel/core@7.0.0", "lodash@3.10.1", "jest@1.0.0", "lodash@4.17.15", "opt@2.0.0"}) // lockfile path order
}

func TestNpmLockV1(t *testing.T) {
	body := `{"lockfileVersion":1,"dependencies":{
	 "a":{"version":"1.0.0","dependencies":{"b":{"version":"2.0.0"}}},
	 "dev":{"version":"1.0.0","dev":true},
	 "loc":{"version":"file:../loc"}}}`
	eq(t, run(t, "package-lock.json", body, Options{}), []string{"a@1.0.0", "b@2.0.0"})
}

func TestRequirements(t *testing.T) {
	body := "# comment\nDjango==3.2.0\nrequests[socks]==2.25.0 ; python_version > '3'\n" +
		"flask>=2.0\n-r other.txt\n--hash=sha256:abc\npyyaml===5.3 # pinned\n\n"
	eq(t, run(t, "requirements.txt", body, Options{}), []string{"Django@3.2.0", "requests@2.25.0", "pyyaml@5.3"})
}

func TestPipfileLock(t *testing.T) {
	body := `{"default":{"requests":{"version":"==2.25.0"},"gitdep":{"git":"x"}},"develop":{"pytest":{"version":"==7.0.0"}}}`
	eq(t, run(t, "Pipfile.lock", body, Options{}), []string{"requests@2.25.0"})
	eq(t, run(t, "Pipfile.lock", body, Options{IncludeDev: true}), []string{"requests@2.25.0", "pytest@7.0.0"})
}

func TestPoetryLock(t *testing.T) {
	body := "[[package]]\nname = \"django\"\nversion = \"3.2.0\"\ncategory = \"main\"\n\n" +
		"[package.dependencies]\nasgiref = \">=3.2\"\n\n[[package]]\nname = \"pytest\"\nversion = \"7.0.0\"\ncategory = \"dev\"\n\n[metadata]\nlock-version = \"1.1\"\n"
	eq(t, run(t, "poetry.lock", body, Options{}), []string{"django@3.2.0"})
}

func TestCargoLock(t *testing.T) {
	body := "version = 3\n\n[[package]]\nname = \"myapp\"\nversion = \"0.1.0\"\n\n" +
		"[[package]]\nname = \"serde\"\nversion = \"1.0.100\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n"
	eq(t, run(t, "Cargo.lock", body, Options{}), []string{"serde@1.0.100"})
}

func TestGoMod(t *testing.T) {
	body := "module example.com/app\n\ngo 1.22\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.6.0\n" +
		"\tgolang.org/x/net v0.0.0-20210405180319-a5a99cb37ef4 // indirect\n\texample.com/local v1.0.0\n)\n" +
		"require github.com/pkg/errors v0.9.1\n\nreplace example.com/local => ../local\n" +
		"replace github.com/pkg/errors v0.9.1 => github.com/fork/errors v0.9.2\n"
	eq(t, run(t, "go.mod", body, Options{}), []string{
		"github.com/gin-gonic/gin@v1.6.0", "golang.org/x/net@v0.0.0-20210405180319-a5a99cb37ef4",
		"github.com/fork/errors@v0.9.2"})
}

func TestComposerLock(t *testing.T) {
	body := `{"packages":[{"name":"symfony/http-kernel","version":"v5.4.0"}],"packages-dev":[{"name":"phpunit/phpunit","version":"9.5.0"}]}`
	eq(t, run(t, "composer.lock", body, Options{}), []string{"symfony/http-kernel@v5.4.0"})
}

func TestGemfileLock(t *testing.T) {
	body := "GEM\n  remote: https://rubygems.org/\n  specs:\n    rails (6.1.0)\n      actionpack (= 6.1.0)\n" +
		"    nokogiri (1.15.4-x86_64-linux)\n\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n  rails\n"
	eq(t, run(t, "Gemfile.lock", body, Options{}), []string{"rails@6.1.0", "nokogiri@1.15.4"})
}

func TestNugetLock(t *testing.T) {
	body := `{"version":1,"dependencies":{"net6.0":{"Newtonsoft.Json":{"type":"Direct","resolved":"12.0.1"},
	 "Other.Project":{"type":"Project"},"System.Text.Json":{"type":"Transitive","resolved":"6.0.0"}},
	 "net8.0":{"Newtonsoft.Json":{"type":"Direct","resolved":"12.0.1"}}}}`
	eq(t, run(t, "packages.lock.json", body, Options{}), []string{"Newtonsoft.Json@12.0.1", "System.Text.Json@6.0.0"})
}

func TestPackagesConfig(t *testing.T) {
	body := `<?xml version="1.0" encoding="utf-8"?><packages><package id="log4net" version="2.0.8" />` +
		`<package id="xunit" version="2.4.1" developmentDependency="true" /></packages>`
	eq(t, run(t, "packages.config", body, Options{}), []string{"log4net@2.0.8"})
	k, _ := Lookup("packages.config")
	_, err := k.Parse(strings.NewReader(`<?xml version="1.0"?><!DOCTYPE p [<!ENTITY x "y">]><packages/>`), Options{})
	if err == nil {
		t.Fatal("DOCTYPE must be rejected")
	}
}

func TestGradleLock(t *testing.T) {
	body := "# comment\ncom.fasterxml.jackson.core:jackson-databind:2.9.8=compileClasspath,runtimeClasspath\nempty=annotationProcessor\n"
	eq(t, run(t, "gradle.lockfile", body, Options{}), []string{"com.fasterxml.jackson.core:jackson-databind@2.9.8"})
}

func TestYarnLockV1AndBerry(t *testing.T) {
	v1 := "# yarn lockfile v1\n\nlodash@^4.17.0, lodash@^4.17.15:\n  version \"4.17.15\"\n  resolved \"x\"\n\n" +
		"\"@babel/core@^7.0.0\":\n  version \"7.0.0\"\n"
	eq(t, run(t, "yarn.lock", v1, Options{}), []string{"lodash@4.17.15", "@babel/core@7.0.0"})
	berry := "__metadata:\n  version: 6\n\n\"lodash@npm:^4.17.0\":\n  version: 4.17.21\n\n" +
		"\"app@workspace:.\":\n  version: 0.0.0-use.local\n"
	eq(t, run(t, "yarn.lock", berry, Options{}), []string{"lodash@4.17.21"})
}

func TestPnpmLock(t *testing.T) {
	v6 := "lockfileVersion: '6.0'\n\npackages:\n\n  /lodash@4.17.21:\n    resolution: {integrity: x}\n    dev: false\n\n" +
		"  /jest@29.0.0:\n    dev: true\n\n  /@babel/core@7.0.0(supports-color@5.5.0):\n    dev: false\n"
	eq(t, run(t, "pnpm-lock.yaml", v6, Options{}), []string{"lodash@4.17.21", "@babel/core@7.0.0"})
	// v9 (Trivy parseV9): roots from importers, graph from snapshots;
	// unreachable from a production root = dev.
	v9 := `lockfileVersion: '9.0'

importers:

  .:
    dependencies:
      express:
        specifier: ^4.18.0
        version: 4.18.2
    devDependencies:
      '@types/node':
        specifier: ^20
        version: 20.0.0
    optionalDependencies:
      fsevents:
        specifier: ^2
        version: 2.3.3

packages:

  express@4.18.2:
    resolution: {integrity: a}
  body-parser@1.20.1:
    resolution: {integrity: b}
  '@types/node@20.0.0':
    resolution: {integrity: c}
  undici-types@5.26.5:
    resolution: {integrity: d}
  fsevents@2.3.3:
    resolution: {integrity: e}

snapshots:

  express@4.18.2:
    dependencies:
      body-parser: 1.20.1

  body-parser@1.20.1: {}

  '@types/node@20.0.0':
    dependencies:
      undici-types: 5.26.5

  undici-types@5.26.5: {}

  fsevents@2.3.3: {}
`
	eq(t, run(t, "pnpm-lock.yaml", v9, Options{}), []string{"body-parser@1.20.1", "express@4.18.2"})
	eq(t, run(t, "pnpm-lock.yaml", v9, Options{IncludeDev: true}),
		[]string{"@types/node@20.0.0", "body-parser@1.20.1", "express@4.18.2", "fsevents@2.3.3", "undici-types@5.26.5"})
	v5 := "lockfileVersion: 5.4\n\npackages:\n\n  /lodash/4.17.21:\n    dev: false\n\n  /@babel/core/7.0.0_supports-color@5.5.0:\n    dev: false\n"
	eq(t, run(t, "pnpm-lock.yaml", v5, Options{}), []string{"lodash@4.17.21", "@babel/core@7.0.0"})
	odd := "packages:\n\n  /@scope/pkg/1.2.3_@types+node@20.0.0:\n    dev: false\n\n  tarball@https://x/y.tgz:\n    resolution: {}\n"
	eq(t, run(t, "pnpm-lock.yaml", odd, Options{}), []string{"@scope/pkg@1.2.3"})
}

func TestUnsupportedManifestsAreNamed(t *testing.T) {
	for _, f := range []string{"pom.xml", "build.gradle", "Pipfile", "Gemfile"} {
		if _, ok := Unsupported(f); !ok {
			t.Fatalf("%s must be reported as not analysed", f)
		}
	}
}

func TestControlCharactersRejected(t *testing.T) {
	got := run(t, "requirements.txt", "evil\x1b[31m==1.0\nok==1.0\n", Options{})
	eq(t, got, []string{"ok@1.0"})
}

// memFiles is an in-memory parse.Files for tests.
type memFiles map[string]string

func (m memFiles) Read(rel string) ([]byte, error) {
	if v, ok := m[rel]; ok {
		return []byte(v), nil
	}
	return nil, errNotFound
}

func (m memFiles) Glob(pattern string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for k := range m {
		dir := k[:strings.LastIndex(k+"/", "/")]
		if i := strings.LastIndex(k, "/"); i > 0 {
			dir = k[:i]
		} else {
			continue
		}
		if ok, _ := pathMatch(pattern, dir); ok && !seen[dir] {
			seen[dir] = true
			out = append(out, dir)
		}
	}
	return out, nil
}

func TestYarnDevDependenciesFromPackageJSONAndWorkspaces(t *testing.T) {
	lock := `# yarn lockfile v1

express@^4.18.0:
  version "4.18.2"
  dependencies:
    body-parser "1.20.1"

body-parser@1.20.1:
  version "1.20.1"

jest@^29.0.0:
  version "29.0.0"
  dependencies:
    body-parser "1.20.1"
    chalk "^4.0.0"

chalk@^4.0.0:
  version "4.1.2"

lodash@^4.17.0:
  version "4.17.21"

orphan@^1.0.0:
  version "1.0.0"
`
	files := memFiles{
		"package.json":            `{"dependencies":{"express":"^4.18.0"},"devDependencies":{"jest":"^29.0.0"},"workspaces":["packages/*"]}`,
		"packages/a/package.json": `{"dependencies":{"lodash":"^4.17.0"}}`,
	}
	k, _ := Lookup("yarn.lock")
	ps, err := k.Parse(strings.NewReader(lock), Options{Files: files})
	if err != nil {
		t.Fatal(err)
	}
	// body-parser: reachable from dev (jest) AND prod (express) -> prod.
	// chalk, jest: dev only. lodash: prod via a workspace. orphan: unreachable -> kept (Trivy).
	eq(t, names(ps), []string{"express@4.18.2", "body-parser@1.20.1", "lodash@4.17.21", "orphan@1.0.0"})
	ps, _ = k.Parse(strings.NewReader(lock), Options{})
	if len(ps) != 6 {
		t.Fatalf("without package.json nothing is dev (Trivy): %v", names(ps))
	}
}

func TestYarnBerryDevDependencies(t *testing.T) {
	lock := "__metadata:\n  version: 8\n\n" +
		"\"react@npm:^18.0.0\":\n  version: 18.2.0\n  dependencies:\n    loose-envify: \"npm:^1.1.0\"\n\n" +
		"\"loose-envify@npm:^1.1.0\":\n  version: 1.4.0\n\n" +
		"\"typescript@npm:^5.0.0\":\n  version: 5.4.5\n\n" +
		"\"app@workspace:.\":\n  version: 0.0.0-use.local\n"
	files := memFiles{"package.json": `{"dependencies":{"react":"^18.0.0"},"devDependencies":{"typescript":"^5.0.0"}}`}
	k, _ := Lookup("yarn.lock")
	ps, err := k.Parse(strings.NewReader(lock), Options{Files: files})
	if err != nil {
		t.Fatal(err)
	}
	eq(t, names(ps), []string{"react@18.2.0", "loose-envify@1.4.0"})
}

func TestPoetryGroupsAndPyproject(t *testing.T) {
	lock := `[[package]]
name = "django"
version = "4.2.0"
groups = ["main"]

[package.dependencies]
asgiref = ">=3.6"

[[package]]
name = "asgiref"
version = "3.7.2"
groups = ["main"]

[[package]]
name = "pytest"
version = "7.4.0"
groups = ["dev"]

[[package]]
name = "unused-main"
version = "1.0.0"
groups = ["main"]
`
	k, _ := Lookup("poetry.lock")
	ps, err := k.Parse(strings.NewReader(lock), Options{})
	if err != nil {
		t.Fatal(err)
	}
	eq(t, names(ps), []string{"django@4.2.0", "asgiref@3.7.2", "unused-main@1.0.0"})
	files := memFiles{"pyproject.toml": "[project]\nname = \"app\"\ndependencies = [\n  \"Django (>=4.2)\",  # web\n]\n"}
	ps, err = k.Parse(strings.NewReader(lock), Options{Files: files})
	if err != nil {
		t.Fatal(err)
	}
	// With pyproject.toml, packages unreachable from the main dependencies are dev (Trivy).
	eq(t, names(ps), []string{"django@4.2.0", "asgiref@3.7.2"})
}

func TestGemfileGitAndPathSections(t *testing.T) {
	body := "GIT\n  remote: https://github.com/x/webpush\n  revision: abc\n  specs:\n    webpush (1.1.0)\n\n" +
		"PATH\n  remote: ./local\n  specs:\n    local-gem (0.0.1)\n\nGEM\n  specs:\n    rails (7.0.0)\n"
	eq(t, run(t, "Gemfile.lock", body, Options{}), []string{"webpush@1.1.0", "local-gem@0.0.1", "rails@7.0.0"})
}

func TestYarnAliasReportsTheRealPackage(t *testing.T) {
	lock := "__metadata:\n  version: 8\n\n" +
		"\"esbuild@npm:esbuild-wasm@^0.23.0\":\n  version: 0.23.0\n\n" +
		"\"tool@npm:^1.0.0\":\n  version: 1.0.0\n  dependencies:\n    esbuild: \"npm:esbuild-wasm@^0.23.0\"\n"
	files := memFiles{"package.json": `{"dependencies":{"tool":"^1.0.0"}}`}
	k, _ := Lookup("yarn.lock")
	ps, err := k.Parse(strings.NewReader(lock), Options{Files: files})
	if err != nil {
		t.Fatal(err)
	}
	// esbuild-wasm is reached from a prod root through the alias edge.
	eq(t, names(ps), []string{"esbuild-wasm@0.23.0", "tool@1.0.0"})
}
