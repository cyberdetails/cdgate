// Package parse reads dependency lockfiles and manifests into packages.
//
// Every parser treats its input as untrusted: it never executes anything,
// never follows references to other files or URLs, returns an error instead
// of panicking on malformed input, and is fuzz-tested (parse_fuzz_test.go).
// Size limits are applied by the caller (internal/scan) before parsing.
package parse

import (
	"bufio"
	"errors"
	"io"
	"path"
	"strings"

	"github.com/ferhatcil/cdgate/internal/model"
)

// Options controls what a parser includes.
type Options struct {
	// IncludeDev adds development-only dependencies (npm devDependencies,
	// Pipfile "develop", composer "packages-dev", ...). Off by default, like Trivy.
	IncludeDev bool
	// Files gives read access to files next to the lockfile (package.json,
	// pyproject.toml, workspace manifests). Nil means none: dev dependencies
	// that only a manifest can identify are then kept, like Trivy without one.
	Files Files
	// LocalProjects, when set, counts the application's own projects a
	// reader left out (Cargo workspace crates, .deps.json "project"
	// libraries): their names are not sent, and Trivy matches them.
	LocalProjects *int
}

func countLocal(opt Options) {
	if opt.LocalProjects != nil {
		*opt.LocalProjects++
	}
}

// Files is read access limited to the scanned tree. Implementations must
// refuse paths outside the scan root, refuse symbolic links in any path
// component, and cap the size of what they return (see internal/scan).
type Files interface {
	// Read returns a file; rel is a slash path relative to the lockfile's directory.
	Read(rel string) ([]byte, error)
	// Glob returns directories (slash paths relative to the lockfile's
	// directory) matching a path.Match pattern such as "packages/*".
	Glob(pattern string) ([]string, error)
}

// Parser reads one file. ecosystem is filled in by the registry.
type Parser func(r io.Reader, opt Options) ([]model.Package, error)

// Kind describes a supported file.
type Kind struct {
	Name      string // e.g. "package-lock.json"
	Ecosystem string // OSV ecosystem name sent to the API
	Parse     Parser
}

// ErrNotSupported marks a recognised manifest we cannot read yet (e.g. pom.xml
// without dependency resolution). The scanner reports it instead of skipping
// it silently.
var ErrNotSupported = errors.New("recognised but not supported yet")

var byName = map[string]Kind{
	"package-lock.json":           {"package-lock.json", "npm", parseNpmLock},
	"npm-shrinkwrap.json":         {"npm-shrinkwrap.json", "npm", parseNpmLock},
	"yarn.lock":                   {"yarn.lock", "npm", parseYarnLock},
	"pnpm-lock.yaml":              {"pnpm-lock.yaml", "npm", parsePnpmLock},
	"requirements.txt":            {"requirements.txt", "PyPI", parseRequirements},
	"Pipfile.lock":                {"Pipfile.lock", "PyPI", parsePipfileLock},
	"poetry.lock":                 {"poetry.lock", "PyPI", parsePoetryLock},
	"go.mod":                      {"go.mod", "Go", parseGoMod},
	"Cargo.lock":                  {"Cargo.lock", "crates.io", parseCargoLock},
	"composer.lock":               {"composer.lock", "Packagist", parseComposerLock},
	"Gemfile.lock":                {"Gemfile.lock", "RubyGems", parseGemfileLock},
	"packages.lock.json":          {"packages.lock.json", "NuGet", parseNugetLock},
	"packages.config":             {"packages.config", "NuGet", parsePackagesConfig},
	"gradle.lockfile":             {"gradle.lockfile", "Maven", parseGradleLock},
	"buildscript-gradle.lockfile": {"buildscript-gradle.lockfile", "Maven", parseGradleLock},
	"Manifest.toml":               {"Manifest.toml", "Julia", parseJuliaManifest},
}

// Recognised manifests that need resolution we do not do yet. Listed so the
// report can say "found but not analysed" (never a silent pass).
var unsupported = map[string]string{
	"pom.xml":          "Maven pom.xml needs dependency resolution (planned); use a CycloneDX SBOM or gradle.lockfile meanwhile",
	"build.gradle":     "Gradle build file: generate gradle.lockfile (`gradle dependencies --write-locks`)",
	"build.gradle.kts": "Gradle build file: generate gradle.lockfile (`gradle dependencies --write-locks`)",
	"Pipfile":          "Pipfile without Pipfile.lock: run `pipenv lock`",
	"pyproject.toml":   "pyproject.toml without a lockfile (poetry.lock / requirements.txt)",
	"Gemfile":          "Gemfile without Gemfile.lock: run `bundle lock`",
	"composer.json":    "composer.json without composer.lock: run `composer update --lock`",
	"Cargo.toml":       "Cargo.toml without Cargo.lock: run `cargo generate-lockfile`",
}

// Lookup returns the parser for a file name (base name only).
func Lookup(fileName string) (Kind, bool) {
	k, ok := byName[path.Base(fileName)]
	if ok {
		return k, true
	}
	if strings.HasSuffix(fileName, ".gradle.lockfile") || strings.HasSuffix(fileName, "-gradle.lockfile") {
		return Kind{"gradle.lockfile", "Maven", parseGradleLock}, true
	}
	if strings.HasSuffix(fileName, ".deps.json") {
		return Kind{".deps.json", "NuGet", parseDepsJSON}, true
	}
	if IsPackagesProps(fileName) {
		return Kind{"packages.props", "NuGet", parsePackagesProps}, true
	}
	return Kind{}, false
}

// Unsupported returns a human reason when the file is a recognised manifest
// that is not analysed.
func Unsupported(fileName string) (string, bool) {
	r, ok := unsupported[path.Base(fileName)]
	return r, ok
}

// lines yields text lines with a per-line cap so a single huge line cannot
// exhaust memory.
func lines(r io.Reader) *bufio.Scanner {
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 64*1024), 4*1024*1024)
	return s
}

// clean trims and rejects values with control characters or excessive length.
func clean(s string, max int) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > max {
		return "", false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return "", false
		}
	}
	return s, true
}

func pkg(name, version string, direct bool) (model.Package, bool) {
	n, ok1 := clean(name, 214)
	v, ok2 := clean(version, 100)
	if !ok1 || !ok2 {
		return model.Package{}, false
	}
	return model.Package{Name: n, Version: v, Direct: direct}, true
}
