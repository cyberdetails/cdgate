package parse

import (
	"errors"
	"sort"
	"strings"
	"testing"
)

type mapFiles map[string]string

func (m mapFiles) Read(rel string) ([]byte, error) {
	if b, ok := m[rel]; ok {
		return []byte(b), nil
	}
	return nil, errors.New("not found")
}
func (m mapFiles) Glob(string) ([]string, error) { return nil, nil }

const julV2 = `julia_version = "1.10.4"
manifest_format = "2.0"

[[deps.Alpha]]
deps = ["Beta", "Stdl"]
uuid = "a"
version = "1.2.3"

[[deps.Beta]]
uuid = "b"
version = "0.5.0+1"

[[deps.Gamma]]
deps = {Zeta = "z"}
uuid = "c"
version = "2.0.0"

[[deps.Delta]]
uuid = "d"
version = "9.9.9"

[[deps.Stdl]]
uuid = "e"

[[deps.Zeta]]
uuid = "z"
version = "3.0.0"
`

const julProject = "[deps]\nAlpha = \"a\"\n\n[extras]\nGamma = \"c\"\n"

func julia(t *testing.T, body string, opt Options) ([]string, error) {
	t.Helper()
	k, ok := Lookup("x/Manifest.toml")
	if !ok || k.Ecosystem != "Julia" {
		t.Fatal("Manifest.toml not registered as Julia")
	}
	ps, err := k.Parse(strings.NewReader(body), opt)
	var out []string
	for _, p := range ps {
		out = append(out, p.Name+"@"+p.Version)
	}
	sort.Strings(out)
	return out, err
}

// Rules from trivy 00b7394 (parser/julia/manifest, analyzer/language/julia/pkg).
func TestJuliaManifest(t *testing.T) {
	all := "Alpha@1.2.3,Beta@0.5.0+1,Delta@9.9.9,Gamma@2.0.0,Stdl@1.10.4,Zeta@3.0.0"
	for name, c := range map[string]struct {
		opt  Options
		want string
	}{
		"no project keeps all":      {Options{}, all},
		"project: what deps reach":  {Options{Files: mapFiles{"Project.toml": julProject}}, "Alpha@1.2.3,Beta@0.5.0+1,Stdl@1.10.4"},
		"extras with --include-dev": {Options{IncludeDev: true, Files: mapFiles{"Project.toml": julProject}}, "Alpha@1.2.3,Beta@0.5.0+1,Gamma@2.0.0,Stdl@1.10.4,Zeta@3.0.0"},
		"unreadable project":        {Options{Files: mapFiles{"Project.toml": "[deps\nbroken"}}, all},
		"empty deps":                {Options{Files: mapFiles{"Project.toml": "[extras]\nGamma = \"c\"\n"}}, ""},
	} {
		got, err := julia(t, julV2, c.opt)
		if err != nil || strings.Join(got, ",") != c.want {
			t.Errorf("%s: %v %v", name, got, err)
		}
	}
	// v1: top-level [[Name]] tables, stdlib version "unknown"
	v1 := "[[Base64]]\nuuid = \"b64\"\n\n[[JSON]]\ndeps = [\"Base64\"]\nuuid = \"j\"\nversion = \"0.21.0\"\n"
	if got, err := julia(t, v1, Options{}); err != nil || strings.Join(got, ",") != "Base64@unknown,JSON@0.21.0" {
		t.Errorf("v1: %v %v", got, err)
	}
	// a v2 file without manifest_format yields nothing (Trivy keeps the empty v1 result)
	if got, err := julia(t, "julia_version = \"1.10.4\"\n\n[[deps.A]]\nuuid = \"a\"\nversion = \"1\"\n", Options{}); err != nil || len(got) != 0 {
		t.Errorf("no manifest_format: %v %v", got, err)
	}
	// deps that are neither: the TOML library decodes without error and Trivy
	// keeps the package (checked against the lab build: A@1.0.0)
	if got, err := julia(t, "julia_version = \"1\"\nmanifest_format = \"2.0\"\n[[deps.A]]\ndeps = 3\nuuid = \"a\"\nversion = \"1.0.0\"\n", Options{}); err != nil || strings.Join(got, ",") != "A@1.0.0" {
		t.Errorf("deps = 3: %v %v", got, err)
	}
	for name, body := range map[string]string{
		"dependency named twice": "julia_version = \"1\"\nmanifest_format = \"2.0\"\n[[deps.A]]\ndeps = [\"D\"]\nuuid = \"a\"\n[[deps.D]]\nuuid = \"d1\"\n[[deps.D]]\nuuid = \"d2\"\n",
		"dependency missing":     "julia_version = \"1\"\nmanifest_format = \"2.0\"\n[[deps.A]]\ndeps = [\"Nope\"]\nuuid = \"a\"\n",
		"not TOML":               "[[deps.A\n",
	} {
		if _, err := julia(t, body, Options{}); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
