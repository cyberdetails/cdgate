package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// testdata/gate is produced by the Python gate (cyberdetails.sca/lab/gate_golden.py)
// on the same reports and the same server answers. Each case runs the Go CLI
// end to end against an httptest server serving those answers and requires
// the same exit code, the same --json-out document and the same text.

const goldenBase = "https://cyberdetails.org"

// golden reads testdata/gate/<name>, or <name>.gz (large files are stored
// compressed). ok=false when neither exists.
func golden(t *testing.T, name string) ([]byte, bool) {
	t.Helper()
	p := filepath.Join("testdata", "gate", name)
	if data, err := os.ReadFile(p); err == nil {
		return data, true
	}
	f, err := os.Open(p + ".gz")
	if os.IsNotExist(err) {
		return nil, false
	}
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	return data, true
}

func triageServer(t *testing.T) (*httptest.Server, *int) {
	t.Helper()
	raw, ok := golden(t, "triage.json")
	if !ok {
		t.Fatal("testdata/gate/triage.json missing")
	}
	var answers map[string]map[string]json.RawMessage
	if err := json.Unmarshal(raw, &answers); err != nil {
		t.Fatal(err)
	}
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/sca/triage" {
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		var body struct {
			CVEs         []string `json:"cves"`
			BlockAt      string   `json:"block_at"`
			BlockUnknown bool     `json:"block_unknown"`
		}
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields() // the gate sends CVE ids and the threshold, nothing else
		if err := dec.Decode(&body); err != nil || len(body.CVEs) == 0 || len(body.CVEs) > 1000 {
			http.Error(w, "bad body", http.StatusUnprocessableEntity)
			return
		}
		items := make([]json.RawMessage, 0, len(body.CVEs))
		for _, c := range body.CVEs {
			items = append(items, answers[body.BlockAt][c])
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"items": items})
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func normalise(t *testing.T, data []byte, base string) any {
	t.Helper()
	var v map[string]any
	if err := json.Unmarshal(bytes.ReplaceAll(data, []byte(base), []byte(goldenBase)), &v); err != nil {
		t.Fatal(err)
	}
	v["tool"] = "VERSION"
	return v
}

func TestGateMatchesPythonGolden(t *testing.T) {
	srv, _ := triageServer(t)
	reports, _ := filepath.Glob("testdata/gate/*.report.json*")
	if len(reports) < 5 {
		t.Fatalf("golden reports missing: %v", reports)
	}
	n := 0
	for _, path := range reports {
		name := strings.TrimSuffix(strings.TrimSuffix(filepath.Base(path), ".gz"), ".report.json")
		data, _ := golden(t, name+".report.json")
		rep := filepath.Join(t.TempDir(), name+".json")
		if err := os.WriteFile(rep, data, 0o600); err != nil {
			t.Fatal(err)
		}
		for _, blockAt := range []string{"known_exploited", "high", "cisa_kev", "never"} {
			txtWant, ok := golden(t, name+"."+blockAt+".txt")
			if !ok {
				continue
			}
			n++
			t.Run(name+"/"+blockAt, func(t *testing.T) {
				jsonOut := filepath.Join(t.TempDir(), "out.json")
				var stdout, stderr bytes.Buffer
				code := run([]string{"gate", rep, "--block-at", blockAt, "--json-out", jsonOut, "--api", srv.URL},
					&stdout, &stderr)
				text := strings.ReplaceAll(stdout.String(), "CyberDetails SCA gate "+version+" ", "CyberDetails SCA gate VERSION ")
				got := "exit=" + string(rune('0'+code)) + "\n" + strings.ReplaceAll(text, srv.URL, goldenBase)
				if got != string(txtWant) {
					t.Errorf("text differs (stderr %q)\n%s", stderr.String(), firstDiff(got, string(txtWant)))
				}
				gotJSON, err := os.ReadFile(jsonOut)
				if err != nil {
					t.Fatal(err)
				}
				wantJSON, ok := golden(t, name+"."+blockAt+".json")
				if !ok {
					t.Fatal("golden JSON missing")
				}
				if g, w := normalise(t, gotJSON, srv.URL), normalise(t, wantJSON, goldenBase); !reflect.DeepEqual(g, w) {
					t.Errorf("--json-out differs: %s", jsonDiff(g, w))
				}
			})
		}
	}
	if n < 20 {
		t.Fatalf("only %d golden cases ran", n)
	}
}

func firstDiff(a, b string) string {
	al, bl := strings.Split(a, "\n"), strings.Split(b, "\n")
	for i := 0; i < len(al) || i < len(bl); i++ {
		var x, y string
		if i < len(al) {
			x = al[i]
		}
		if i < len(bl) {
			y = bl[i]
		}
		if x != y {
			return "line " + string(rune('0'+i%10)) + "…\n  go:     " + x + "\n  python: " + y
		}
	}
	return ""
}

func jsonDiff(g, w any) string {
	gm, _ := g.(map[string]any)
	wm, _ := w.(map[string]any)
	var keys []string
	for k := range wm {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if !reflect.DeepEqual(gm[k], wm[k]) {
			if k == "findings" {
				gl, _ := gm[k].([]any)
				wl, _ := wm[k].([]any)
				for i := range wl {
					if i >= len(gl) || !reflect.DeepEqual(gl[i], wl[i]) {
						gb, _ := json.Marshal(func() any {
							if i < len(gl) {
								return gl[i]
							}
							return nil
						}())
						wb, _ := json.Marshal(wl[i])
						return "findings[" + string(rune('0'+i%10)) + "]\n go:     " + string(gb) + "\n python: " + string(wb)
					}
				}
			}
			gb, _ := json.Marshal(gm[k])
			wb, _ := json.Marshal(wm[k])
			if len(gb) > 600 {
				gb = gb[:600]
			}
			if len(wb) > 600 {
				wb = wb[:600]
			}
			return k + "\n go:     " + string(gb) + "\n python: " + string(wb)
		}
	}
	return "?"
}

func TestGateExitCodes(t *testing.T) {
	srv, calls := triageServer(t)
	dir := t.TempDir()
	write := func(name, s string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	noCVE := write("nocve.json", `{"SchemaVersion":2,"Results":[{"Target":"x","Class":"lang-pkgs","Type":"npm",
		"Vulnerabilities":[{"VulnerabilityID":"GHSA-aaaa-bbbb-cccc","PkgName":"a","InstalledVersion":"1"}]}]}`)
	cases := []struct {
		name string
		args []string
		want int
	}{
		{"no CVE: pass without calling the API", []string{"gate", noCVE, "--api", srv.URL}, 0},
		{"missing file", []string{"gate", filepath.Join(dir, "nope.json"), "--api", srv.URL}, 2},
		{"not JSON", []string{"gate", write("bad.json", "{"), "--api", srv.URL}, 2},
		{"trailing data", []string{"gate", write("trail.json", `{"Results":[]} {}`), "--api", srv.URL}, 2},
		{"array", []string{"gate", write("arr.json", `[]`), "--api", srv.URL}, 2},
		{"unknown shape", []string{"gate", write("unk.json", `{"foo":1}`), "--api", srv.URL}, 2},
		{"malformed field", []string{"gate", write("mal.json", `{"Results":[{"Vulnerabilities":[{"PkgName":{"x":1}}]}]}`), "--api", srv.URL}, 2},
		{"not UTF-8", []string{"gate", write("lat.json", "{\"Results\":[],\"x\":\"\xff\"}"), "--api", srv.URL}, 2},
		{"plain http to a remote host", []string{"gate", noCVE, "--api", "http://example.com"}, 2},
		{"bad threshold", []string{"gate", noCVE, "--block-at", "low"}, 2},
		{"two reports", []string{"gate", noCVE, noCVE}, 2},
		{"BOM is accepted", []string{"gate", write("bom.json", "\xef\xbb\xbf{\"Results\":[]}"), "--api", srv.URL}, 0},
	}
	for _, c := range cases {
		var out, errb bytes.Buffer
		if got := run(c.args, &out, &errb); got != c.want {
			t.Errorf("%s: exit %d, want %d (stderr %q)", c.name, got, c.want, errb.String())
		}
	}
	if *calls != 0 {
		t.Errorf("API called %d time(s) although no report carried a CVE", *calls)
	}
}

func TestGateAPIOmissionIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		_, _ = w.Write([]byte(`{"items":[]}`))
	}))
	defer srv.Close()
	p := filepath.Join(t.TempDir(), "r.json")
	_ = os.WriteFile(p, []byte(`{"Results":[{"Target":"x","Vulnerabilities":[{"VulnerabilityID":"CVE-2021-44228","PkgName":"a"}]}]}`), 0o600)
	var out, errb bytes.Buffer
	if got := run([]string{"gate", p, "--api", srv.URL}, &out, &errb); got != 2 {
		t.Fatalf("exit %d, want 2", got)
	}
	if !strings.Contains(errb.String(), "omitted 1 CVE(s)") || !strings.Contains(errb.String(), "this is not a pass") {
		t.Errorf("stderr: %q", errb.String())
	}
}
