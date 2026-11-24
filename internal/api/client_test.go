package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cyberdetails/cdgate/internal/model"
)

func TestValidateBase(t *testing.T) {
	ok := map[string]string{
		"https://cyberdetails.org/":  "https://cyberdetails.org",
		"http://127.0.0.1:8765":      "http://127.0.0.1:8765",
		"http://localhost:3000/base": "http://localhost:3000/base",
		"http://[::1]:8000":          "http://[::1]:8000",
	}
	for in, want := range ok {
		got, err := ValidateBase(in)
		if err != nil || got != want {
			t.Fatalf("%s: got %q %v", in, got, err)
		}
	}
	for _, bad := range []string{"http://cyberdetails.org", "ftp://x", "https://u:p@cyberdetails.org", "nope", "http://10.0.0.1"} {
		if _, err := ValidateBase(bad); err == nil {
			t.Fatalf("%s must be rejected", bad)
		}
	}
}

func server(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	s := httptest.NewServer(h)
	t.Cleanup(s.Close)
	c, err := New(s.URL, "k-secret", "test")
	if err != nil {
		t.Fatal(err)
	}
	c.sleep = func(time.Duration) {}
	return c
}

func TestQuerySendsOnlyPackageFieldsAndKeyHeader(t *testing.T) {
	var body map[string]any
	var key string
	c := server(t, func(w http.ResponseWriter, r *http.Request) {
		key = r.Header.Get("CD-API-KEY")
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)
		w.Write([]byte(`{"packages":[{"ecosystem":"npm","name":"a","version":"1.0.0","status":"no_known_vulnerabilities","findings":[]}]}`))
	})
	_, err := c.Query([]model.Package{{Ecosystem: "npm", Name: "a", Version: "1.0.0", Source: "secret/path/package-lock.json"}}, "known_exploited", false)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(body)
	if strings.Contains(string(raw), "secret/path") || strings.Contains(string(raw), "source") {
		t.Fatalf("the file path left the machine: %s", raw)
	}
	if key != "k-secret" {
		t.Fatalf("API key header missing")
	}
}

func TestMissingPackageInAnswerIsAnError(t *testing.T) {
	c := server(t, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"packages":[]}`)) })
	if _, err := c.Query([]model.Package{{Ecosystem: "npm", Name: "a", Version: "1"}}, "never", false); err == nil {
		t.Fatal("an answer that omits a package must not pass")
	}
}

func TestRedirectIsRefused(t *testing.T) {
	c := server(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://evil.example/collect", http.StatusTemporaryRedirect)
	})
	if _, err := c.Query([]model.Package{{Ecosystem: "npm", Name: "a", Version: "1"}}, "never", false); err == nil {
		t.Fatal("a redirect must not be followed")
	}
}

func TestRetryOn503ThenSuccess(t *testing.T) {
	n := 0
	c := server(t, func(w http.ResponseWriter, r *http.Request) {
		n++
		if n == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(503)
			return
		}
		w.Write([]byte(`{"packages":[{"ecosystem":"npm","name":"a","version":"1","status":"no_known_vulnerabilities","findings":[]}]}`))
	})
	if _, err := c.Query([]model.Package{{Ecosystem: "npm", Name: "a", Version: "1"}}, "never", false); err != nil || n != 2 {
		t.Fatalf("expected one retry, got n=%d err=%v", n, err)
	}
}

func TestErrorsNeverCarryTheKey(t *testing.T) {
	c := server(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(422)
		w.Write([]byte(`{"detail":"item 0: unsupported ecosystem"}`))
	})
	_, err := c.Query([]model.Package{{Ecosystem: "x", Name: "a", Version: "1"}}, "never", false)
	if err == nil || strings.Contains(err.Error(), "k-secret") || !strings.Contains(err.Error(), "422") {
		t.Fatalf("got %v", err)
	}
}

// RPM packages travel with their architecture (Rocky's fixes differ per arch):
// the same name and version in two architectures are two queries, and each
// answer is joined back by architecture. Nothing else about the package is sent.
func TestRPMArchIsSentAndKeyed(t *testing.T) {
	var body struct {
		Packages []map[string]any `json:"packages"`
	}
	c := server(t, func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)
		w.Write([]byte(`{"packages":[
		{"ecosystem":"Rocky Linux:9","name":"glibc","version":"2.34-1.el9","arch":"x86_64","status":"vulnerable","findings":[]},
		{"ecosystem":"Rocky Linux:9","name":"glibc","version":"2.34-1.el9","arch":"i686","status":"no_known_vulnerabilities","findings":[]},
		{"ecosystem":"npm","name":"a","version":"1.0.0","arch":null,"status":"no_known_vulnerabilities","findings":[]}]}`))
	})
	pk := []model.Package{
		{Ecosystem: "Rocky Linux:9", Name: "glibc", Version: "2.34-1.el9", Arch: "x86_64", ModularityLabel: "m:1:2:3", SourcePackage: "glibc"},
		{Ecosystem: "Rocky Linux:9", Name: "glibc", Version: "2.34-1.el9", Arch: "i686"},
		{Ecosystem: "npm", Name: "a", Version: "1.0.0"},
	}
	res, err := c.Query(pk, "known_exploited", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(body.Packages) != 3 {
		t.Fatalf("sent %d packages, want 3", len(body.Packages))
	}
	for _, p := range body.Packages {
		for k := range p {
			if k != "ecosystem" && k != "name" && k != "version" && k != "arch" {
				t.Errorf("field %q left the machine", k)
			}
		}
		if p["ecosystem"] == "npm" {
			if _, ok := p["arch"]; ok {
				t.Error("a non-RPM package carries no arch")
			}
		}
	}
	if res[Key("Rocky Linux:9", "glibc", "2.34-1.el9", "x86_64")].Status != "vulnerable" ||
		res[Key("Rocky Linux:9", "glibc", "2.34-1.el9", "i686")].Status != "no_known_vulnerabilities" ||
		res[Key("npm", "a", "1.0.0", "")].Status != "no_known_vulnerabilities" {
		t.Errorf("answers not joined by arch: %v", res)
	}
}

// Red Hat build information travels with the package; an empty content set
// list stays present (build information exists); malformed values are dropped.
func TestRedHatBuildInfoSent(t *testing.T) {
	enc := func(p model.Package) map[string]any {
		b, _ := json.Marshal(queryPackage(p))
		var m map[string]any
		json.Unmarshal(b, &m)
		return m
	}
	m := enc(model.Package{Ecosystem: "Red Hat:8", Name: "bash", Version: "4.4-1", Arch: "x86_64",
		BuildInfo: &model.BuildInfo{ContentSets: []string{"rhel-8-for-x86_64-baseos-rpms", "bad name", "../x"},
			Nvr: "ubi8-container-8.1-408", Arch: "x86_64"}})
	if cs, _ := json.Marshal(m["content_sets"]); string(cs) != `["rhel-8-for-x86_64-baseos-rpms"]` ||
		m["nvr"] != "ubi8-container-8.1-408-x86_64" {
		t.Errorf("got %v", m)
	}
	m = enc(model.Package{Ecosystem: "CentOS:7", Name: "bash", Version: "1", BuildInfo: &model.BuildInfo{Nvr: "a b", Arch: "x"}})
	if cs, ok := m["content_sets"]; !ok || cs == nil || len(cs.([]any)) != 0 || m["nvr"] != nil {
		t.Errorf("empty content sets must be sent, bad NVR dropped: %v", m)
	}
	if m = enc(model.Package{Ecosystem: "Red Hat:9", Name: "bash", Version: "1"}); m["content_sets"] != nil || m["nvr"] != nil {
		t.Errorf("no build information: %v", m)
	}
	if m = enc(model.Package{Ecosystem: "Rocky Linux:9", Name: "bash", Version: "1",
		BuildInfo: &model.BuildInfo{ContentSets: []string{"x"}}}); m["content_sets"] != nil {
		t.Errorf("only Red Hat and CentOS send build information: %v", m)
	}
}

func TestKeyValidation(t *testing.T) {
	for _, bad := range []string{"CD-abc\r\nX-Evil: 1", "CD-" + strings.Repeat("a", 300), "CD-ab c", "CD-é"} {
		_, err := New("https://cyberdetails.org", bad, "t")
		if err == nil || strings.Contains(err.Error(), "CD-ab") {
			t.Errorf("%q: %v", bad, err)
		}
	}
	c, err := New("https://cyberdetails.org", " CD-abcdefghijk123 ", "t")
	if err != nil || c.key != "CD-abcdefghijk123" {
		t.Errorf("%v %+v", err, c)
	}
	if c, err := New("https://cyberdetails.org", "", "t"); err != nil || c.key != "" {
		t.Error("anonymous")
	}
}
