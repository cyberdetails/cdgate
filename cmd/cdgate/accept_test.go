package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A lockfile entry the API would refuse (a name with "€") must not reach the
// request: one refused item 422s the whole batch. It is listed as not checked,
// the other packages are still queried, and the result is INCOMPLETE.
func TestRefusedPackageIsUncheckedNotSent(t *testing.T) {
	dir := t.TempDir()
	lock := `{"name":"app","lockfileVersion":3,"packages":{"":{"name":"app"},` +
		`"node_modules/lodash":{"version":"4.17.21"},"node_modules/€uro":{"version":"1.0.0"}}}`
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(b))
		var req struct {
			Packages []struct{ Ecosystem, Name, Version string } `json:"packages"`
		}
		_ = json.Unmarshal(b, &req)
		out := []map[string]any{}
		for _, p := range req.Packages {
			out = append(out, map[string]any{"ecosystem": p.Ecosystem, "name": p.Name, "version": p.Version,
				"arch": nil, "status": "no_known_vulnerabilities", "findings": []any{}})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"packages": out})
	}))
	defer srv.Close()
	var out, errb bytes.Buffer
	code := run([]string{"scan", dir, "--api", srv.URL}, &out, &errb)
	if code != 2 {
		t.Fatalf("exit %d\n%s\n%s", code, out.String(), errb.String())
	}
	if len(bodies) != 1 || strings.Contains(bodies[0], "uro") || !strings.Contains(bodies[0], `"lodash"`) {
		t.Errorf("request bodies: %q", bodies)
	}
	if !strings.Contains(out.String(), "RESULT: INCOMPLETE") || !strings.Contains(out.String(), "does not accept") {
		t.Errorf("report:\n%s", out.String())
	}

	// Every package refused: no request at all, still INCOMPLETE (never PASS).
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(
		`{"name":"app","lockfileVersion":3,"packages":{"":{"name":"app"},"node_modules/€uro":{"version":"1.0.0"}}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	bodies, out = nil, bytes.Buffer{}
	if code := run([]string{"scan", dir, "--api", srv.URL}, &out, &errb); code != 2 || len(bodies) != 0 ||
		!strings.Contains(out.String(), "RESULT: INCOMPLETE") {
		t.Errorf("exit %d, %d request(s):\n%s", code, len(bodies), out.String())
	}
}
