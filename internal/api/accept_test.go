package api

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/cyberdetails/cdgate/internal/model"
)

// The API generates the fixture from its own model; the client must decide
// every case the same way (a refused package would 422 the whole request).
func TestRejectedMatchesAPIModel(t *testing.T) {
	// In the CyberDetails repository the fixture lives beside the other clients'
	// fixtures; the standalone cdgate repository carries a copy in testdata/
	// (written by export_cdgate.py).
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "tests", "fixtures", "api_accepts.json"))
	if os.IsNotExist(err) {
		b, err = os.ReadFile(filepath.Join("testdata", "api_accepts.json"))
	}
	if err != nil {
		t.Fatal(err)
	}
	var fx struct {
		Cases []struct {
			Name     string `json:"name"`
			Version  string `json:"version"`
			Accepted bool   `json:"accepted"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(b, &fx); err != nil || len(fx.Cases) < 40 {
		t.Fatalf("fixture: %v (%d cases)", err, len(fx.Cases))
	}
	for _, c := range fx.Cases {
		got := Rejected(model.Package{Ecosystem: "npm", Name: c.Name, Version: c.Version}) == ""
		if got != c.Accepted {
			t.Errorf("%q %q: client accepts=%v, API accepts=%v", c.Name, c.Version, got, c.Accepted)
		}
	}
	// RapidFort binaries go through the same name rule.
	p := model.Package{Ecosystem: "RapidFort:Ubuntu:22.04", Name: "openssl", Version: "3.0.2-0ubuntu1.10", Binaries: []string{"libssl3", "€"}}
	if Rejected(p) != NameNotAccepted {
		t.Error("a refused RapidFort binary name must keep the package out of the request")
	}
	p.Binaries = []string{"libssl3"}
	if Rejected(p) != "" {
		t.Error("valid RapidFort row")
	}
}
