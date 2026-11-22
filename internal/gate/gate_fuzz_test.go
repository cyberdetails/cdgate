package gate

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzParse: an untrusted report must never panic the gate, and every path
// through Parse, Join, BuildPlan and Text must terminate.
func FuzzParse(f *testing.F) {
	seeds, _ := filepath.Glob("../../cmd/cdgate/testdata/gate/*.report.json")
	for _, s := range seeds {
		if data, err := os.ReadFile(s); err == nil && len(data) < 64<<10 {
			f.Add(data)
		}
	}
	f.Add([]byte(`{"matches":[{"vulnerability":{"id":"CVE-2021-44228","fix":{"versions":["1",2,null,true]}},"artifact":{"name":"a","version":"1:2-3","type":"deb","locations":[{"path":"x"}]}}]}`))
	f.Add([]byte(`{"Results":[{"Class":"os-pkgs","Type":"debian","Vulnerabilities":[{"VulnerabilityID":"CVE-2021-0001","PkgName":"a","InstalledVersion":"1:","FixedVersion":"~,=,>=, ,0:0-0"}]}]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		tool, findings, meta, err := Parse(data)
		if err != nil {
			return
		}
		results := Join(findings, nil, "https://cyberdetails.org")
		_ = Text(results, tool, "fuzz", "known_exploited", BuildPlan(results), meta)
	})
}
