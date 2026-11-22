package parse

import (
	"bufio"
	"os"
	"strings"
	"testing"
)

// testdata/npmrange_node.tsv: (version, range, node-semver 7.6.3 result) from
// the lab corpus (React and Yarn lockfiles, npm CLI and Vite manifests),
// generated 2026-11-18. "ERR" = node-semver rejects the range or version.
func TestNpmSatisfiesMatchesNodeSemver(t *testing.T) {
	f, err := os.Open("testdata/npmrange_node.tsv")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	n, bad := 0, 0
	for s.Scan() {
		p := strings.Split(s.Text(), "\t")
		if len(p) != 3 || p[2] == "ERR" {
			continue
		}
		n++
		got, valid := npmSatisfies(p[0], p[1])
		want := p[2] == "1"
		if !valid || got != want {
			bad++
			if bad <= 15 {
				t.Errorf("satisfies(%q, %q) = %v (valid=%v), node-semver says %v", p[0], p[1], got, valid, want)
			}
		}
	}
	if n < 1000 {
		t.Fatalf("too few reference rows: %d", n)
	}
	if bad > 0 {
		t.Fatalf("%d of %d rows differ from node-semver", bad, n)
	}
}

func TestNpmSatisfiesEdgeCases(t *testing.T) {
	cases := []struct {
		v, r string
		want bool
	}{
		{"1.2.3", "^1.2.3", true}, {"2.0.0", "^1.2.3", false}, {"0.2.5", "^0.2.3", true},
		{"0.3.0", "^0.2.3", false}, {"0.0.4", "^0.0.3", false}, {"1.3.0", "~1.2.3", false},
		{"1.2.9", "~1.2", true}, {"1.9.9", "1.x", true}, {"2.0.0", "1.x", false},
		{"1.2.3-beta.1", "^1.2.3-beta.0", true}, {"1.2.4-beta.1", "^1.2.3", false},
		{"1.5.0", "1.0.0 - 2.0.0", true}, {"2.0.1", "1.0.0 - 2.0.0", false},
		{"3.0.0", "<2 || >=3", true}, {"1.0.0", "*", true}, {"1.0.0", "", true},
	}
	for _, c := range cases {
		if got, ok := npmSatisfies(c.v, c.r); !ok || got != c.want {
			t.Errorf("satisfies(%q, %q) = %v ok=%v, want %v", c.v, c.r, got, ok, c.want)
		}
	}
}
