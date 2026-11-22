package langpkg

import (
	"bufio"
	"encoding/json"
	"os"
	"reflect"
	"runtime/debug"
	"strconv"
	"strings"
	"testing"
)

// TestLdflagsAgainstOracle compares the -ldflags reader with
// testdata/ldflags_oracle.tsv, produced by ldflags_oracle.go.txt: Trivy's
// ParseLDFlags code with the real go-shellwords v1.0.16, pflag v1.0.10 and
// x/mod v0.42.0, over real ldflags from images, hand-written edge cases and
// 16k generated strings. Columns: Go-quoted input, version, -X map JSON
// (or ERR when Trivy's parse failed).
//
// Where shellSplit refuses shell syntax (` ( ) ; & | < >) the version must be
// "": never a version Trivy would not report.
func TestLdflagsAgainstOracle(t *testing.T) {
	f, err := os.Open("testdata/ldflags_oracle.tsv")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 1<<20), 1<<20)
	n, refused, versions := 0, 0, 0
	for s.Scan() {
		cols := strings.SplitN(s.Text(), "\t", 3)
		in, err := strconv.Unquote(cols[0])
		if err != nil {
			t.Fatalf("line %d: %v", n+1, err)
		}
		n++
		wantVer, wantMap := cols[1], cols[2]
		got := ldflagsVersion("github.com/example/app", []debug.BuildSetting{{Key: "-ldflags", Value: in}})
		args, serr := shellSplit(in)
		if serr == errUnsupportedShell {
			refused++
			if got != "" {
				t.Errorf("%q: refused input produced version %q", in, got)
			}
			continue
		}
		if got != wantVer {
			t.Errorf("%q: version %q, oracle %q", in, got, wantVer)
		}
		if wantVer != "" {
			versions++
		}
		var x map[string]string
		if serr == nil {
			x, serr = xFlags(args)
		}
		if (serr != nil) != (wantMap == "ERR") {
			t.Errorf("%q: error %v, oracle %s", in, serr, wantMap)
			continue
		}
		if serr == nil {
			var want map[string]string
			if err := json.Unmarshal([]byte(wantMap), &want); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(x, want) {
				t.Errorf("%q: -X map %v, oracle %v", in, x, want)
			}
		}
	}
	if n < 16000 || versions < 2000 {
		t.Fatalf("golden file too small: %d lines, %d with a version", n, versions)
	}
	t.Logf("%d inputs, %d with a version, %d refused (shell syntax)", n, versions, refused)
}

func TestSemverAndPseudo(t *testing.T) {
	for v, want := range map[string]bool{
		"v1": true, "v1.2": true, "v1.2.3": true, "v1.2.3-rc.1+b.5": true, "v1.2-pre": false, "1.2.3": false,
		"v01.2.3": false, "v1.2.3-01": false, "v1.2.3-0a": true, "v1.2.3+": false, "v1.2.3-": false,
		"v1.2.3-a..b": false, "v1.2.3+01": true, "v": false, "": false, "v1.2.3.4": false,
	} {
		if semverValid(v) != want {
			t.Errorf("semverValid(%q) = %v", v, !want)
		}
	}
	for v, want := range map[string]bool{
		"v0.0.0-20230101120000-abcdef123456": true, "v1.2.4-0.20230101120000-abcdef123456": true,
		"v1.2.3-pre.0.20230101120000-abcdef123456": true, "v1.2.3": false, "v0.0.0-2023-abc": false,
	} {
		if isPseudoVersion(v) != want {
			t.Errorf("isPseudoVersion(%q) = %v", v, !want)
		}
	}
	cases := []struct{ v, l, e, want string }{
		{"v1.0.0", "v2.0.0", "", "v1.0.0"},
		{"v0.0.0-20230101120000-abcdef123456", "2.45.0", "", "2.45.0"},
		{"v0.0.0-20230101120000-abcdef123456", "", "3.0.0", "3.0.0"},
		{"v0.0.0-20230101120000-abcdef123456", "", "", "v0.0.0-20230101120000-abcdef123456"},
		{"", "", "", ""},
		{"", "", "1.0.0", "1.0.0"},
		{"", "2.0.0", "3.0.0", "2.0.0"}, // -ldflags before ELF symbols
		{"v0.0.0-20230101120000-abcdef123456", "2.0.0", "3.0.0", "2.0.0"},
	}
	for _, c := range cases {
		if got := chooseMainVersion(c.v, c.l, c.e); got != c.want {
			t.Errorf("chooseMainVersion(%q,%q,%q) = %q", c.v, c.l, c.e, got)
		}
	}
}
