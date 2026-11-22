package gate

import (
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/ferhatcil/cdgate/internal/api"
)

// A link from the server may only point at the site's own pages (the
// canonical /cve/CVE-... page, a /exploit/<slug> record or its pack.zip);
// anything else is never printed as a clickable link in a CI log.
var sitePath = regexp.MustCompile(`^/(cve/CVE-[0-9]{4}-[0-9]{4,7}|exploit/[A-Za-z0-9._-]{1,300}(/pack\.zip)?)$`)

// FormatNames maps the query formats the server may report to display
// names. Unknown formats are dropped.
var FormatNames = map[string]string{"sigma": "Sigma", "splunk_spl": "Splunk SPL",
	"sentinel_kql": "Sentinel KQL", "elastic_eql": "Elastic EQL", "google_secops_yaral": "YARA-L"}

var urgencyRank = map[string]int{"known_exploited": 0, "high": 1, "standard": 2, "not_in_database": 3, "no_cve": 4}

func rank(m map[string]int, k string, def int) int {
	if v, ok := m[k]; ok {
		return v
	}
	return def
}

// flatText mirrors _duz_metin: server text -> one printable line. Control
// characters (ANSI escapes) and format characters (bidi overrides) are
// dropped, whitespace is collapsed, the result is cut to n characters with an
// ellipsis. Workarounds are model text whose source is scraped content; the
// server cleans it too, this is the second layer.
func flatText(s string, n int) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '\t' || r == '\n' || r == '\r':
			b.WriteByte(' ')
		case unicode.In(r, unicode.Cc, unicode.Cf, unicode.Zl, unicode.Zp):
		default:
			b.WriteRune(r)
		}
	}
	t := strings.Join(strings.FieldsFunc(b.String(), pyIsSpace), " ")
	if utf8.RuneCountInString(t) <= n {
		return t
	}
	return strings.TrimRightFunc(string([]rune(t)[:n-1]), pyIsSpace) + "…"
}

func mitigation(m *api.Mitigation, base string) *Mitigation {
	if m == nil {
		return nil
	}
	out := &Mitigation{Workarounds: []string{}}
	if d := m.Detection; d != nil {
		formats := []string{}
		for _, f := range d.Formats {
			if _, ok := FormatNames[f]; ok {
				formats = append(formats, f)
			}
		}
		if sitePath.MatchString(d.Path) && len(formats) > 0 {
			det := &Detection{URL: base + d.Path, Formats: formats}
			if sitePath.MatchString(d.PackPath) {
				u := base + d.PackPath
				det.PackURL = &u
			}
			out.Detection = det
		}
	}
	for i, w := range m.Workarounds {
		if i == 3 {
			break
		}
		if t := flatText(w, 200); t != "" {
			out.Workarounds = append(out.Workarounds, t)
		}
	}
	out.WorkaroundsAIGenerated = len(out.Workarounds) > 0
	return out
}

// Join merges each finding with the server's verdict. A finding without a
// CVE is "no_cve" and never blocks.
func Join(findings []Finding, items map[string]api.TriageItem, base string) []Finding {
	out := make([]Finding, 0, len(findings))
	for _, f := range findings {
		var it api.TriageItem
		ok := false
		if f.CVE != nil {
			it, ok = items[*f.CVE]
		}
		if !ok {
			f.Urgency, f.Blocked = "no_cve", false
			f.Reasons = []string{"No CVE identifier; not triaged by CyberDetails."}
			f.URL, f.Signals, f.Mitigation = nil, nil, nil
			out = append(out, f)
			continue
		}
		f.Urgency, f.Blocked = it.Urgency, it.Blocked
		f.Reasons = []string{}
		for i, r := range it.Reasons {
			if i == 10 {
				break
			}
			if t := flatText(r, 300); t != "" {
				f.Reasons = append(f.Reasons, t)
			}
		}
		f.URL = nil
		if it.Path != nil && sitePath.MatchString(*it.Path) {
			u := base + *it.Path
			f.URL = &u
		}
		f.Signals = it.Signals
		f.Mitigation = mitigation(it.Mitigation, base)
		out = append(out, f)
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Blocked != b.Blocked {
			return a.Blocked
		}
		if ra, rb := rank(urgencyRank, a.Urgency, 9), rank(urgencyRank, b.Urgency, 9); ra != rb {
			return ra < rb
		}
		if a.key() != b.key() {
			return a.key() < b.key()
		}
		return a.Package < b.Package
	})
	return out
}
