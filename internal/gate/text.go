package gate

import (
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"
)

var labels = map[string]string{"known_exploited": "known exploited", "high": "high", "standard": "standard",
	"not_in_database": "not in archive", "no_cve": "without CVE"}

const (
	maxReview = 10 // REVIEW rows printed; the rest is in --json-out
	maxPlan   = 5  // NEXT rows printed
)

// short is Python's _kisa: cut to n characters with an ellipsis.
func short(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n-1]) + "…"
}

// pad is Python's f"{s:<n}".
func pad(s string, n int) string {
	if c := utf8.RuneCountInString(s); c < n {
		return s + strings.Repeat(" ", n-c)
	}
	return s
}

type group struct {
	id       string
	findings []Finding
}

// cveGroups puts findings of the same CVE together, in first-seen order. A
// distribution image builds several binary packages from one source
// (libc-bin + libc6); one row per package repeated the same CVE.
func cveGroups(list []Finding) []group {
	var out []group
	idx := map[string]int{}
	for _, f := range list {
		i, ok := idx[f.key()]
		if !ok {
			i = len(out)
			idx[f.key()] = i
			out = append(out, group{id: f.key()})
		}
		out[i].findings = append(out[i].findings, f)
	}
	return out
}

func groupLines(g group) []string {
	r := g.findings[0]
	reason := ""
	if len(r.Reasons) > 0 {
		reason = r.Reasons[0]
	}
	out := []string{fmt.Sprintf("  %s %s", pad(g.id, 17), short(reason, 96))}
	type iv struct{ installed, fixed string }
	var order []iv
	pkgs := map[iv][]string{}
	for _, b := range g.findings {
		k := iv{b.Installed, b.Fixed}
		if _, ok := pkgs[k]; !ok {
			order = append(order, k)
			pkgs[k] = []string{}
		}
		dup := false
		for _, n := range pkgs[k] {
			dup = dup || n == b.Package
		}
		if !dup {
			pkgs[k] = append(pkgs[k], b.Package)
		}
	}
	for _, k := range order {
		names := pkgs[k]
		shown := names
		if len(shown) > 4 {
			shown = shown[:4]
		}
		s := strings.Join(shown, ", ")
		if len(names) > 4 {
			s += fmt.Sprintf(" +%d", len(names)-4)
		}
		target := "(no fix listed)"
		if k.fixed != "" {
			target = "-> " + k.fixed
		}
		out = append(out, fmt.Sprintf("      %s %s %s", short(s, 70), short(k.installed, 30), short(target, 50)))
	}
	if r.URL != nil {
		out = append(out, "      "+*r.URL)
	}
	if m := r.Mitigation; m != nil {
		if d := m.Detection; d != nil {
			names := make([]string, len(d.Formats))
			for i, f := range d.Formats {
				names[i] = FormatNames[f]
			}
			out = append(out, fmt.Sprintf("      detect: SIEM queries (%s) %s", strings.Join(names, ", "), d.URL))
		}
		// A workaround only for a blocked CVE where NO package has a fix: when
		// a fix exists, the answer is the upgrade.
		anyFix := false
		for _, b := range g.findings {
			anyFix = anyFix || b.Fixed != ""
		}
		if r.Blocked && len(m.Workarounds) > 0 && !anyFix {
			out = append(out, "      no fixed version yet; if you cannot patch (AI-written, verify):")
			for _, w := range m.Workarounds {
				out = append(out, "        - "+short(w, 110))
			}
		}
	}
	return out
}

func planLine(x Entry) string {
	shown := x.Packages
	if len(shown) > 3 {
		shown = shown[:3]
	}
	names := strings.Join(shown, ", ")
	if len(x.Packages) > 3 {
		names += fmt.Sprintf(" +%d", len(x.Packages)-3)
	}
	if !x.OSPackage && x.Target != "" {
		names += " (" + x.Target + ")"
	}
	var target string
	if x.UpgradeTo != nil && *x.UpgradeTo != "" {
		target = "-> " + *x.UpgradeTo
		if x.UpgradeToAll != nil && *x.UpgradeToAll != "" {
			target += " (all listed fixes: " + *x.UpgradeToAll + ")"
		}
	} else {
		c := x.Candidates
		if len(c) > 4 {
			c = c[:4]
		}
		target = "-> one of " + strings.Join(c, ", ") + " (check)"
	}
	var parts []string
	if n := len(x.BlockedCVEs); n > 0 {
		parts = append(parts, fmt.Sprintf("%d blocked", n))
	}
	if n := len(x.HighCVEs); n > 0 {
		parts = append(parts, fmt.Sprintf("%d high", n))
	}
	if x.OtherFixable > 0 {
		parts = append(parts, fmt.Sprintf("+%d other", x.OtherFixable))
	}
	return fmt.Sprintf("  %s %s %s   %s", pad(short(names, 46), 46), short(x.Installed, 26), short(target, 60),
		strings.Join(parts, ", "))
}

func planText(p Plan) []string {
	var lines []string
	var blocked, high, other []Entry
	for _, x := range p.Entries {
		switch x.Tier {
		case "blocked":
			blocked = append(blocked, x)
		case "high":
			high = append(high, x)
		default:
			other = append(other, x)
		}
	}
	if len(blocked) > 0 {
		n, k := p.BlockedCVEs, p.BlockedCVEsFixable
		if k >= n {
			lines = append(lines, fmt.Sprintf("FIX PLAN — %d upgrade(s) clear all %d blocked CVE(s)", len(blocked), n))
		} else {
			lines = append(lines, fmt.Sprintf("FIX PLAN — %d upgrade(s) clear %d of %d blocked CVE(s)", len(blocked), k, n))
		}
		for _, x := range blocked {
			lines = append(lines, planLine(x))
		}
		for _, c := range p.Commands.Blocked {
			lines = append(lines, "  run: "+c)
		}
	}
	if nf := p.BlockedWithoutFix; len(nf) > 0 {
		shown := nf
		if len(shown) > 5 {
			shown = shown[:5]
		}
		s := fmt.Sprintf("  %d blocked CVE(s) have a package with no fixed version yet: %s", len(nf), strings.Join(shown, ", "))
		if len(nf) > 5 {
			s += " …"
		}
		lines = append(lines, s)
	}
	if len(high) > 0 {
		cves := map[string]bool{}
		for _, x := range high {
			for _, c := range x.HighCVEs {
				cves[c] = true
			}
		}
		head := "FIX PLAN"
		if len(blocked) > 0 {
			head = "NEXT"
		}
		s := fmt.Sprintf("%s — %d upgrade(s) fix %d high-signal CVE(s)", head, len(high), len(cves))
		if len(high) > maxPlan {
			s += fmt.Sprintf(" (top %d)", maxPlan)
		}
		lines = append(lines, s)
		for i, x := range high {
			if i == maxPlan {
				break
			}
			lines = append(lines, planLine(x))
		}
		label := "  run: "
		if len(blocked) > 0 {
			label = "  run (blocked + high): "
		}
		for _, c := range p.Commands.BlockedAndHigh {
			lines = append(lines, label+c)
		}
	}
	if len(other) > 0 {
		sum := 0
		for _, x := range other {
			sum += x.OtherFixable
		}
		lines = append(lines, fmt.Sprintf("  + %d more upgrade(s) fix %d other finding(s); full plan in --json-out.", len(other), sum))
	}
	if len(lines) > 0 {
		lines = append(lines, "")
	}
	return lines
}

// counter counts keys and returns them in first-seen order (Python dict).
type counter struct {
	order []string
	n     map[string]int
}

func (c *counter) add(k string) {
	if c.n == nil {
		c.n = map[string]int{}
	}
	if _, ok := c.n[k]; !ok {
		c.order = append(c.order, k)
	}
	c.n[k]++
}

// sorted returns the keys stably sorted by rank (unknown keys last).
func (c *counter) sorted(rankOf func(string) int) []string {
	out := append([]string(nil), c.order...)
	sort.SliceStable(out, func(i, j int) bool { return rankOf(out[i]) < rankOf(out[j]) })
	return out
}

var severityRank = map[string]int{"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}

// Text is the human summary. One CVE once; the full list is in --json-out.
func Text(findings []Finding, tool, version, blockAt string, plan Plan, meta Meta) string {
	var urg, sev counter
	cves := map[string]bool{}
	var blocked []Finding
	for _, r := range findings {
		urg.add(r.Urgency)
		s := r.ScannerSeverity
		if s == "" {
			s = "UNKNOWN"
		}
		// Python str.upper(); severities are Trivy/Grype enums (ASCII), where
		// strings.ToUpper agrees with it.
		sev.add(strings.ToUpper(s))
		if r.CVE != nil {
			cves[*r.CVE] = true
		}
		if r.Blocked {
			blocked = append(blocked, r)
		}
	}
	lines := []string{fmt.Sprintf("CyberDetails SCA gate %s — %s: %d finding(s), %d distinct CVE(s); block at: %s",
		version, tool, len(findings), len(cves), blockAt)}
	if len(sev.order) > 0 {
		var parts []string
		for _, k := range sev.sorted(func(k string) int { return rank(severityRank, k, 9) }) {
			parts = append(parts, fmt.Sprintf("%d %s", sev.n[k], k))
		}
		lines = append(lines, "  scanner severity: "+strings.Join(parts, ", "))
	}
	var parts []string
	for _, k := range urg.sorted(func(k string) int { return rank(urgencyRank, k, 9) }) {
		l, ok := labels[k]
		if !ok {
			l = k
		}
		parts = append(parts, fmt.Sprintf("%d %s", urg.n[k], l))
	}
	lines = append(lines, "  exploitation:     "+strings.Join(parts, ", "))
	if meta.OS != nil && *meta.OS != "" {
		s := "  base OS:          " + *meta.OS
		if meta.EOSL != nil && *meta.EOSL {
			s += " — END OF LIFE: the distribution no longer ships security fixes; rebuild on a supported base image"
		}
		lines = append(lines, s)
	}
	lines = append(lines, "")

	if len(blocked) > 0 {
		groups := cveGroups(blocked)
		lines = append(lines, fmt.Sprintf("BLOCKED — %d CVE(s), %d finding(s)", len(groups), len(blocked)))
		for _, g := range groups {
			lines = append(lines, groupLines(g)...)
		}
		lines = append(lines, "")
	}

	var strong []Finding
	for _, r := range findings {
		if !r.Blocked && (r.Urgency == "known_exploited" || r.Urgency == "high") {
			strong = append(strong, r)
		}
	}
	if review := cveGroups(strong); len(review) > 0 {
		s := fmt.Sprintf("REVIEW — %d CVE(s) with strong signals, not blocking at this threshold", len(review))
		if len(review) > maxReview {
			s += fmt.Sprintf(" (top %d)", maxReview)
		}
		lines = append(lines, s)
		for i, g := range review {
			if i == maxReview {
				break
			}
			lines = append(lines, groupLines(g)...)
		}
		lines = append(lines, "")
	}

	lines = append(lines, planText(plan)...)

	if n := urg.n["not_in_database"]; n > 0 {
		lines = append(lines, fmt.Sprintf("NOTE — %d finding(s) have no CyberDetails record. They are NOT judged safe; use --block-unknown to fail on them.", n))
	}
	if n := urg.n["no_cve"]; n > 0 {
		lines = append(lines, fmt.Sprintf("NOTE — %d finding(s) have no CVE identifier (e.g. GHSA-only) and were not sent.", n))
	}
	lines = append(lines, "Version matching comes from the scanner; CyberDetails ranks by exploitation evidence.")
	if len(blocked) > 0 {
		lines = append(lines, fmt.Sprintf("RESULT: FAIL (%d blocked)", len(blocked)))
	} else {
		lines = append(lines, "RESULT: PASS")
	}
	return strings.Join(lines, "\n")
}

// Blocked reports whether any finding fails the build.
func Blocked(findings []Finding) bool {
	for _, f := range findings {
		if f.Blocked {
			return true
		}
	}
	return false
}
