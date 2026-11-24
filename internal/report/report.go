// Package report turns API answers into terminal output, JSON and an exit code.
//
// Every string that came from the server or from a scanned file passes
// through sanitize.Text before it is printed. A link is printed only if it
// points to the CyberDetails site itself or to a GitHub advisory.
package report

import (
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"

	"github.com/cyberdetails/cdgate/internal/api"
	"github.com/cyberdetails/cdgate/internal/model"
	"github.com/cyberdetails/cdgate/internal/sanitize"
	"github.com/cyberdetails/cdgate/internal/scan"
)

// Exit codes: three distinct states, never mixed.
const (
	ExitPass    = 0 // policy passed
	ExitBlocked = 1 // at least one finding is blocked
	ExitError   = 2 // the tool could not run (unreadable input, API unreachable)
)

var (
	sitePath = regexp.MustCompile(`^/(cve/CVE-\d{4}-\d{4,7}|exploit/[A-Za-z0-9._-]{1,300}(/pack\.zip)?)$`)
	ghsaURL  = regexp.MustCompile(`^https://github\.com/advisories/GHSA(-[23456789cfghjmpqrvwx]{4}){3}$`)
)

// Link returns a safe absolute link or "".
func Link(base string, path, advisory *string) string {
	if path != nil && sitePath.MatchString(*path) {
		return base + *path
	}
	if advisory != nil && ghsaURL.MatchString(*advisory) {
		return *advisory
	}
	return ""
}

// Row is one package with its findings, joined with where it was found.
type Row struct {
	Package model.Package     `json:"package"`
	Sources []string          `json:"sources"`
	Result  api.PackageResult `json:"result"`
}

// Join groups the scanned packages by identity and attaches the API answer.
func Join(pkgs []model.Package, results map[string]api.PackageResult) []Row {
	idx := map[string]int{}
	var rows []Row
	for _, p := range pkgs {
		k := api.Key(p.Ecosystem, p.Name, p.Version, p.Arch)
		if i, ok := idx[k]; ok {
			if !contains(rows[i].Sources, p.Source) {
				rows[i].Sources = append(rows[i].Sources, p.Source)
			}
			continue
		}
		idx[k] = len(rows)
		rows = append(rows, Row{Package: p, Sources: []string{p.Source}, Result: results[k]})
	}
	return rows
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

// Blocked counts blocked findings.
func Blocked(rows []Row) int {
	n := 0
	for _, r := range rows {
		for _, f := range r.Result.Findings {
			if f.Blocked {
				n++
			}
		}
	}
	return n
}

// NotChecked are the rows the server could not check (status "not_checked":
// Red Hat content sets that map to no product). Never a clean result.
func NotChecked(rows []Row) []Row {
	var out []Row
	for _, r := range rows {
		if r.Result.Status == "not_checked" {
			out = append(out, r)
		}
	}
	return out
}

// Incomplete is the number of packages that were found but not checked.
func Incomplete(res *scan.Result, rows []Row) int { return len(res.Unchecked) + len(NotChecked(rows)) }

var urgencyLabel = map[string]string{
	"malicious_package": "malicious package", "known_exploited": "known exploited",
	"high": "high", "standard": "standard", "not_in_database": "not in archive",
}

var formatName = map[string]string{
	"sigma": "Sigma", "splunk_spl": "Splunk SPL", "sentinel_kql": "Sentinel KQL",
	"elastic_eql": "Elastic EQL", "google_secops_yaral": "YARA-L",
}

const maxReview = 10

// Text writes the human report.
func Text(w io.Writer, version, base, blockAt string, res *scan.Result, rows []Row) {
	t := func(s string, n int) string { return sanitize.Text(s, n) }
	counts := map[string]int{}
	unverified := 0
	for _, r := range rows {
		for _, f := range r.Result.Findings {
			if f.Match == "unverified" {
				unverified++
			} else {
				counts[f.Urgency]++
			}
		}
	}
	what := "scan"
	switch {
	case res.Image != "":
		what = "image " + t(res.Image, 120)
	case res.SBOM:
		what = "sbom"
	case res.RootFS:
		what = "rootfs " + t(res.Root, 120)
	}
	fmt.Fprintf(w, "cdgate %s — %s: %d package(s) from %d file(s); block at: %s\n",
		version, what, len(rows), len(res.Files), blockAt)
	if res.OS != nil {
		fmt.Fprintf(w, "  operating system: %s %s\n", t(res.OS.Family, 20), t(res.OS.Name, 40))
	}
	for _, f := range res.Files {
		line := fmt.Sprintf("  %s (%s, %d)", t(f.Path, 200), f.Ecosystem, f.Packages)
		if f.Error != "" {
			line += " — NOT READ: " + t(f.Error, 200)
		}
		fmt.Fprintln(w, line)
	}
	for _, f := range res.Unsupported {
		fmt.Fprintf(w, "  %s — not analysed: %s\n", t(f.Path, 200), t(f.Error, 200))
	}
	if res.Truncated {
		fmt.Fprintf(w, "  WARNING: stopped after %d directory entries; the scan is incomplete\n", scan.MaxEntries)
	}
	var parts []string
	for _, u := range []string{"malicious_package", "known_exploited", "high", "standard", "not_in_database"} {
		if counts[u] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[u], urgencyLabel[u]))
		}
	}
	if unverified > 0 {
		parts = append(parts, fmt.Sprintf("%d unverified", unverified))
	}
	if len(parts) == 0 {
		parts = []string{"no known vulnerabilities"}
		if Incomplete(res, rows) > 0 {
			parts = []string{"none among the packages that were checked"}
		}
	}
	fmt.Fprintf(w, "  findings: %s\n", strings.Join(parts, ", "))
	reasons := map[string]int{}
	var order []string
	for _, p := range res.Unchecked {
		why := p.UncheckedReason
		if why == "" {
			why = "CyberDetails has no advisories for " + p.Ecosystem + " yet"
		}
		if reasons[why] == 0 {
			order = append(order, why)
		}
		reasons[why]++
	}
	for _, why := range order {
		fmt.Fprintf(w, "  NOT CHECKED: %d package(s): %s.\n", reasons[why], t(why, 200))
	}
	// The server's reasons, grouped like the local ones: a source not used
	// for licensing reasons and an advisory set that could not be selected are
	// different things and both must be visible.
	serverWhy := map[string]int{}
	var serverOrder []string
	for _, r := range NotChecked(rows) {
		why := strings.TrimSuffix(strings.TrimSpace(r.Result.NotCheckedReason), ".")
		if why == "" {
			why = "the server could not select their advisories"
		}
		if serverWhy[why] == 0 {
			serverOrder = append(serverOrder, why)
		}
		serverWhy[why]++
	}
	for _, why := range serverOrder {
		fmt.Fprintf(w, "  NOT CHECKED: %d package(s): %s.\n", serverWhy[why], t(why, 200))
	}
	if Incomplete(res, rows) > 0 {
		fmt.Fprintln(w, "  They are listed in --json-out; this result is INCOMPLETE, not clean.")
	}
	if res.LocalNotSent > 0 {
		fmt.Fprintf(w, "  NOTE: %d of your own project(s) (Cargo workspace crates, .NET projects, an SBOM's root component) were not sent: their names stay on this machine. "+
			"Trivy also matches them by name, which matters when a project is a published package.\n", res.LocalNotSent)
	}
	fmt.Fprintln(w)

	section := func(title string, pick func(api.Finding) bool, limit int) {
		type item struct {
			r Row
			f api.Finding
		}
		var items []item
		for _, r := range rows {
			for _, f := range r.Result.Findings {
				if pick(f) {
					items = append(items, item{r, f})
				}
			}
		}
		if len(items) == 0 {
			return
		}
		head := fmt.Sprintf("%s — %d finding(s)", title, len(items))
		if limit > 0 && len(items) > limit {
			head += fmt.Sprintf(" (top %d)", limit)
			items = items[:limit]
		}
		fmt.Fprintln(w, head)
		for _, it := range items {
			reason := ""
			if len(it.f.Reasons) > 0 {
				reason = it.f.Reasons[0]
			}
			fmt.Fprintf(w, "  %-20s %s %s  %s\n", t(it.f.ID, 40), pkgLabel(it.r.Package, t)+supplierTag(it.r.Result),
				t(it.r.Package.Version, 40), t(reason, 110))
			if it.f.FixedVersion != nil && *it.f.FixedVersion != "" {
				fmt.Fprintf(w, "      fixed in %s\n", t(*it.f.FixedVersion, 60))
			} else if it.f.Kind != "malicious" {
				fmt.Fprintln(w, "      no fixed version yet")
			}
			if l := Link(base, it.f.Path, it.f.AdvisoryURL); l != "" {
				fmt.Fprintf(w, "      %s\n", l)
			}
			if m := it.f.Mitigation; m != nil && m.Detection != nil && sitePath.MatchString(m.Detection.Path) {
				var names []string
				for _, fm := range m.Detection.Formats {
					if n, ok := formatName[fm]; ok {
						names = append(names, n)
					}
				}
				if len(names) > 0 {
					fmt.Fprintf(w, "      detect: SIEM queries (%s) %s%s\n", strings.Join(names, ", "), base, m.Detection.Path)
				}
			}
			if it.f.Blocked && (it.f.FixedVersion == nil || *it.f.FixedVersion == "") && it.f.Mitigation != nil &&
				len(it.f.Mitigation.Workarounds) > 0 {
				fmt.Fprintln(w, "      if you cannot patch (AI-written, verify):")
				for i, wa := range it.f.Mitigation.Workarounds {
					if i == 3 {
						break
					}
					fmt.Fprintf(w, "        - %s\n", t(wa, 110))
				}
			}
			fmt.Fprintf(w, "      in %s\n", t(strings.Join(it.r.Sources, ", "), 200))
		}
		fmt.Fprintln(w)
	}
	section("BLOCKED", func(f api.Finding) bool { return f.Blocked }, 0)
	section("REVIEW", func(f api.Finding) bool {
		return !f.Blocked && f.Match == "affected" && (f.Urgency == "known_exploited" || f.Urgency == "high")
	}, maxReview)

	// Upgrade plan: server-computed targets, blocked packages first.
	type plan struct {
		r       Row
		blocked int
	}
	var plans []plan
	for _, r := range rows {
		b := 0
		for _, f := range r.Result.Findings {
			if f.Blocked {
				b++
			}
		}
		if r.Result.Remove || r.Result.UpgradeTo != nil || len(r.Result.UpgradeCandidates) > 0 {
			plans = append(plans, plan{r, b})
		}
	}
	sort.SliceStable(plans, func(i, j int) bool { return plans[i].blocked > plans[j].blocked })
	if len(plans) > 0 {
		fmt.Fprintln(w, "UPGRADE PLAN")
		for _, p := range plans {
			r := p.r.Result
			name := t(p.r.Package.Name, 60) + " " + t(p.r.Package.Version, 40)
			switch {
			case r.Remove:
				fmt.Fprintf(w, "  %-50s REMOVE: known malicious package\n", name)
			case r.UpgradeTo != nil:
				line := fmt.Sprintf("  %-50s -> %s", name, t(*r.UpgradeTo, 60))
				if r.UpgradeToAll != nil {
					line += fmt.Sprintf(" (all listed fixes: %s)", t(*r.UpgradeToAll, 60))
				}
				if p.blocked > 0 {
					line += fmt.Sprintf("   clears %d blocked", p.blocked)
				}
				fmt.Fprintln(w, line)
			default:
				fmt.Fprintf(w, "  %-50s -> one of %s (versions could not be compared; check)\n", name,
					t(strings.Join(r.UpgradeCandidates, ", "), 120))
			}
		}
		fmt.Fprintln(w)
	}
	if counts["not_in_database"] > 0 {
		fmt.Fprintf(w, "NOTE — %d finding(s) have a CVE that is not in the CyberDetails archive; they are NOT judged safe.\n",
			counts["not_in_database"])
	}
	if unverified > 0 {
		fmt.Fprintf(w, "NOTE — %d finding(s) could not be version-checked; use --block-unknown to fail on them.\n", unverified)
	}
	for _, r := range rows {
		if r.Result.FindingsTruncated {
			fmt.Fprintf(w, "NOTE — %s %s has %d findings; the server listed the %d most urgent (blocked first). The result uses all of them.\n",
				t(r.Package.Name, 60), t(r.Package.Version, 40), r.Result.FindingsTotal, len(r.Result.Findings))
		}
	}
	fmt.Fprintln(w, "Only ecosystem, package name and version (for RPM packages also the architecture; for Red Hat "+
		"also the image's content sets and container NVR) were sent to CyberDetails.")
	switch b := Blocked(rows); {
	case b > 0:
		fmt.Fprintf(w, "RESULT: FAIL (%d blocked)\n", b)
	case Incomplete(res, rows) > 0:
		fmt.Fprintf(w, "RESULT: INCOMPLETE (%d package(s) not checked)\n", Incomplete(res, rows))
	default:
		fmt.Fprintln(w, "RESULT: PASS")
	}
}

// supplierTag marks a package matched against a supplier's own advisories.
func supplierTag(r api.PackageResult) string {
	switch r.Supplier {
	case "seal":
		return " [Seal Security build]"
	case "rootio":
		return " [Root.io image]"
	case "rapidfort":
		return " [RapidFort curated image]"
	case "echo":
		return " [Echo build]"
	}
	return ""
}

// pkgLabel is the package name as the user sees it: for OS packages the
// source package with its installed binaries ("glibc (libc-bin, libc6)").
func pkgLabel(p model.Package, t func(string, int) string) string {
	n := t(p.Name, 60)
	if len(p.Binaries) == 0 || (len(p.Binaries) == 1 && p.Binaries[0] == p.Name) {
		return n
	}
	b := p.Binaries
	more := ""
	if len(b) > 4 {
		b, more = b[:4], fmt.Sprintf(" +%d", len(p.Binaries)-4)
	}
	return n + " (" + t(strings.Join(b, ", "), 120) + more + ")"
}
