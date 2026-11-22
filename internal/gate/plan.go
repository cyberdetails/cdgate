package gate

import (
	"encoding/json"
	"regexp"
	"sort"
	"strings"
)

var tierRank = map[string]int{"blocked": 0, "high": 1, "other": 2}

// Package type -> paste-ready upgrade command (only the ones known for sure).
var manager = map[string]string{"debian": "apt", "ubuntu": "apt", "deb": "apt",
	"alpine": "apk", "wolfi": "apk", "chainguard": "apk", "apk": "apk"}

// A package name enters a paste-ready command only if it follows the
// distribution's naming rule: Debian Policy 5.6.1 for apt, apk names for apk.
// The report comes from scanning a pull request; a name that does not match
// never reaches the command (shell injection).
var commandName = map[string]*regexp.Regexp{
	"apt": regexp.MustCompile(`^[a-z0-9][a-z0-9+.\-]{0,127}$`),
	"apk": regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9+._\-]{0,127}$`),
}

// Entry is one row of the fix plan. Field order is the Python JSON key order.
type Entry struct {
	Packages     []string `json:"packages"`
	PkgType      string   `json:"pkg_type"`
	OSPackage    bool     `json:"os_package"`
	Target       string   `json:"target"`
	Installed    string   `json:"installed"`
	UpgradeTo    *string  `json:"upgrade_to"`
	UpgradeToAll *string  `json:"upgrade_to_all"`
	Candidates   []string `json:"candidates"`
	Tier         string   `json:"tier"`
	BlockedCVEs  []string `json:"blocked_cves"`
	HighCVEs     []string `json:"high_cves"`
	OtherFixable int      `json:"other_fixable"`
	Unfixed      int      `json:"unfixed"`
}

// Plan is the fix plan written to --json-out and printed as FIX PLAN.
type Plan struct {
	Entries            []Entry  `json:"entries"`
	BlockedCVEs        int      `json:"blocked_cves"`
	BlockedCVEsFixable int      `json:"blocked_cves_fixable"`
	BlockedWithoutFix  []string `json:"blocked_without_fix"`
	Commands           struct {
		Blocked        []string `json:"blocked"`
		BlockedAndHigh []string `json:"blocked_and_high"`
	} `json:"commands"`
}

type fix struct {
	tier       string
	choice     *string
	candidates []string
}

type pkgAcc struct {
	target, name, installed, typ string
	osPkg                        bool
	fixOrder                     []string
	fixes                        map[string]fix
	unfixed                      map[string]bool
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// BuildPlan turns findings into one upgrade per package. The target version
// closes the package's blocked and high-signal findings with the smallest
// upgrade (upgrade_to); upgrade_to_all covers every listed fix. Binary
// packages from one source (libc6 + libc-bin: same installed version, same
// target, same CVEs) share one row.
func BuildPlan(findings []Finding) Plan {
	var order []string
	pkgs := map[string]*pkgAcc{}
	for _, r := range findings {
		k := mustKey(r.Target, r.Package, r.Installed, r.PkgType, r.OSPackage)
		p := pkgs[k]
		if p == nil {
			p = &pkgAcc{target: r.Target, name: r.Package, installed: r.Installed, typ: r.PkgType,
				osPkg: r.OSPackage, fixes: map[string]fix{}, unfixed: map[string]bool{}}
			pkgs[k] = p
			order = append(order, k)
		}
		id := r.key()
		important := r.Blocked || r.Urgency == "known_exploited" || r.Urgency == "high"
		tier := "other"
		if r.Blocked {
			tier = "blocked"
		} else if important {
			tier = "high"
		}
		if r.Fixed == "" {
			p.unfixed[id] = true
			continue
		}
		choice, ok, cands := pickCandidate(r.Installed, r.Fixed, r.OSPackage)
		var c *string
		if ok {
			c = &choice
		}
		old, seen := p.fixes[id]
		if !seen {
			p.fixOrder = append(p.fixOrder, id)
		}
		if !seen || tierRank[tier] < tierRank[old.tier] {
			p.fixes[id] = fix{tier, c, cands}
		}
	}

	var rowOrder []string
	rows := map[string]*Entry{}
	for _, k := range order {
		p := pkgs[k]
		if len(p.fixes) == 0 {
			continue
		}
		var important []string
		for _, id := range p.fixOrder {
			if p.fixes[id].tier != "other" {
				important = append(important, id)
			}
		}
		set := important
		if len(set) == 0 {
			set = p.fixOrder
		}
		target := func(ids []string) *string {
			var choices []string
			for _, id := range ids {
				c := p.fixes[id].choice
				if c == nil {
					return nil
				}
				choices = append(choices, *c)
			}
			if v, ok := maxVersion(choices, p.osPkg); ok {
				return &v
			}
			return nil
		}
		upgrade, all := target(set), target(p.fixOrder)
		cands := []string{}
		if upgrade == nil {
			u := map[string]bool{}
			for _, id := range set {
				for _, c := range p.fixes[id].candidates {
					u[c] = true
				}
			}
			cands = sortedKeys(u)
		}
		blocked, high := map[string]bool{}, map[string]bool{}
		for id, f := range p.fixes {
			switch f.tier {
			case "blocked":
				blocked[id] = true
			case "high":
				high[id] = true
			}
		}
		e := Entry{Packages: []string{p.name}, PkgType: p.typ, OSPackage: p.osPkg, Target: p.target,
			Installed: p.installed, UpgradeTo: upgrade, Candidates: cands, Tier: "other",
			BlockedCVEs: sortedKeys(blocked), HighCVEs: sortedKeys(high),
			OtherFixable: len(p.fixes) - len(blocked) - len(high), Unfixed: len(p.unfixed)}
		if len(blocked) > 0 {
			e.Tier = "blocked"
		} else if len(high) > 0 {
			e.Tier = "high"
		}
		if all != nil && (upgrade == nil || *all != *upgrade) {
			e.UpgradeToAll = all
		}
		fixIDs := sortedKeys(func() map[string]bool {
			m := map[string]bool{}
			for id := range p.fixes {
				m[id] = true
			}
			return m
		}())
		rk := mustKey(p.target, p.installed, p.typ, p.osPkg, upgrade, all, cands, fixIDs, sortedKeys(p.unfixed))
		if row := rows[rk]; row != nil {
			row.Packages = append(row.Packages, p.name)
			continue
		}
		rows[rk] = &e
		rowOrder = append(rowOrder, rk)
	}
	plan := Plan{Entries: make([]Entry, 0, len(rowOrder))}
	for _, rk := range rowOrder {
		plan.Entries = append(plan.Entries, *rows[rk])
	}
	sort.SliceStable(plan.Entries, func(i, j int) bool {
		a, b := plan.Entries[i], plan.Entries[j]
		switch {
		case tierRank[a.Tier] != tierRank[b.Tier]:
			return tierRank[a.Tier] < tierRank[b.Tier]
		case len(a.BlockedCVEs) != len(b.BlockedCVEs):
			return len(a.BlockedCVEs) > len(b.BlockedCVEs)
		case len(a.HighCVEs) != len(b.HighCVEs):
			return len(a.HighCVEs) > len(b.HighCVEs)
		case a.OtherFixable != b.OtherFixable:
			return a.OtherFixable > b.OtherFixable
		}
		return a.Packages[0] < b.Packages[0]
	})

	// Blocked CVEs: which ones the plan clears, which have a package with no
	// fixed version yet.
	blockedAll, cleared, noFix := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, r := range findings {
		if r.Blocked {
			blockedAll[r.key()] = true
			if r.Fixed == "" {
				noFix[r.key()] = true
			}
		}
	}
	for _, e := range plan.Entries {
		for _, id := range e.BlockedCVEs {
			cleared[id] = true
		}
	}
	plan.BlockedCVEs, plan.BlockedCVEsFixable = len(blockedAll), len(cleared)
	plan.BlockedWithoutFix = sortedKeys(noFix)
	plan.Commands.Blocked = commands(plan.Entries, "blocked")
	plan.Commands.BlockedAndHigh = commands(plan.Entries, "blocked", "high")
	return plan
}

func commands(entries []Entry, tiers ...string) []string {
	var mgrOrder []string
	groups := map[string][]string{}
	for _, e := range entries {
		mgr := ""
		if e.OSPackage {
			mgr = manager[e.PkgType]
		}
		inTier := false
		for _, t := range tiers {
			inTier = inTier || e.Tier == t
		}
		if mgr == "" || !inTier || e.UpgradeTo == nil || *e.UpgradeTo == "" {
			continue
		}
		for _, name := range e.Packages {
			if !commandName[mgr].MatchString(name) {
				continue
			}
			if _, ok := groups[mgr]; !ok {
				mgrOrder = append(mgrOrder, mgr)
			}
			dup := false
			for _, n := range groups[mgr] {
				dup = dup || n == name
			}
			if !dup {
				groups[mgr] = append(groups[mgr], name)
			}
		}
	}
	out := []string{}
	for _, mgr := range mgrOrder {
		switch mgr {
		case "apt":
			out = append(out, "apt-get update && apt-get install -y --only-upgrade "+strings.Join(groups[mgr], " "))
		case "apk":
			out = append(out, "apk add --no-cache --upgrade "+strings.Join(groups[mgr], " "))
		}
	}
	return out
}

// mustKey builds a composite map key (a Python tuple) from plain values.
func mustKey(parts ...any) string {
	b, err := json.Marshal(parts)
	if err != nil {
		panic(err) // strings, bools, slices and *string only: cannot fail
	}
	return string(b)
}
