package parse

// npm semver range matching (node-semver `satisfies`, includePrerelease=false).
// Used only to decide which installed versions a package.json constraint
// refers to (dev/prod classification, like Trivy's go-npm-version). It never
// decides whether a version is vulnerable — that is the server's job.
//
// Verified against node-semver 7.6.3 on the lab corpus (npmrange_test.go and
// cyberdetails.sca/lab).

import (
	"strconv"
	"strings"
)

type sv struct {
	maj, min, pat int
	pre           []string
}

func parseSV(s string) (sv, bool) {
	s = strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(s), "="), "v"))
	if i := strings.IndexByte(s, '+'); i >= 0 {
		s = s[:i]
	}
	var v sv
	core := s
	if i := strings.IndexByte(s, '-'); i >= 0 {
		core = s[:i]
		v.pre = strings.Split(s[i+1:], ".")
	}
	p := strings.Split(core, ".")
	if len(p) != 3 {
		return sv{}, false
	}
	for i, f := range p {
		n, err := strconv.Atoi(f)
		if err != nil || n < 0 || (len(f) > 1 && f[0] == '0') {
			return sv{}, false
		}
		switch i {
		case 0:
			v.maj = n
		case 1:
			v.min = n
		default:
			v.pat = n
		}
	}
	return v, true
}

func cmpPre(a, b []string) int {
	if len(a) == 0 && len(b) == 0 {
		return 0
	}
	if len(a) == 0 {
		return 1
	}
	if len(b) == 0 {
		return -1
	}
	for i := 0; i < len(a) && i < len(b); i++ {
		x, ex := strconv.Atoi(a[i])
		y, ey := strconv.Atoi(b[i])
		switch {
		case ex == nil && ey == nil:
			if x != y {
				if x < y {
					return -1
				}
				return 1
			}
		case ex == nil:
			return -1
		case ey == nil:
			return 1
		default:
			if a[i] != b[i] {
				if a[i] < b[i] {
					return -1
				}
				return 1
			}
		}
	}
	switch {
	case len(a) < len(b):
		return -1
	case len(a) > len(b):
		return 1
	}
	return 0
}

func cmpSV(a, b sv) int {
	for _, d := range [][2]int{{a.maj, b.maj}, {a.min, b.min}, {a.pat, b.pat}} {
		if d[0] != d[1] {
			if d[0] < d[1] {
				return -1
			}
			return 1
		}
	}
	return cmpPre(a.pre, b.pre)
}

type comparator struct {
	op string // ">=", "<", ">", "<=", "="
	v  sv
}

// partial: "1", "1.2", "1.x", "1.2.*", "*", "" -> (numbers, how many given)
func partial(s string) (n [3]int, given int, pre []string, ok bool) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	if s == "" || s == "*" || s == "x" || s == "X" {
		return n, 0, nil, true
	}
	if i := strings.IndexByte(s, '+'); i >= 0 {
		s = s[:i]
	}
	core := s
	if i := strings.IndexByte(s, '-'); i >= 0 {
		core, pre = s[:i], strings.Split(s[i+1:], ".")
	}
	parts := strings.Split(core, ".")
	if len(parts) > 3 {
		return n, 0, nil, false
	}
	for i, f := range parts {
		if f == "x" || f == "X" || f == "*" {
			return n, i, nil, true
		}
		v, err := strconv.Atoi(f)
		if err != nil || v < 0 {
			return n, 0, nil, false
		}
		n[i] = v
		given = i + 1
	}
	if given < 3 {
		pre = nil
	}
	return n, given, pre, true
}

func lower(n [3]int, pre []string) sv { return sv{n[0], n[1], n[2], pre} }

// upper bound "<X.Y.Z-0" (excludes prereleases of the bound)
func upperBound(maj, min, pat int) comparator {
	return comparator{"<", sv{maj, min, pat, []string{"0"}}}
}

func expand(tok string) ([]comparator, bool) {
	op := ""
	for _, o := range []string{">=", "<=", ">", "<", "=", "^", "~>", "~"} {
		if strings.HasPrefix(tok, o) {
			op, tok = o, strings.TrimSpace(tok[len(o):])
			break
		}
	}
	n, g, pre, ok := partial(tok)
	if !ok {
		return nil, false
	}
	switch op {
	case "^":
		if g == 0 {
			return []comparator{{">=", sv{}}}, true
		}
		lo := comparator{">=", lower(n, pre)}
		switch {
		case n[0] > 0 || g == 1:
			return []comparator{lo, upperBound(n[0]+1, 0, 0)}, true
		case n[1] > 0 || g == 2:
			return []comparator{lo, upperBound(0, n[1]+1, 0)}, true
		default:
			return []comparator{lo, upperBound(0, 0, n[2]+1)}, true
		}
	case "~", "~>":
		if g == 0 {
			return []comparator{{">=", sv{}}}, true
		}
		lo := comparator{">=", lower(n, pre)}
		if g == 1 {
			return []comparator{lo, upperBound(n[0]+1, 0, 0)}, true
		}
		return []comparator{lo, upperBound(n[0], n[1]+1, 0)}, true
	case "", "=":
		switch g {
		case 0:
			return []comparator{{">=", sv{}}}, true
		case 1:
			return []comparator{{">=", lower(n, nil)}, upperBound(n[0]+1, 0, 0)}, true
		case 2:
			return []comparator{{">=", lower(n, nil)}, upperBound(n[0], n[1]+1, 0)}, true
		}
		return []comparator{{"=", lower(n, pre)}}, true
	case ">":
		switch g {
		case 0:
			return []comparator{{"<", sv{0, 0, 0, []string{"0"}}}}, true // matches nothing
		case 1:
			return []comparator{{">=", sv{n[0] + 1, 0, 0, nil}}}, true
		case 2:
			return []comparator{{">=", sv{n[0], n[1] + 1, 0, nil}}}, true
		}
		return []comparator{{">", lower(n, pre)}}, true
	case ">=":
		return []comparator{{">=", lower(n, pre)}}, true
	case "<":
		if g == 0 {
			return []comparator{{"<", sv{0, 0, 0, []string{"0"}}}}, true
		}
		if g < 3 {
			return []comparator{{"<", sv{n[0], n[1], n[2], []string{"0"}}}}, true
		}
		return []comparator{{"<", lower(n, pre)}}, true
	case "<=":
		switch g {
		case 0:
			return []comparator{{">=", sv{}}}, true
		case 1:
			return []comparator{upperBound(n[0]+1, 0, 0)}, true
		case 2:
			return []comparator{upperBound(n[0], n[1]+1, 0)}, true
		}
		return []comparator{{"<=", lower(n, pre)}}, true
	}
	return nil, false
}

func (c comparator) test(v sv) bool {
	r := cmpSV(v, c.v)
	switch c.op {
	case ">=":
		return r >= 0
	case ">":
		return r > 0
	case "<":
		return r < 0
	case "<=":
		return r <= 0
	default:
		return r == 0
	}
}

// npmSatisfies reports whether version satisfies the npm range. ok=false:
// the range or version is not semver (dist-tags, URLs, protocols).
func npmSatisfies(version, rng string) (bool, bool) {
	v, ok := parseSV(version)
	if !ok {
		return false, false
	}
	any := false
	for _, set := range strings.Split(rng, "||") {
		set = strings.TrimSpace(set)
		var comps []comparator
		if i := strings.Index(set, " - "); i > 0 { // hyphen range
			a, b := strings.TrimSpace(set[:i]), strings.TrimSpace(set[i+3:])
			na, ga, pa, ok1 := partial(a)
			nb, gb, pb, ok2 := partial(b)
			if !ok1 || !ok2 {
				return false, false
			}
			comps = append(comps, comparator{">=", lower(na, pa)})
			switch gb {
			case 0:
			case 1:
				comps = append(comps, upperBound(nb[0]+1, 0, 0))
			case 2:
				comps = append(comps, upperBound(nb[0], nb[1]+1, 0))
			default:
				comps = append(comps, comparator{"<=", lower(nb, pb)})
			}
			_ = ga
		} else {
			// "> 1.2" -> ">1.2": operators may be followed by spaces
			toks := strings.Fields(set)
			for i := 0; i < len(toks); i++ {
				t := toks[i]
				if (t == ">" || t == ">=" || t == "<" || t == "<=" || t == "=" || t == "^" || t == "~") && i+1 < len(toks) {
					t += toks[i+1]
					i++
				}
				c, ok := expand(t)
				if !ok {
					return false, false
				}
				comps = append(comps, c...)
			}
			if len(toks) == 0 {
				comps = append(comps, comparator{">=", sv{}})
			}
		}
		match := true
		for _, c := range comps {
			if !c.test(v) {
				match = false
				break
			}
		}
		if match && len(v.pre) > 0 {
			// A prerelease matches only if a comparator of this set has the
			// same major.minor.patch with a prerelease (node-semver rule).
			allowed := false
			for _, c := range comps {
				if len(c.v.pre) > 0 && !(len(c.v.pre) == 1 && c.v.pre[0] == "0" && c.op == "<") &&
					c.v.maj == v.maj && c.v.min == v.min && c.v.pat == v.pat {
					allowed = true
				}
			}
			match = allowed
		}
		any = any || match
	}
	return any, true
}
