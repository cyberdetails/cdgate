// Package api talks to the CyberDetails SCA API.
//
// What leaves the machine: for `scan`, each package's ecosystem, name and
// version; for `gate`, CVE identifiers. Never file paths, repository or image
// names, or the API key in any log or report.
package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ferhatcil/cdgate/internal/model"
)

const (
	DefaultBase  = "https://cyberdetails.org"
	queryPath    = "/api/v1/sca/query"
	maxResponse  = 64 << 20
	chunk        = 500
	attempts     = 3
	maxRetryWait = 30 * time.Second
)

// Client is safe for one scan; not shared across goroutines.
type Client struct {
	base  string
	key   string
	http  *http.Client
	agent string
	sleep func(time.Duration)
}

// ValidateBase enforces https, except plain http on loopback for local
// development, and rejects credentials in the URL.
func ValidateBase(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return "", errors.New("--api must be an http(s) URL")
	}
	if u.User != nil {
		return "", errors.New("--api must not contain credentials")
	}
	if u.Scheme == "http" {
		h := u.Hostname()
		ip := net.ParseIP(h)
		if h != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return "", errors.New("--api must use https (plain http only for localhost)")
		}
	}
	return strings.TrimRight(u.Scheme+"://"+u.Host+u.Path, "/"), nil
}

// New returns a client. key may be empty (anonymous, IP rate limit applies).
func New(base, key, version string) (*Client, error) {
	b, err := ValidateBase(base)
	if err != nil {
		return nil, err
	}
	key = strings.TrimSpace(key)
	if len(key) > 200 || strings.IndexFunc(key, func(r rune) bool { return r < 0x21 || r > 0x7e }) >= 0 {
		return nil, errors.New("CD_API_KEY is not a valid key (value not shown)")
	}
	return &Client{
		base: b, key: key, agent: "github.com/ferhatcil/cdgate/" + version + " (+https://cyberdetails.org)",
		sleep: time.Sleep,
		http: &http.Client{
			Timeout: 120 * time.Second,
			// No redirects: a POST with package data must not be replayed to
			// another host, and the API never redirects.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

// QueryPackage is the wire format of one package.
type QueryPackage struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	// Arch is sent for RPM packages only (Rocky's fixes are per architecture).
	Arch string `json:"arch,omitempty"`
	// Red Hat / CentOS only: the image layer's content sets (repository
	// names) and container NVR, which select the product (CPE) an advisory
	// applies to. A non-nil empty list still means "build information
	// present", so the server does not fall back to the default repositories.
	ContentSets *[]string `json:"content_sets,omitempty"`
	NVR         string    `json:"nvr,omitempty"`
	// RapidFort only: the binary packages built from this source package
	// (Trivy also looks advisories up by the binary name).
	Binaries []string `json:"binaries,omitempty"`
}

// Finding mirrors ScaQueryFinding (API models/sca.py).
type Finding struct {
	ID           string          `json:"id"`
	Aliases      []string        `json:"aliases"`
	CVEs         []string        `json:"cves"`
	Kind         string          `json:"kind"`
	Match        string          `json:"match"`
	FixedVersion *string         `json:"fixed_version"`
	Urgency      string          `json:"urgency"`
	Blocked      bool            `json:"blocked"`
	Reasons      []string        `json:"reasons"`
	Signals      json.RawMessage `json:"signals"`
	Mitigation   *Mitigation     `json:"mitigation"`
	Path         *string         `json:"path"`
	AdvisoryURL  *string         `json:"advisory_url"`
	Severity     *string         `json:"severity"`
	Summary      *string         `json:"summary"`
	// VendorStatus (Red Hat): fixed, affected, will_not_fix, ...
	VendorStatus *string `json:"vendor_status"`
}

type Mitigation struct {
	Detection *struct {
		Record   string   `json:"record"`
		Path     string   `json:"path"`
		PackPath string   `json:"pack_path"`
		Formats  []string `json:"formats"`
	} `json:"detection"`
	Workarounds            []string `json:"workarounds"`
	WorkaroundsAIGenerated bool     `json:"workarounds_ai_generated"`
}

// PackageResult mirrors ScaQueryPackage.
type PackageResult struct {
	Ecosystem string    `json:"ecosystem"`
	Name      string    `json:"name"`
	Version   string    `json:"version"`
	Arch      *string   `json:"arch"`
	Status    string    `json:"status"`
	Findings  []Finding `json:"findings"`
	// The server returns at most 500 findings per package, blocked and most
	// urgent first; its decision and counts cover all of them.
	FindingsTotal     int  `json:"findings_total"`
	FindingsTruncated bool `json:"findings_truncated"`
	// Upgrade recommendation computed by the server with the ecosystem's own
	// version rules (the client does not carry a second copy of them).
	UpgradeTo         *string  `json:"upgrade_to"`
	UpgradeToAll      *string  `json:"upgrade_to_all"`
	UpgradeCandidates []string `json:"upgrade_candidates"`
	Unfixed           int      `json:"unfixed"`
	Remove            bool     `json:"remove"`
	// NotCheckedReason is set with status "not_checked".
	NotCheckedReason string `json:"not_checked_reason"`
	// Supplier is "seal" when the package is Seal Security's patched build and
	// was matched against Seal's advisories only, "rootio" in a Root.io image
	// (distribution and Root.io advisories), "rapidfort" in a RapidFort curated
	// image, "echo" for an Echo build (Echo's advisories only).
	Supplier string `json:"supplier"`
}

type queryResponse struct {
	Packages []PackageResult `json:"packages"`
}

// Query sends the packages in chunks and returns one result per unique
// (ecosystem, name, version). A missing package in an answer is an error,
// never a silent "no vulnerabilities".
func (c *Client) Query(pkgs []model.Package, blockAt string, blockUnknown bool) (map[string]PackageResult, error) {
	uniq := map[string]QueryPackage{}
	order := []string{}
	for _, p := range pkgs {
		k := Key(p.Ecosystem, p.Name, p.Version, queryArch(p))
		if _, ok := uniq[k]; !ok {
			uniq[k] = queryPackage(p)
			order = append(order, k)
		}
	}
	out := map[string]PackageResult{}
	for i := 0; i < len(order); i += chunk {
		end := i + chunk
		if end > len(order) {
			end = len(order)
		}
		body := struct {
			Packages     []QueryPackage `json:"packages"`
			BlockAt      string         `json:"block_at"`
			BlockUnknown bool           `json:"block_unknown"`
		}{BlockAt: blockAt, BlockUnknown: blockUnknown}
		for _, k := range order[i:end] {
			body.Packages = append(body.Packages, uniq[k])
		}
		var resp queryResponse
		if err := c.post(queryPath, body, &resp); err != nil {
			return nil, err
		}
		for _, r := range resp.Packages {
			a := ""
			if r.Arch != nil {
				a = *r.Arch
			}
			out[Key(r.Ecosystem, r.Name, r.Version, a)] = r
		}
		for _, k := range order[i:end] {
			if _, ok := out[k]; !ok {
				return nil, fmt.Errorf("CyberDetails API omitted a package from its answer")
			}
		}
	}
	return out, nil
}

// Key is the case-insensitive identity used to join answers with packages.
// Key identifies a queried package; arch is "" for everything but RPM packages.
func Key(eco, name, version, arch string) string {
	return strings.ToLower(eco) + "|" + name + "|" + version + "|" + arch
}

func (c *Client) post(path string, body any, out any) error {
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	var last error
	for i := 1; i <= attempts; i++ {
		req, err := http.NewRequest(http.MethodPost, c.base+path, bytes.NewReader(data))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", c.agent)
		if c.key != "" {
			req.Header.Set("CD-API-KEY", c.key)
		}
		resp, err := c.http.Do(req)
		if err != nil {
			last = fmt.Errorf("cannot reach CyberDetails API: %s", errText(err))
			if i < attempts {
				c.sleep(time.Duration(1<<i) * time.Second)
				continue
			}
			return last
		}
		raw, rerr := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
		resp.Body.Close()
		if rerr != nil {
			return fmt.Errorf("reading CyberDetails API response: %s", errText(rerr))
		}
		if len(raw) > maxResponse {
			return errors.New("CyberDetails API response is larger than 64 MiB")
		}
		switch {
		case resp.StatusCode == http.StatusOK:
			if err := json.Unmarshal(raw, out); err != nil {
				return errors.New("CyberDetails API returned a non-JSON response")
			}
			return nil
		case (resp.StatusCode == 429 || resp.StatusCode >= 500) && i < attempts:
			wait := time.Duration(1<<i) * time.Second
			if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && s > 0 {
				wait = time.Duration(s) * time.Second
			}
			if wait > maxRetryWait {
				wait = maxRetryWait
			}
			last = fmt.Errorf("CyberDetails API returned HTTP %d", resp.StatusCode)
			c.sleep(wait)
			continue
		default:
			var e struct {
				Detail any `json:"detail"`
			}
			_ = json.Unmarshal(raw, &e)
			msg := fmt.Sprintf("CyberDetails API returned HTTP %d", resp.StatusCode)
			if s, ok := e.Detail.(string); ok && s != "" {
				if len(s) > 300 {
					s = s[:300]
				}
				msg += ": " + s
			}
			return errors.New(msg)
		}
	}
	return last
}

// errText drops the URL from transport errors (it may carry a query string).
func errText(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err.Error()
	}
	return err.Error()
}

const triagePath = "/api/v1/sca/triage"

// TriageItem mirrors ScaTriageItem (API models/sca.py).
type TriageItem struct {
	CVE        string          `json:"cve"`
	Urgency    string          `json:"urgency"`
	Blocked    bool            `json:"blocked"`
	Reasons    []string        `json:"reasons"`
	Signals    json.RawMessage `json:"signals"`
	Path       *string         `json:"path"`
	Mitigation *Mitigation     `json:"mitigation"`
}

// Triage sends CVE identifiers only (gate mode) in chunks of 1000 and returns
// one item per CVE. A CVE missing from the answer is an error, never a pass.
func (c *Client) Triage(cves []string, blockAt string, blockUnknown bool) (map[string]TriageItem, error) {
	out := map[string]TriageItem{}
	for i := 0; i < len(cves); i += 1000 {
		end := min(i+1000, len(cves))
		body := struct {
			CVEs         []string `json:"cves"`
			BlockAt      string   `json:"block_at"`
			BlockUnknown bool     `json:"block_unknown"`
		}{cves[i:end], blockAt, blockUnknown}
		var resp struct {
			Items *[]TriageItem `json:"items"`
		}
		if err := c.post(triagePath, body, &resp); err != nil {
			return nil, err
		}
		if resp.Items == nil {
			return nil, errors.New("CyberDetails API response has no items")
		}
		for _, it := range *resp.Items {
			if it.CVE != "" {
				out[strings.ToUpper(it.CVE)] = it
			}
		}
	}
	missing := 0
	for _, cve := range cves {
		if _, ok := out[cve]; !ok {
			missing++
		}
	}
	if missing > 0 {
		return nil, fmt.Errorf("CyberDetails API omitted %d CVE(s) from its answer", missing)
	}
	return out, nil
}

// queryArch is the architecture sent with an RPM package (model.Package.Arch
// is set only for those); other packages are queried without one.
func queryArch(p model.Package) string { return p.Arch }

var nvrRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,255}$`)
var contentSetRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,200}$`)

// queryPackage builds the request item. Build information is sent for Red Hat
// and CentOS only (the server rejects it elsewhere). Trivy looks the NVR up as
// "<nvr>-<arch>"; a value with characters no Red Hat NVR has cannot be in the
// mapping, so it is left out (it would add no product either way). Content
// set names are checked the same way; a malformed one is dropped, never sent.
func queryPackage(p model.Package) QueryPackage {
	q := QueryPackage{Ecosystem: p.Ecosystem, Name: p.Name, Version: p.Version, Arch: queryArch(p)}
	if strings.HasPrefix(p.Ecosystem, "RapidFort:") && len(p.Binaries) > 0 {
		q.Binaries = p.Binaries // at most ospkg.MaxRapidFortBinaries (larger rows are unchecked)
	}
	if p.BuildInfo == nil || !(strings.HasPrefix(p.Ecosystem, "Red Hat:") || strings.HasPrefix(p.Ecosystem, "CentOS:")) {
		return q
	}
	cs := []string{}
	for _, c := range p.BuildInfo.ContentSets {
		if contentSetRe.MatchString(c) && len(cs) < 64 {
			cs = append(cs, c)
		}
	}
	q.ContentSets = &cs
	if p.BuildInfo.Nvr != "" {
		if n := p.BuildInfo.Nvr + "-" + p.BuildInfo.Arch; nvrRe.MatchString(n) {
			q.NVR = n
		}
	}
	return q
}
