// Command cdgate finds the dependencies of a project and asks CyberDetails
// which of them are vulnerable, exploited or malicious.
//
//	cdgate scan .                         # lockfiles in this directory tree
//	cdgate scan . --block-at high --json-out cdgate.json
//	cdgate gate trivy.json                # rank an existing Trivy/Grype report
//	cdgate image image.tar                # OS packages of a `docker save` archive
//
// Exit codes: 0 pass, 1 blocked, 2 the tool could not run (never 0 on error).
// scan sends only ecosystem, package name and version; gate sends only CVE
// identifiers.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/cyberdetails/cdgate/internal/api"
	"github.com/cyberdetails/cdgate/internal/gate"
	"github.com/cyberdetails/cdgate/internal/image"
	"github.com/cyberdetails/cdgate/internal/langpkg"
	"github.com/cyberdetails/cdgate/internal/model"
	"github.com/cyberdetails/cdgate/internal/ospkg"
	"github.com/cyberdetails/cdgate/internal/parse"
	"github.com/cyberdetails/cdgate/internal/report"
	"github.com/cyberdetails/cdgate/internal/sbom"
	"github.com/cyberdetails/cdgate/internal/scan"
)

// version is set at build time: -ldflags "-X main.version=..."
var version = "0.1.0-dev"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func usage(w io.Writer) {
	fmt.Fprintf(w, `cdgate %s — dependency vulnerability gate by CyberDetails

Usage:
  cdgate scan <path> [flags]   scan lockfiles under <path> (directory or file)
  cdgate image <archive> [flags]  OS packages and installed language packages of a
                               'docker save -o image.tar' archive (supported
                               distributions: see README); same flags as scan
  cdgate rootfs <dir> [flags]  OS and installed language packages of a root
                               filesystem (as trivy rootfs); same flags as scan
  cdgate sbom <file> [flags]   packages of a CycloneDX JSON or SPDX (JSON, tag-value) SBOM;
                               same flags as scan
  cdgate gate <report> [flags] rank a Trivy (--format json) or Grype (-o json)
                               report; '-' reads stdin; sends CVE ids only
  cdgate version

Flags for scan:
  --block-at cisa_kev|known_exploited|high|never   what fails the build (default known_exploited)
  --block-unknown        also fail on findings that could not be verified
  --include-dev          include development-only dependencies
  --json-out FILE        write the merged result as JSON
  --api URL              API base (default %s; https, plain http only for localhost)
  --quiet                print only the result line
Flags for gate: --block-at, --block-unknown (CVEs not in the archive), --json-out,
  --api, --quiet (same meaning as for scan)
Environment:
  CD_API_KEY             optional free key for a higher rate limit (never printed)
`, version, api.DefaultBase)
}

func run(args []string, stdout, stderr io.Writer) (code int) {
	// An unexpected failure must never look like a pass (0) or a finding (1).
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintln(stderr, "cdgate: error: internal error; please report it")
			fmt.Fprintln(stderr, "RESULT: ERROR (exit 2) — the tool did not run; this is not a pass.")
			code = report.ExitError
		}
	}()
	if len(args) == 0 {
		usage(stderr)
		return report.ExitError
	}
	switch args[0] {
	case "version", "--version":
		fmt.Fprintln(stdout, version)
		return report.ExitPass
	case "scan":
		return runScanLike(args[1:], stdout, stderr, "scan")
	case "gate":
		return runGate(args[1:], stdout, stderr)
	case "image":
		return runScanLike(args[1:], stdout, stderr, "image")
	case "sbom":
		return runScanLike(args[1:], stdout, stderr, "sbom")
	case "rootfs":
		return runScanLike(args[1:], stdout, stderr, "rootfs")
	case "-h", "--help", "help":
		usage(stdout)
		return report.ExitPass
	default:
		fmt.Fprintf(stderr, "cdgate: unknown command %q\n", args[0])
		usage(stderr)
		return report.ExitError
	}
}

func fail(stderr io.Writer, err error) int {
	fmt.Fprintf(stderr, "cdgate: error: %s\n", err)
	fmt.Fprintln(stderr, "RESULT: ERROR (exit 2) — the scan did not run; this is not a pass.")
	return report.ExitError
}

// parseArgs allows flags after the positional argument
// (`cdgate scan . --block-at high`) and returns the positionals.
func parseArgs(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	rest := args
	for len(rest) > 0 {
		if err := fs.Parse(rest); err != nil {
			return nil, err
		}
		rest = fs.Args()
		if len(rest) > 0 {
			pos = append(pos, rest[0])
			rest = rest[1:]
		}
	}
	return pos, nil
}

func validBlockAt(v string, stderr io.Writer) bool {
	switch v {
	case "cisa_kev", "known_exploited", "high", "never":
		return true
	}
	fmt.Fprintln(stderr, "cdgate: --block-at must be cisa_kev, known_exploited, high or never")
	return false
}

func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("cannot write --json-out: %w", err)
	}
	return nil
}

// imageResult reads a `docker save` archive into a scan result: OS packages
// and installed language packages (langpkg). An image without a supported
// OS (scratch, static distroless) still gets its language packages scanned.
func imageResult(file string) (*scan.Result, error) {
	im, err := image.Open(file)
	if err != nil {
		return nil, err
	}
	label := strings.Join(im.Tags, ", ")
	if label == "" {
		label = filepath.Base(file)
	}
	res := &scan.Result{Root: file, Image: label}
	treeResult(res, im, im, im.Skipped, "(SBOM files in the image)")
	return res, nil
}

// rootfsResult reads a root filesystem the way `trivy rootfs` does: the
// image analyzers over a directory (scan.OpenRootFS).
func rootfsResult(dir string) (*scan.Result, error) {
	rf, err := scan.OpenRootFS(dir)
	if err != nil {
		return nil, err
	}
	res := &scan.Result{Root: rf.Root, RootFS: true}
	treeResult(res, rf.OSFiles(), rf, rf.Skipped, "(SBOM files in the root filesystem)")
	return res, nil
}

// treeResult adds an image's or a root filesystem's OS packages and installed
// language packages to res.
func treeResult(res *scan.Result, osFiles ospkg.Files, src langpkg.Source, skipped []string, sbomSource string) {
	if r, err := ospkg.Analyze(osFiles); err != nil {
		res.Unsupported = append(res.Unsupported, scan.File{Path: "(operating system packages)", Kind: "os-packages",
			Error: err.Error()})
	} else {
		res.OS = &r.OS
		if r.Queryable {
			res.Packages = r.Packages
		} else {
			res.Unchecked = r.Packages
		}
		res.Unchecked = append(res.Unchecked, r.Unchecked...)
		for _, p := range r.Files {
			res.Files = append(res.Files, scan.File{Path: p, Kind: "os-packages", Ecosystem: r.Ecosystem, Packages: len(r.Packages)})
		}
	}
	lr := langpkg.Analyze(src, ospkg.InstalledFiles(osFiles))
	res.Packages = append(res.Packages, lr.Packages...)
	res.Unchecked = append(res.Unchecked, lr.Unchecked...)
	res.LocalNotSent += lr.LocalNotSent
	if len(lr.SBOMOS) > 0 {
		var o *sbom.OS
		if res.OS != nil {
			o = &sbom.OS{Family: res.OS.Family, Name: res.OS.Name}
		}
		addSBOMOS(res, o, lr.SBOMOS, sbomSource)
	}
	byEco := map[string]int{}
	files := map[string]map[string]bool{}
	for _, p := range lr.Packages {
		byEco[p.Ecosystem]++
		if files[p.Ecosystem] == nil {
			files[p.Ecosystem] = map[string]bool{}
		}
		files[p.Ecosystem][p.Source] = true
	}
	ecos := make([]string, 0, len(byEco))
	for e := range byEco {
		ecos = append(ecos, e)
	}
	sort.Strings(ecos)
	for _, e := range ecos {
		res.Files = append(res.Files, scan.File{Path: fmt.Sprintf("installed packages (%d file(s))", len(files[e])),
			Kind: "installed-packages", Ecosystem: e, Packages: byEco[e]})
	}
	for _, s := range skipped {
		res.Unsupported = append(res.Unsupported, scan.File{Path: "(executable)", Kind: "gobinary", Error: s})
	}
	if n := lr.Skipped["go_main_module_version_unknown"]; n > 0 {
		res.Unsupported = append(res.Unsupported, scan.File{Path: "(Go main modules)", Kind: "gobinary",
			Error: fmt.Sprintf("%d Go binary main module(s) built without a version ((devel)); their dependencies and stdlib are scanned", n)})
	}
	if n := lr.Skipped["sbom_component_skipped"]; n > 0 {
		res.Unsupported = append(res.Unsupported, scan.File{Path: "(SBOM components)", Kind: "sbom", Error: sbomSkipped(n)})
	}
	if n := lr.Skipped["sbom_unreadable"]; n > 0 {
		res.Unsupported = append(res.Unsupported, scan.File{Path: "(SBOM files)", Kind: "sbom",
			Error: fmt.Sprintf("%d SBOM file(s) could not be read (Trivy skips them too)", n)})
	}
}

func sbomSkipped(n int) string {
	return fmt.Sprintf("%d SBOM component(s) without a version or a package URL of a supported type were skipped (Trivy cannot match them either)", n)
}

// addSBOMOS queries an SBOM's OS packages with the OS given (the SBOM's own,
// or the image's for SBOMs inside an image) and lists the rest unchecked.
func addSBOMOS(res *scan.Result, o *sbom.OS, pkgs []sbom.OSPackage, source string) {
	if len(pkgs) == 0 {
		return
	}
	r, rest, err := ospkg.FromSBOM(o, pkgs)
	why := "operating-system package of another type than the SBOM's operating system"
	if err != nil {
		why = err.Error()
	}
	if r != nil {
		for _, p := range r.Packages {
			p.Source = source
			if !r.Queryable { // as for an image: no advisories for this distribution yet
				res.Unchecked = append(res.Unchecked, p)
				continue
			}
			res.Packages = append(res.Packages, p)
		}
		for _, p := range r.Unchecked {
			p.Source = source
			res.Unchecked = append(res.Unchecked, p)
		}
		if res.OS == nil {
			res.OS = &r.OS
		}
		res.Files = append(res.Files, scan.File{Path: source + " (operating system)", Kind: "sbom-os-packages",
			Ecosystem: r.Ecosystem, Packages: len(r.Packages)})
	}
	for _, p := range rest {
		res.Unchecked = append(res.Unchecked, model.Package{Ecosystem: p.Type, Name: p.Name, Version: p.Version,
			Source: source, UncheckedReason: why})
	}
}

// MaxSBOMBytes caps one SBOM file read by `cdgate sbom`.
const MaxSBOMBytes = 64 << 20

// sbomResult reads one CycloneDX JSON or SPDX JSON document.
func sbomResult(file string) (*scan.Result, error) {
	fi, err := os.Lstat(file)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", file)
	}
	if fi.Size() > MaxSBOMBytes {
		return nil, fmt.Errorf("SBOM is larger than %d MiB", MaxSBOMBytes>>20)
	}
	b, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	r, err := sbom.Decode(b)
	if errors.Is(err, sbom.ErrNotRead) {
		return nil, fmt.Errorf("the SBOM is %s, which is not read (Trivy does not read it either); export it as CycloneDX JSON or SPDX", r.Format)
	} else if err != nil {
		return nil, fmt.Errorf("SBOM could not be read: %w", err)
	}
	name := filepath.Base(file)
	res := &scan.Result{Root: file, LocalNotSent: r.LocalNotSent, SBOM: true}
	for _, p := range r.Packages {
		p.Source = name
		res.Packages = append(res.Packages, p)
	}
	for _, p := range r.Unchecked {
		p.Source = name
		res.Unchecked = append(res.Unchecked, p)
	}
	res.Files = []scan.File{{Path: name, Kind: r.Format, Ecosystem: r.Format, Packages: len(r.Packages)}}
	addSBOMOS(res, r.OS, r.OSPackages, name)
	if r.Skipped > 0 {
		res.Unsupported = append(res.Unsupported, scan.File{Path: "(SBOM components)", Kind: "sbom", Error: sbomSkipped(r.Skipped)})
	}
	return res, nil
}

func runScanLike(args []string, stdout, stderr io.Writer, ad string) int {
	fs := flag.NewFlagSet(ad, flag.ContinueOnError)
	fs.SetOutput(stderr)
	blockAt := fs.String("block-at", "known_exploited", "")
	blockUnknown := fs.Bool("block-unknown", false, "")
	includeDev := fs.Bool("include-dev", false, "")
	jsonOut := fs.String("json-out", "", "")
	apiBase := fs.String("api", api.DefaultBase, "")
	quiet := fs.Bool("quiet", false, "")
	paths, err := parseArgs(fs, args)
	if err != nil {
		return report.ExitError
	}
	if len(paths) != 1 {
		fmt.Fprintf(stderr, "cdgate: %s needs exactly one path\n", ad)
		return report.ExitError
	}
	if !validBlockAt(*blockAt, stderr) {
		return report.ExitError
	}

	var res *scan.Result
	var err2 error
	switch ad {
	case "image":
		res, err2 = imageResult(paths[0])
	case "sbom":
		res, err2 = sbomResult(paths[0])
	case "rootfs":
		res, err2 = rootfsResult(paths[0])
	default:
		res, err2 = scan.Dir(paths[0], parse.Options{IncludeDev: *includeDev})
	}
	if err2 != nil {
		return fail(stderr, err2)
	}
	for _, f := range res.Files {
		if f.Error != "" {
			// A lockfile we found but could not read is not a pass.
			return fail(stderr, fmt.Errorf("%s could not be read: %s", f.Path, f.Error))
		}
	}
	if len(res.Packages) == 0 {
		if len(res.Files) == 0 && len(res.Unsupported) == 0 {
			return fail(stderr, errors.New("no supported lockfile found"))
		}
		if len(res.Files) == 0 {
			return fail(stderr, fmt.Errorf("only manifests that are not analysed were found (%s)", res.Unsupported[0].Path))
		}
	}
	// A package the API would refuse 422s the whole request: list it as not
	// checked instead of sending it, and query the rest.
	sendable := make([]model.Package, 0, len(res.Packages))
	for _, p := range res.Packages {
		if r := api.Rejected(p); r != "" {
			p.UncheckedReason = r
			res.Unchecked = append(res.Unchecked, p)
			continue
		}
		sendable = append(sendable, p)
	}
	res.Packages = sendable
	var rows []report.Row
	if len(res.Packages) > 0 || len(res.Unchecked) == 0 {
		client, err := api.New(*apiBase, os.Getenv("CD_API_KEY"), version)
		if err != nil {
			return fail(stderr, err)
		}
		results, err := client.Query(res.Packages, *blockAt, *blockUnknown)
		if err != nil {
			return fail(stderr, err)
		}
		rows = report.Join(res.Packages, results)
	}
	decision := "pass"
	switch {
	case report.Blocked(rows) > 0:
		decision = "fail"
	case report.Incomplete(res, rows) > 0:
		decision = "incomplete" // a coverage gap must not read as a clean result
	}
	if *jsonOut != "" {
		out := struct {
			Tool         string          `json:"tool"`
			BlockAt      string          `json:"block_at"`
			Decision     string          `json:"decision"`
			Files        []scan.File     `json:"files"`
			Unsupported  []scan.File     `json:"unsupported"`
			Truncated    bool            `json:"truncated"`
			Packages     []report.Row    `json:"packages"`
			Unchecked    []model.Package `json:"unchecked_packages,omitempty"`
			LocalNotSent int             `json:"local_projects_not_sent,omitempty"`
		}{"cdgate " + version, *blockAt, decision, res.Files, res.Unsupported, res.Truncated, rows, res.Unchecked, res.LocalNotSent}
		if err := writeJSON(*jsonOut, out); err != nil {
			return fail(stderr, err)
		}
	}
	base, _ := api.ValidateBase(*apiBase)
	if *quiet {
		fmt.Fprintln(stdout, "RESULT: "+strings.ToUpper(decision))
	} else {
		report.Text(stdout, version, base, *blockAt, res, rows)
	}
	switch decision {
	case "fail":
		return report.ExitBlocked
	case "incomplete":
		return report.ExitError
	}
	return report.ExitPass
}

// runGate ranks an existing scanner report (port of cd_sca_gate.py).
func runGate(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	blockAt := fs.String("block-at", "known_exploited", "")
	blockUnknown := fs.Bool("block-unknown", false, "")
	jsonOut := fs.String("json-out", "", "")
	apiBase := fs.String("api", api.DefaultBase, "")
	quiet := fs.Bool("quiet", false, "")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return report.ExitError
	}
	if len(pos) != 1 {
		fmt.Fprintln(stderr, "cdgate: gate needs exactly one report file ('-' for stdin)")
		return report.ExitError
	}
	if !validBlockAt(*blockAt, stderr) {
		return report.ExitError
	}
	gateFail := func(err error) int {
		fmt.Fprintf(stderr, "cdgate: error: %s\n", err)
		fmt.Fprintln(stderr, "RESULT: ERROR (exit 2) — the gate did not run; this is not a pass.")
		return report.ExitError
	}
	base, err := api.ValidateBase(*apiBase)
	if err != nil {
		return gateFail(err)
	}
	tool, findings, meta, err := gate.Read(pos[0])
	if err != nil {
		return gateFail(err)
	}
	seen := map[string]bool{}
	var cves []string
	for _, f := range findings {
		if f.CVE != nil && !seen[*f.CVE] {
			seen[*f.CVE] = true
			cves = append(cves, *f.CVE)
		}
	}
	sort.Strings(cves)
	items := map[string]api.TriageItem{}
	if len(cves) > 0 {
		client, err := api.New(*apiBase, os.Getenv("CD_API_KEY"), version)
		if err != nil {
			return gateFail(err)
		}
		if items, err = client.Triage(cves, *blockAt, *blockUnknown); err != nil {
			return gateFail(err)
		}
	}
	results := gate.Join(findings, items, base)
	plan := gate.BuildPlan(results)
	blocked := gate.Blocked(results)
	if *jsonOut != "" {
		decision := "pass"
		if blocked {
			decision = "fail"
		}
		out := struct {
			Tool         string         `json:"tool"`
			Scanner      string         `json:"scanner"`
			OS           gate.Meta      `json:"os"`
			BlockAt      string         `json:"block_at"`
			BlockUnknown bool           `json:"block_unknown"`
			Decision     string         `json:"decision"`
			FixPlan      gate.Plan      `json:"fix_plan"`
			Findings     []gate.Finding `json:"findings"`
		}{"cdgate " + version, tool, meta, *blockAt, *blockUnknown, decision, plan, results}
		if err := writeJSON(*jsonOut, out); err != nil {
			return gateFail(err)
		}
	}
	switch {
	case *quiet && blocked:
		fmt.Fprintln(stdout, "RESULT: FAIL")
	case *quiet:
		fmt.Fprintln(stdout, "RESULT: PASS")
	default:
		fmt.Fprintln(stdout, gate.Text(results, tool, version, *blockAt, plan, meta))
	}
	if blocked {
		return report.ExitBlocked
	}
	return report.ExitPass
}
