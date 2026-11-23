# CyberDetails SCA

Your scanner finds 300 CVEs in your dependencies. CyberDetails tells you which
few are being exploited in the wild, fails the build on those, shows the
upgrade that clears them and, where you cannot patch yet, how to detect
exploitation.

> This repository holds `cdgate`, the Go scanner, and `cd_sca_gate.py`, the
> single-file Python gate described below. Both are exported from the
> CyberDetails source tree, where the API also lives. Changes are made in the
> source tree and exported.

> **Status: preview.** The hosted API at `https://cyberdetails.org` has
> answered these requests since 2026-11-19. `cdgate` has no binary release
> yet; install it with Go (below).

There are two tools and one API:

| Tool | What it reads | What it sends |
|---|---|---|
| `cd_sca_gate.py` (Python 3.8+, one file, no dependencies) | a Trivy or Grype JSON report | CVE identifiers only |
| `cdgate` (Go, one binary) | lockfiles, container images, root filesystems, SBOMs; or a Trivy/Grype report | ecosystem, package name and version (details in [What leaves your machine](#what-leaves-your-machine)) |

Both use one policy and one exit-code contract, and both talk to
`/api/v1/sca/*` ([API reference](#api-reference)).

## Contents

1. [Quick start](#quick-start)
2. [Working with Trivy and Grype](#working-with-trivy-and-grype)
3. [What leaves your machine](#what-leaves-your-machine)
4. [Supported inputs](#supported-inputs)
5. [Policy and exit codes](#policy-and-exit-codes)
6. [When the build fails](#when-the-build-fails)
7. [CI recipes](#ci-recipes)
8. [API reference](#api-reference)
9. [Accuracy](#accuracy)
10. [Limits and FAQ](#limits-and-faq)
11. [Changelog](#changelog)
12. [License](#license)

## Quick start

**I already run Trivy or Grype.** Keep it. Hand its JSON report to the gate;
only the CVE identifiers are sent.

```sh
trivy fs --scanners vuln --format json --output trivy.json .
python cd_sca_gate.py trivy.json          # or: cdgate gate trivy.json
```

**I have no scanner.** `cdgate` finds the packages itself and asks the API
which versions are affected.

```sh
cdgate scan .                             # lockfiles under the current directory
docker save -o image.tar myapp:latest
cdgate image image.tar                    # OS + installed language packages
cdgate rootfs /mnt/extracted-image        # same, for an unpacked root filesystem
cdgate sbom bom.cdx.json                  # CycloneDX JSON or SPDX (JSON, tag-value)
```

**Just trying it?** [cyberdetails.org/sca/check](https://cyberdetails.org/sca/check)
reads a Trivy or Grype report, a CycloneDX or SPDX JSON SBOM, or a JSON
lockfile (`package-lock.json`, `npm-shrinkwrap.json`, `Pipfile.lock`,
`composer.lock`, `packages.lock.json`) in your browser: a report sends only
its CVE identifiers, an SBOM or lockfile only the ecosystem, name and version
of each language package. Operating-system packages in an SBOM are counted
and left to `cdgate sbom`, so such a result reads INCOMPLETE. It also checks a
pasted CVE list or a few packages.

**Both.** They answer different questions and can run side by side: your
scanner and `cdgate scan` each decide which versions are affected; the gate
ranks whatever CVEs a scanner reported by exploitation evidence.

`cdgate` has no binary release yet. Install it with Go 1.22 or newer:

```sh
go install github.com/ferhatcil/cdgate/cmd/cdgate@latest
```

The source is at [github.com/ferhatcil/cdgate](https://github.com/ferhatcil/cdgate)
(Apache-2.0).

`cd_sca_gate.py` is one file in the same repository and needs only Python 3.8
or newer. Download it next to your scanner's report:

```sh
curl -fsSLO https://raw.githubusercontent.com/ferhatcil/cdgate/main/cd_sca_gate.py
```

In CI, replace `main` in that URL with a commit hash so a later change cannot
alter your build. `cdgate gate` applies the same policy to the same reports.

## Working with Trivy and Grype

CyberDetails is not a replacement for a scanner, and the two tools draw the
line in different places:

- **The gate** (`cd_sca_gate.py`, `cdgate gate`) leaves package discovery and
  version matching to your scanner. It adds the decision the scanner does not
  make: which of the reported CVEs are known to be exploited (CISA and
  VulnCheck KEV, CISA SSVC active exploitation), have a public exploit
  (Metasploit, Nuclei), or a high EPSS percentile or CyberDetails Priority Score.
- **`cdgate scan / image / rootfs / sbom`** reads the same package sources as
  `trivy fs`, `trivy image`, `trivy rootfs` and `trivy sbom`, following Trivy's
  own parsing rules (measured against Trivy, see [Accuracy](#accuracy)). The
  difference is where the advisory data lives: Trivy downloads a vulnerability
  database to your machine; `cdgate` asks the CyberDetails API online and
  nothing is downloaded.

## What leaves your machine

| Command | Sent to CyberDetails | Never sent |
|---|---|---|
| `cd_sca_gate.py`, `cdgate gate` | CVE identifiers and the policy | package names, versions, paths, repository and image names; findings without a CVE (`GHSA-…`, `GO-…`) |
| `cdgate scan`, `image`, `rootfs`, `sbom` | for each package: ecosystem, name, version. RPM packages add the architecture; Red Hat and CentOS images add the image's content sets and container NVR; RapidFort images add the binary package names of a source package | file paths, repository, image or host names, the names of your own projects (workspace crates, .NET projects, SBOM root components: counted and reported as "not sent"), SHA-1 digests of Java archives |

On the server:

- Request bodies are not logged and not stored. Log lines carry counts only
  (number of CVEs, packages, findings).
- A CVE that is **not in the archive** is counted in `sca_gaps`
  (`{CVE, count, first and last day seen}`), with no IP address, request id or
  "which CVEs arrived together", written in batches once a minute, deleted 90
  days after it was last seen. It tells us which CVEs to import next.
- Like any web request, the reverse proxy's access log records time, IP
  address, path and user agent.
- With an API key: the digest of the address it was issued to and the digest
  of the key (see [Rate limits and keys](#rate-limits-and-keys)). No company
  name, no account.

## Supported inputs

### Lockfiles (`cdgate scan`)

| Ecosystem | Files |
|---|---|
| npm | `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml` |
| PyPI | `requirements.txt` (pinned `==` / `===` lines only), `Pipfile.lock`, `poetry.lock` |
| Go | `go.mod` |
| crates.io | `Cargo.lock` |
| Packagist | `composer.lock` |
| RubyGems | `Gemfile.lock` |
| NuGet | `packages.lock.json`, `packages.config`, `*.deps.json`, `Directory.Packages.props` / `*packages.props` |
| Maven | `gradle.lockfile`, `buildscript-gradle.lockfile`, `*.gradle.lockfile` |
| Julia | `Manifest.toml` (with its `Project.toml`) |

Drupal contrib modules (`drupal/<module>` in `composer.lock`, served from
packages.drupal.org) are matched against the Drupal Security Team's own
advisories as well as GitHub's; Trivy does not read the Drupal ones.

Found but **not analysed**, and reported as such (never a silent pass):
`pom.xml` (needs dependency resolution; use a CycloneDX SBOM or a
`gradle.lockfile`), `build.gradle(.kts)`, `Pipfile`, `pyproject.toml`,
`Gemfile`, `composer.json` and `Cargo.toml` without their lockfile.
Development-only dependencies are skipped unless `--include-dev` is given.

### Container images and root filesystems (`cdgate image`, `cdgate rootfs`)

`cdgate image` reads a `docker save -o image.tar` archive; `cdgate rootfs`
reads a directory. Both read what `trivy image` / `trivy rootfs` read.

**Operating system packages**

| Family | Releases |
|---|---|
| Debian | numbered releases (`testing` / `sid` are reported as unsupported) |
| Ubuntu | `YY.MM` releases, including ESM |
| Alpine | `vX.Y` and `edge` |
| Red Hat Enterprise Linux, CentOS | RHEL 6–9, CentOS 6–8 (advisories selected by the image's content sets) |
| Rocky Linux, AlmaLinux | 8, 9, 10 |
| Amazon Linux | 2, 2023 |
| Oracle Linux | 5–10 |
| SUSE | SLES 11–16.1, SLE Micro 5.0–6.2, openSUSE Leap 15.x / 16.x / 42.x, openSUSE Tumbleweed |
| Photon OS | 1.0–5.0 |
| Azure Linux, CBL-Mariner | Azure Linux 3.0, CBL-Mariner 1.0 / 2.0, including distroless images (`var/lib/rpmmanifest/container-manifest-2`) |
| Bottlerocket | rolling (one stream) |
| Wolfi, Chainguard, MinimOS | rolling (one stream each) |
| Echo | rolling (one stream) |

Packages rebuilt by a supplier are matched against the supplier's own
advisories, as Trivy does: Seal Security (`sp` versions and `seal-` packages),
Root.io images, RapidFort curated images and Echo's patched language packages
(`+echo.N`). The license of every advisory source is listed on
[cyberdetails.org/sources](https://cyberdetails.org/sources).
A release outside these lists (CentOS Stream, Fedora, CoreOS, …) is reported
as unsupported, and its packages are listed as **not checked**; the result is
`INCOMPLETE`, never `PASS`.

**Installed language packages**: npm `package.json`, Python `METADATA` /
egg-info, RubyGems specifications, Composer `installed.json`, Go and Rust
(cargo-auditable) executables, Java archives (`.jar`, `.war`, `.ear`, `.par`),
NuGet / .NET (`*.deps.json`, `packages.lock.json`, `packages.config`,
`*packages.props`), `Cargo.lock`, Julia `Manifest.toml`, and SBOM files inside
the image. Conda packages are listed as not checked (Trivy lists them but does
not match them either).

A Java archive whose identity is only in its SHA-1 digest (no matching
`pom.properties`) is listed as **not checked** with its digest, because
identifying it needs Trivy's 1 GB Java database; nothing about it is sent.

### SBOMs (`cdgate sbom`)

CycloneDX JSON and SPDX 2.1–2.3 (JSON and tag-value), including their OS
packages (deb, apk, rpm). Components are read the way `trivy sbom` reads them.
CycloneDX XML is rejected with an explicit error: Trivy does not read it
either.

## Policy and exit codes

| `--block-at` | Fails the build on |
|---|---|
| `cisa_kev` | CISA KEV only: strictest evidence, least noise |
| `known_exploited` (default) | CISA KEV, VulnCheck KEV or CISA SSVC active exploitation |
| `high` | the above, plus a CRITICAL Priority Score label or a score of 65 or more, EPSS in the 90th percentile or above, a Metasploit or Nuclei module, or a proof of concept that CISA SSVC marks automatable |
| `never` | nothing: report only |

A known **malicious package** fails the build at every threshold except
`never`. `--block-unknown` also fails on CVEs that are not in the archive and,
for `cdgate`, on findings whose version could not be compared.

| Exit | Meaning |
|---|---|
| 0 | `PASS`: the policy passed |
| 1 | `FAIL`: at least one finding is blocked |
| 2 | the tool did not run (unreadable input, API unreachable or erroring), **or** `INCOMPLETE`: some packages could not be checked |

A broken network or a coverage gap must not turn a build green, so neither
returns 0. To let the build continue when only the tool itself fails:
`cdgate scan . || [ $? -eq 2 ]`.

## When the build fails

**Fix plan.** For each package: `upgrade_to`, the smallest version that clears
its blocked and high-signal findings, and `upgrade_to_all`, the version that
clears every fix listed for it.

- The gate computes the plan **on your machine** from the scanner's fixed
  versions; `cdgate scan` gets it from the API, computed with the ecosystem's
  own version rules.
- When fixes exist per release branch (Maven `2.9.10, 2.8.11.5`), the smallest
  fix above your installed version is chosen, so you stay on your branch
  where possible.
- Binaries built from one source package (`libc6` + `libc-bin`) share a line.
- If versions cannot be compared, the candidates are shown with "check",
  never a guess.
- A paste-ready `apt-get` / `apk` command is printed only for Debian, Ubuntu
  and Alpine packages; application dependencies are listed with their
  manifest.
- A blocked CVE with no fixed version is listed as such, never dropped.

**If you cannot patch yet.** For blocked and review findings the output links
to ready-made SIEM hunting queries (Sigma, Splunk SPL, Microsoft Sentinel KQL,
Elastic EQL, Google SecOps YARA-L) when CyberDetails has them for **that** CVE,
and `--json-out` carries a direct `pack.zip` link. For a blocked CVE with no
fix, up to three workarounds are printed, labelled **AI-written, verify**:
they are model output, not vendor guidance.

**End-of-life base images.** When a Trivy report marks the image's
distribution as end of life, the gate says so: such an image stops receiving
fixes, and the real fix is a supported base image.

A real `nginx:1.21` image scan through the gate (1,091 findings):

```
CyberDetails SCA gate 0.2.0 — trivy: 1091 finding(s), 637 distinct CVE(s); block at: known_exploited
  exploitation:     4 known exploited, 32 high, 151 standard, …
  base OS:          debian 11.3 — END OF LIFE: the distribution no longer ships security fixes; rebuild on a supported base image

BLOCKED — 3 CVE(s), 4 finding(s)
  CVE-2023-4911     Known exploited vulnerability (CISA KEV), federal due date 2023-12-12.
      libc-bin, libc6 2.31-13+deb11u3 -> 2.31-13+deb11u7
      https://cyberdetails.org/cve/CVE-2023-4911
      detect: SIEM queries (Sigma, Splunk SPL, Sentinel KQL, Elastic EQL, YARA-L) https://cyberdetails.org/exploit/CDE-2023-6628
  …

FIX PLAN — 3 upgrade(s) clear all 3 blocked CVE(s)
  libc-bin, libc6     2.31-13+deb11u3 -> 2.31-13+deb11u7 (all listed fixes: 2.31-13+deb11u14)   1 blocked, +13 other
  …
  run: apt-get update && apt-get install -y --only-upgrade libc-bin libc6 libnghttp2-14 libwebp6
RESULT: FAIL (4 blocked)
```

### How a signal is attributed

A KEV listing, EPSS score, SSVC decision, exploit module, detection query or
workaround counts for a CVE only when it belongs to **that** CVE. A vendor
bulletin that covers ten CVEs, one of them in KEV, does not make the other
nine "known exploited".

## CI recipes

The recipes use the Python gate, which runs anywhere Python 3.8+ does. For
`cdgate`, replace the gate line with `cdgate scan .` (or `image`, `rootfs`,
`sbom`) and keep the rest. Set `CD_API_KEY` as a secret variable if you have
a key.

**GitHub Actions**

```yaml
- name: Scan dependencies
  run: trivy fs --scanners vuln --format json --output trivy.json .
- name: CyberDetails gate
  env:
    CD_API_KEY: ${{ secrets.CD_API_KEY }}
  run: python cd_sca_gate.py trivy.json --json-out cd-triage.json
- uses: actions/upload-artifact@v4
  if: always()
  with: { name: cd-triage, path: cd-triage.json }
```

**GitLab CI**

```yaml
sca_gate:
  stage: test
  image: python:3.12-slim
  script:
    - python cd_sca_gate.py trivy.json --json-out cd-triage.json
  artifacts:
    when: always
    paths: [cd-triage.json]
```

**Jenkins (declarative)**

```groovy
stage('CyberDetails gate') {
  environment { CD_API_KEY = credentials('cd-api-key') }
  steps { sh 'python3 cd_sca_gate.py trivy.json --json-out cd-triage.json' }
  post { always { archiveArtifacts artifacts: 'cd-triage.json', allowEmptyArchive: true } }
}
```

**Bitbucket Pipelines**

```yaml
- step:
    name: CyberDetails gate
    image: python:3.12-slim
    script:
      - python cd_sca_gate.py trivy.json --json-out cd-triage.json
    artifacts:
      - cd-triage.json
```

**Azure DevOps**

```yaml
- script: python3 cd_sca_gate.py trivy.json --json-out cd-triage.json
  displayName: CyberDetails gate
  env:
    CD_API_KEY: $(CD_API_KEY)
```

## API reference

Base URL `https://cyberdetails.org/api/v1/sca`. JSON in, JSON out. Unknown
fields are rejected (422), and a 422 never echoes your input back. Request
bodies are limited to 1 MiB.

### `POST /triage`

```json
{"cves": ["CVE-2021-44228", "CVE-2021-23337"], "block_at": "known_exploited", "block_unknown": false}
```

| Field | |
|---|---|
| `cves` | 1–1,000 CVE identifiers (`CVE-YYYY-NNNN`); duplicates are merged |
| `block_at` | `cisa_kev`, `known_exploited` (default), `high`, `never` |
| `block_unknown` | fail on CVEs not in the archive (default `false`) |

The response has `decision` (`pass` / `fail`), counts per urgency, and one
item per CVE: `urgency` (`known_exploited`, `high`, `standard`,
`not_in_database`), `blocked`, `reasons`, `signals`, `mitigation` (detection
queries and workarounds) and `path` (the CVE's page). Every CVE you sent comes
back; the clients treat a missing one as an error.

### `POST /query`

```json
{"packages": [{"ecosystem": "npm", "name": "lodash", "version": "4.17.20"}],
 "block_at": "known_exploited", "block_unknown": false}
```

| Field | |
|---|---|
| `packages` | 1–500 packages: `ecosystem`, `name`, `version`; optional `arch` (RPM), `content_sets` and `nvr` (Red Hat, CentOS), `binaries` (RapidFort) |
| `block_at`, `block_unknown` | as for `/triage`; `block_unknown` also fails on versions that could not be compared |

Ecosystems: `npm`, `PyPI`, `Maven`, `Go`, `NuGet`, `RubyGems`, `crates.io`,
`Packagist`, `Hex`, `Pub`, `Julia`, `Bitnami`, and the distribution streams of
[the image table](#container-images-and-root-filesystems-cdgate-image-cdgate-rootfs)
written as `Debian:12`, `Ubuntu:22.04`, `Alpine:v3.19`, `Rocky Linux:9`, … (the
full list is in the API's schema). Each package comes back with `status`
(`vulnerable`, `unverified`, `no_known_vulnerabilities`, `not_checked`),
`findings` (vulnerabilities and known malicious packages), `upgrade_to`,
`upgrade_to_all`, `unfixed` and `remove` (for a malicious package: remove it,
do not upgrade). `no_known_vulnerabilities` means none known, not "safe".

### Rate limits and keys

| | Package queries | Triage requests |
|---|---|---|
| Anonymous, per IP address | 60 per hour | 120 per hour |
| With a free API key, per key | 1,000 per hour (default) | 2,000 per hour (default) |

Need more? Write to the address on
[cyberdetails.org/access](https://cyberdetails.org/access) for a **free**
key; no account and no company name are needed. Send it in the `CD-API-KEY`
header, or set `CD_API_KEY` for both tools. A key is counted on its own,
without the IP limit, so a shared CI runner does not use up its neighbours'
quota.

### Errors

| Status | Meaning | What the clients do |
|---|---|---|
| 401 | the API key is invalid or revoked (the same answer for every case; a bad key never falls back to the anonymous limit) | exit 2 |
| 413 | one request touches too many advisories or archive records | send fewer packages or CVEs per request |
| 422 | the body does not match the schema; only the location of the error is returned, and a field name the schema does not know is shown as `<unknown field>` | exit 2 |
| 429 | hourly limit reached, or too many invalid API keys from one address (20 an hour); `Retry-After` says when | up to 3 attempts in total (each wait capped at 30 s), then exit 2 |
| 503 | the query timed out, the key could not be checked, the package data is not ready, or the endpoint is not enabled yet | up to 3 attempts in total, then exit 2 |

## Accuracy

Measured in the lab on 17–18 November 2026 against the tools themselves, not
against documentation. Every figure comes from the project journal
(`docs/sca-journal.md`); a figure without a measurement is not published here.

| What | Measured against | Result |
|---|---|---|
| Version comparison, 9 ecosystems | node-semver 7.6.3, golang.org/x/mod, maven-artifact 3.9.9, RubyGems 3.6.9, composer/semver 3.4.3, dpkg, apk-tools 3.0.9 | 198,703 real version pairs, 0 reversed answers |
| npm ranges | node-semver 7.6.3 | 10,870 pairs, 0 differences |
| Debian versions | `dpkg --compare-versions` | 14,998 pairs from the `nginx:1.21` image, 0 differences |
| Rocky Linux 8 / 9 / 10 advisories | Trivy's database | 226,396 / 226,396 identical |
| MinimOS, Echo advisories | Trivy's database | 129,056 / 129,056 and 70,050 / 70,050 |
| RapidFort routing and decisions | Trivy's own code | 57,746 / 57,746 and 147,726 / 147,726 |
| Bitnami ranges | Trivy's code | 790,301 pairs, 0 in the dangerous direction ("not affected" where Trivy says affected) |
| Java archives | Trivy's JAR parser | 170 / 170 packages |
| Rust executables | Trivy | 532 / 532 packages |
| Package URLs | packageurl-go | 28,869 inputs, 0 differences |
| SBOM OS packages | `cdgate image` on the same images | 36 / 36 SBOMs (3,842 rows) |
| Root filesystems | `trivy rootfs` | 8 of 9 identical; the ninth differs only by Java archives identified from Trivy's Java database (listed as not checked here) |
| KEV attribution | CISA's catalog, real Trivy reports | 0 CVEs wrongly reported as CISA KEV |
| Archive coverage | a real multi-ecosystem application report | 312 of 340 CVEs (91.8%) in the archive; the gap is reported as `not_in_database` |

Known differences, kept on purpose:

- Where advisory data contradicts itself (for example `>=9.4.0, <9.3.4`), we
  read it in the safe direction; Trivy may say "not affected".
- A Julia `Manifest.toml` without its `Project.toml` is read in full; Trivy
  reports nothing.

## Limits and FAQ

**Does it check versions?** The gate does not: affected versions and fixes
come from your scanner. `cdgate scan` does, with each ecosystem's own rules;
a version it cannot compare is reported as `unverified`, never as clean.

**Does it know whether a package is used?** No. A scanner reports every
installed package; in the `nginx:1.21` image about 80% of the findings are in
packages the nginx process never loads. Exploitation evidence is the filter,
not reachability.

**Is `not_in_database` safe?** No. It means the archive has no record of that
CVE, so there is no exploitation evidence to judge it by. Use
`--block-unknown` if that should fail the build.

**Can I get the database for offline use?** No. Queries are online only;
the advisory database is not distributed.

**Why exit 2 on INCOMPLETE?** A package that could not be checked is a gap in
coverage, and a gap must never read as a pass.

**A package with an odd name was "not checked"?** Package names may contain
letters, digits and `@/._:+~-`; versions may not contain spaces or control
characters. A package whose name or version breaks these rules (for example a
hand-edited lockfile entry `€uro`) is not sent — the API would refuse the
whole request — and is listed as not checked; every other package is still
checked.

## Changelog

- **cdgate 0.1.0, gate 0.2.0 (2026-11-19, preview; hosted API live).** Online package query
  (`/sca/query`), `cdgate` with `scan`, `image`, `rootfs`, `sbom` and `gate`;
  fix plan, detection queries and workarounds in the gate; free API keys.

## Tests

```sh
go vet ./...
go test ./...
```

The CLI ↔ API contract is also tested from the API suite
(`cyberdetails.api/tests/test_sca_triage.py`). This file is the single source
for the site's documentation page: after editing it, run
`python cyberdetails.sca/sync_docs.py` (`tests/test_docs_mirror.py` fails until
the site copy matches).

## License

`cdgate` is licensed under the [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0).
The advisory data the hosted API answers from stays under its publishers'
terms; see [cyberdetails.org/sources](https://cyberdetails.org/sources).
