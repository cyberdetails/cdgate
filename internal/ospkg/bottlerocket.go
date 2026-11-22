package ospkg

// Bottlerocket: the software inventory under the target sys-root, matched by
// binary package name and epoch:version-release (trivy 00b7394
// pkg/fanal/analyzer/pkg/bottlerocket_inventory, pkg/detector/ospkg/bottlerocket).

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"time"
)

// bottlerocketOSRelease and bottlerocketInventory are Trivy's required files,
// in the same order.
var (
	bottlerocketOSRelease = []string{
		"aarch64-bottlerocket-linux-gnu/sys-root/usr/lib/os-release",
		"x86_64-bottlerocket-linux-gnu/sys-root/usr/lib/os-release",
	}
	bottlerocketInventory = []string{
		"aarch64-bottlerocket-linux-gnu/sys-root/usr/share/bottlerocket/application-inventory.json",
		"x86_64-bottlerocket-linux-gnu/sys-root/usr/share/bottlerocket/application-inventory.json",
	}
)

func init() {
	Paths = append(Paths, bottlerocketOSRelease...)
	Paths = append(Paths, bottlerocketInventory...)
}

// Same field set and types as Trivy's ApplicationInventory, so encoding/json
// accepts and rejects exactly the same documents (a malformed InstalledTime
// fails the file there too).
type bottlerocketApps struct {
	Content []struct {
		Name          string    `json:"Name"`
		Version       string    `json:"Version"`
		Release       string    `json:"Release"`
		Epoch         string    `json:"Epoch"`
		InstalledTime time.Time `json:"InstalledTime"`
	} `json:"Content"`
}

// rpmVersionString is Trivy's scan/utils formatVersion.
func rpmVersionString(epoch int, version, release string) string {
	v := version
	if release != "" {
		v = fmt.Sprintf("%s-%s", v, release)
	}
	if epoch != 0 {
		v = fmt.Sprintf("%d:%s", epoch, v)
	}
	return v
}

// parseBottlerocket reads one inventory file. Deliberate difference: Trivy logs
// a decode or epoch error at debug level and scans on without the file's
// packages (a clean-looking report); here it is an error.
func parseBottlerocket(b []byte, skipped map[string]int) ([]pkgInfo, error) {
	var inv bottlerocketApps
	if err := json.NewDecoder(bytes.NewReader(b)).Decode(&inv); err != nil {
		return nil, fmt.Errorf("bottlerocket application inventory: %w", err)
	}
	var out []pkgInfo
	for _, a := range inv.Content {
		epoch := 0
		if a.Epoch != "" {
			e, err := strconv.Atoi(a.Epoch)
			if err != nil {
				return nil, fmt.Errorf("bottlerocket application inventory: epoch %q: %w", a.Epoch, err)
			}
			epoch = e
		}
		v := rpmVersionString(epoch, a.Version, a.Release)
		switch {
		case a.Name == "":
			skipped["no_name"]++ // Trivy looks up an empty name and finds nothing
		case v == "":
			skipped["invalid_version"]++ // Trivy: installed == "" is skipped
		default:
			out = append(out, pkgInfo{name: a.Name, version: v, srcName: a.Name, srcVersion: v})
		}
	}
	return out, nil
}
