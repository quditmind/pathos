package scanners

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Microsoft Defender Vulnerability Management (Defender for Endpoint API):
// the software vulnerabilities export (GET
// /api/machines/SoftwareVulnerabilitiesByMachine: deviceName, deviceId,
// osPlatform, softwareVendor, softwareName, softwareVersion, cveId,
// vulnerabilitySeverityLevel, cvssScore, recommendedSecurityUpdate,
// diskPaths) and the per-machine list (GET
// /api/vulnerabilities/machinesVulnerabilities: machineId, cveId,
// productName, productVendor, productVersion, severity, fixingKbId), as
// {"value": [...]} or the bare array. Each row is one CVE on one device.

type mdvmRow struct {
	ID              string   `json:"id"`
	CVE             string   `json:"cveId"`
	DeviceName      string   `json:"deviceName"`
	DeviceID        string   `json:"deviceId"`
	MachineID       string   `json:"machineId"`
	OSPlatform      string   `json:"osPlatform"`
	SoftwareVendor  string   `json:"softwareVendor"`
	SoftwareName    string   `json:"softwareName"`
	SoftwareVersion string   `json:"softwareVersion"`
	ProductVendor   string   `json:"productVendor"`
	ProductName     string   `json:"productName"`
	ProductVersion  string   `json:"productVersion"`
	Severity        string   `json:"vulnerabilitySeverityLevel"`
	Severity2       string   `json:"severity"`
	CVSS            float64  `json:"cvssScore"`
	Update          string   `json:"recommendedSecurityUpdate"`
	UpdateURL       string   `json:"recommendedSecurityUpdateUrl"`
	FixingKB        string   `json:"fixingKbId"`
	DiskPaths       []string `json:"diskPaths"`
	Exploitability  string   `json:"exploitabilityLevel"`
}

func isMDVMRow(m map[string]json.RawMessage) bool {
	return hasKeys(m, "cveId") && (hasKeys(m, "deviceId", "softwareName") || hasKeys(m, "machineId", "productName"))
}

func init() {
	registerImportFormat(ImportFormat{ID: "defender-vm", Label: "Microsoft Defender Vulnerability Management JSON (software vulnerabilities by machine)",
		Tool: "Microsoft Defender VM", Category: "sca", Media: "json", Order: 607,
		match: func(p *importProbe) bool {
			return (p.kind == "array" && isMDVMRow(p.keys)) || (p.kind == "object" && isMDVMRow(p.firstOf("value")))
		},
		parse: parseDefenderVM})
}

func parseDefenderVM(raw []byte) ([]importRecord, error) {
	items, err := jsonArray(raw, "value")
	if err != nil {
		return nil, fmt.Errorf("defender vm: invalid JSON: %w", err)
	}
	var out []importRecord
	for i, it := range items {
		var r mdvmRow
		if err := json.Unmarshal(it, &r); err != nil || r.CVE == "" {
			return out, fmt.Errorf("defender vm: row %d: expected cveId", i+1)
		}
		name, version := firstNonEmpty(r.SoftwareName, r.ProductName), firstNonEmpty(r.SoftwareVersion, r.ProductVersion)
		f := Finding{Category: "sca", RuleID: r.CVE, CVE: r.CVE, Severity: firstNonEmpty(r.Severity, r.Severity2), CVSS: floatPtr(r.CVSS),
			PackageName: name, PackageVersion: version, FilePath: firstNonEmpty(r.DeviceName, r.DeviceID, r.MachineID),
			Title: fmt.Sprintf("%s in %s %s", r.CVE, name, version)}
		kb := r.FixingKB
		if kb != "" && !strings.HasPrefix(strings.ToUpper(kb), "KB") {
			kb = "KB" + kb
		}
		f.Description = joinText(fmt.Sprintf("%s %s %s on %s (%s).", firstNonEmpty(r.SoftwareVendor, r.ProductVendor), name, version, f.FilePath, r.OSPlatform),
			labeled("Recommended update", firstNonEmpty(r.Update, kb)), r.UpdateURL, labeled("Paths", strings.Join(r.DiskPaths, ", ")),
			labeled("Exploitability", r.Exploitability))
		out = append(out, importRecord{F: f, Raw: it})
	}
	return out, nil
}
