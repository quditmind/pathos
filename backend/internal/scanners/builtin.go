package scanners

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"pathos/internal/platform/logging"
)

// Checks built into PATHOS (not third-party scanner integrations, so they
// are not counted among the 52 catalog entries).
const (
	// EndpointCheck verifies a repository's declared public endpoints
	// (DNS, reachability, TLS, security headers). Built into the worker.
	EndpointCheck = "pathos-endpoints"
	// Cosign verifies Sigstore signatures and attestations of image and
	// artifact targets.
	Cosign = "cosign"
	// EndOfLife marks findings derived from the endoflife.date feed; it is
	// not run by a worker.
	EndOfLife = "endoflife"
)

// Builtins are synced into the scanner catalog with the integrations.
var Builtins = []Scanner{
	{Key: EndpointCheck, Name: "PATHOS endpoint verification", Category: "dast", License: "Apache-2.0", Decision: "use", Family: "core", Network: "target",
		AdapterAvailable: true, TargetOnly: true, OutputFormat: "json", Homepage: "https://github.com/quditmind/pathos",
		Notes: "Built into the worker: DNS, reachability, TLS (certificate, protocols, ciphers), HSTS and security headers of a repository's declared public endpoints; opt-in and authorized per repository"},
	{Key: Cosign, Name: "Sigstore cosign", Category: "supply-chain", License: "Apache-2.0", Decision: "use", Family: "core", Network: "registry",
		AdapterAvailable: true, TargetOnly: true, OutputFormat: "json", Homepage: "https://github.com/sigstore/cosign",
		Notes: "Verifies signatures and in-toto/SLSA attestations of container image and artifact targets (key-based or keyless)"},
	{Key: EndOfLife, Name: "endoflife.date", Category: "eol", License: "MIT", Decision: "use", Family: "intel", Network: "none",
		OutputFormat: "json", Homepage: "https://endoflife.date",
		Notes: "End-of-life findings from the endoflife.date intelligence feed (opt-in); not a worker tool"},
}

// --- endpoint verification report ------------------------------------------

// EndpointReport is the pathos-endpoints output.
type EndpointReport struct {
	Version   int              `json:"version"`
	Endpoints []EndpointResult `json:"endpoints"`
}

// EndpointResult is the verification of one declared endpoint.
type EndpointResult struct {
	Kind   string `json:"kind"`  // url | domain | ip
	Value  string `json:"value"` // as declared
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
	// Checks holds the observations (DNS, HTTP, TLS, headers).
	Checks map[string]any  `json:"checks"`
	Issues []EndpointIssue `json:"issues,omitempty"`
}

// EndpointIssue is a problem found on an endpoint.
type EndpointIssue struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Severity    string   `json:"severity"`
	Description string   `json:"description"`
	Location    string   `json:"location"`
	CWE         []string `json:"cwe,omitempty"`
}

// EndpointStatuses are the verification outcomes.
var EndpointStatuses = []string{"verified", "unreachable", "dns_failed", "blocked", "skipped", "error"}

// ParseEndpointReport reads and validates a pathos-endpoints report.
func ParseEndpointReport(raw []byte) (EndpointReport, error) {
	var rep EndpointReport
	if err := json.Unmarshal(raw, &rep); err != nil {
		return rep, fmt.Errorf("pathos-endpoints: invalid JSON: %w", err)
	}
	if rep.Version != 1 {
		return rep, errors.New("pathos-endpoints: unsupported report version")
	}
	if len(rep.Endpoints) > 1000 {
		return rep, errors.New("pathos-endpoints: too many endpoints")
	}
	for i, e := range rep.Endpoints {
		valid := false
		for _, s := range EndpointStatuses {
			valid = valid || e.Status == s
		}
		if !valid || (e.Kind != "url" && e.Kind != "domain" && e.Kind != "ip") || e.Value == "" || len(e.Value) > 2048 {
			return rep, fmt.Errorf("pathos-endpoints: endpoint %d is invalid", i)
		}
	}
	return rep, nil
}

func parseEndpoints(raw []byte) ([]Finding, error) {
	rep, err := ParseEndpointReport(raw)
	if err != nil {
		return nil, err
	}
	var out []Finding
	for _, e := range rep.Endpoints {
		for _, is := range e.Issues {
			if is.ID == "" || is.Title == "" {
				continue
			}
			f := Finding{ScannerKey: EndpointCheck, Category: "dast", RuleID: truncate("endpoint/"+is.ID, 300),
				Title: truncate(logging.RedactString(is.Title), 300), Description: truncate(logging.RedactString(is.Description), 4000),
				Severity: severityOrInfo(is.Severity), FilePath: locationOf("", firstNonEmpty(is.Location, e.Value)),
				// Observed directly (certificate, protocol, response headers).
				Confidence: "high"}
			for _, c := range is.CWE {
				if m := firstMatch(cweRe, c); m != "" {
					f.CWE = append(f.CWE, "CWE-"+m)
				}
			}
			f.Fingerprint = Fingerprint(f, "")
			out = append(out, f)
		}
	}
	return out, nil
}

func severityOrInfo(s string) string {
	switch s = strings.ToLower(s); s {
	case "critical", "high", "medium", "low", "info":
		return s
	}
	return "info"
}

// --- signature verification report -----------------------------------------

// SignatureReport is the cosign adapter output: the verification evidence
// of one image or artifact.
type SignatureReport struct {
	Version int    `json:"version"`
	Subject string `json:"subject"` // image reference or artifact file name
	Mode    string `json:"mode"`    // none | key | keyless
	// Status: verified, unsigned, invalid, skipped or error.
	Status   string `json:"status"`
	Detail   string `json:"detail,omitempty"`
	Required bool   `json:"required"`
	// Offline: the transparency log was not consulted.
	Offline    bool                `json:"offline,omitempty"`
	Signatures []SignatureIdentity `json:"signatures,omitempty"`
	// Attestation verification (in-toto / SLSA), when configured.
	Attestation *AttestationResult `json:"attestation,omitempty"`
}

// SignatureIdentity is one verified signature.
type SignatureIdentity struct {
	Digest   string `json:"digest,omitempty"`
	Identity string `json:"identity,omitempty"` // certificate subject (keyless)
	Issuer   string `json:"issuer,omitempty"`   // OIDC issuer (keyless)
	KeyID    string `json:"key_id,omitempty"`
}

// AttestationResult is an attestation verification.
type AttestationResult struct {
	Type          string `json:"type"`
	Status        string `json:"status"` // verified | missing | invalid | skipped | error
	Detail        string `json:"detail,omitempty"`
	PredicateType string `json:"predicate_type,omitempty"`
	BuilderID     string `json:"builder_id,omitempty"`
	SourceRepo    string `json:"source_repository,omitempty"`
}

// SignatureStatuses are the verification outcomes.
var SignatureStatuses = []string{"verified", "unsigned", "invalid", "skipped", "error"}

// ParseSignatureReport reads and validates a cosign adapter report.
func ParseSignatureReport(raw []byte) (SignatureReport, error) {
	var rep SignatureReport
	if err := json.Unmarshal(raw, &rep); err != nil {
		return rep, fmt.Errorf("cosign: invalid JSON: %w", err)
	}
	if rep.Version != 1 {
		return rep, errors.New("cosign: unsupported report version")
	}
	ok := false
	for _, s := range SignatureStatuses {
		ok = ok || rep.Status == s
	}
	if !ok || (rep.Mode != "none" && rep.Mode != "key" && rep.Mode != "keyless") {
		return rep, errors.New("cosign: invalid status or mode")
	}
	if a := rep.Attestation; a != nil {
		switch a.Status {
		case "verified", "missing", "invalid", "skipped", "error":
		default:
			return rep, errors.New("cosign: invalid attestation status")
		}
	}
	if len(rep.Signatures) > 50 {
		rep.Signatures = rep.Signatures[:50]
	}
	return rep, nil
}

// parseSignature creates a finding only when the target requires a valid
// signature (or attestation) and verification did not succeed. The
// verification evidence itself is kept as the raw report.
func parseSignature(raw []byte) ([]Finding, error) {
	rep, err := ParseSignatureReport(raw)
	if err != nil {
		return nil, err
	}
	if !rep.Required {
		return nil, nil
	}
	subject := truncate(firstNonEmpty(rep.Subject, "target"), 1000)
	var out []Finding
	if rep.Status != "verified" {
		title := "Signature required but not verified"
		switch rep.Status {
		case "unsigned":
			title = "Required signature missing"
		case "invalid":
			title = "Signature verification failed"
		case "skipped":
			title = "Required signature could not be verified (verification skipped)"
		}
		f := Finding{ScannerKey: Cosign, Category: "supply-chain", RuleID: "signature/" + rep.Status, Title: title, Severity: "high",
			Description: truncate(logging.RedactString("The target requires a valid Sigstore signature ("+rep.Mode+" verification). Result: "+
				rep.Status+". "+rep.Detail), 4000),
			FilePath: subject, Confidence: "high", CWE: []string{"CWE-345"}}
		f.Fingerprint = Fingerprint(f, "")
		out = append(out, f)
	}
	if a := rep.Attestation; a != nil && a.Status != "verified" && a.Status != "skipped" {
		f := Finding{ScannerKey: Cosign, Category: "supply-chain", RuleID: "attestation/" + a.Status,
			Title: "Required " + firstNonEmpty(a.Type, "provenance") + " attestation not verified", Severity: "medium",
			Description: truncate(logging.RedactString("Attestation verification result: "+a.Status+". "+a.Detail), 4000),
			FilePath:    subject, Confidence: "high", CWE: []string{"CWE-345"}}
		f.Fingerprint = Fingerprint(f, "")
		out = append(out, f)
	}
	return out, nil
}
