// Package compliance maps findings to controls of security frameworks
// (OWASP Top 10, OWASP ASVS, PCI DSS, ISO/IEC 27001, SOC 2) by finding
// category, CWE and package intelligence. The mapping is indicative: it
// shows which open findings are evidence against a control, not whether an
// organization complies, which only an assessment can decide.
package compliance

import (
	"slices"
	"strings"
)

// Control is one control or requirement of a framework.
type Control struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Categories  []string `json:"categories,omitempty"`
	CWE         []string `json:"cwe,omitempty"`
	Malicious   bool     `json:"malicious,omitempty"`
}

// Framework is a set of controls. ScopeKey is the repository compliance
// scope that puts a repository in the framework's scope ("" = every
// repository).
type Framework struct {
	Key         string    `json:"key"`
	Name        string    `json:"name"`
	Version     string    `json:"version"`
	ScopeKey    string    `json:"scope_key"`
	Description string    `json:"description"`
	Controls    []Control `json:"controls"`
}

func cwes(ids ...int) []string {
	out := make([]string, len(ids))
	for i, n := range ids {
		out[i] = "CWE-" + itoa(n)
	}
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// Commonly mapped CWE groups.
var (
	injection   = cwes(20, 74, 75, 77, 78, 79, 80, 83, 87, 88, 89, 90, 91, 93, 94, 95, 96, 97, 98, 99, 113, 116, 138, 184, 470, 471, 564, 610, 643, 644, 652, 917, 943, 1336)
	accessCtl   = cwes(22, 23, 35, 59, 200, 201, 219, 264, 275, 276, 284, 285, 352, 359, 377, 402, 425, 441, 497, 538, 540, 548, 552, 566, 601, 639, 651, 668, 706, 862, 863, 913, 922, 1275)
	crypto      = cwes(261, 296, 310, 319, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330, 331, 335, 336, 337, 338, 340, 347, 523, 720, 757, 759, 760, 780, 818, 916)
	design      = cwes(73, 183, 209, 213, 235, 256, 257, 266, 269, 280, 311, 312, 313, 316, 419, 430, 434, 444, 451, 472, 501, 522, 525, 539, 579, 598, 602, 642, 646, 650, 653, 656, 657, 799, 807, 840, 841, 927, 1021, 1173)
	misconfig   = cwes(2, 11, 13, 15, 16, 260, 315, 520, 526, 537, 541, 547, 611, 614, 756, 776, 942, 1004, 1032, 1174)
	components  = cwes(937, 1035, 1104)
	authn       = cwes(255, 259, 287, 288, 290, 294, 295, 297, 300, 302, 304, 306, 307, 346, 384, 521, 613, 620, 640, 798, 940, 1216)
	integrity   = cwes(345, 353, 426, 494, 502, 565, 784, 829, 830, 915)
	logging     = cwes(117, 223, 532, 778)
	ssrf        = cwes(918)
	secretsCWE  = cwes(798, 259, 321, 522, 256, 257)
	errorsCWE   = cwes(209, 210, 211, 390, 391, 544, 755)
	filesCWE    = cwes(22, 23, 35, 73, 434, 552, 641)
	apiCWE      = cwes(352, 611, 776, 918, 942, 1021)
	sessionCWE  = cwes(384, 539, 613, 614, 1004, 1275)
	transport   = cwes(295, 297, 319, 523, 757)
	dataProtect = cwes(200, 201, 312, 359, 532, 538, 922)
)

func merge(groups ...[]string) []string {
	var out []string
	for _, g := range groups {
		for _, c := range g {
			if !slices.Contains(out, c) {
				out = append(out, c)
			}
		}
	}
	return out
}

// Frameworks is the built-in catalog.
var Frameworks = []Framework{
	{
		Key: "owasp_top10_2021", Name: "OWASP Top 10", Version: "2021",
		Description: "The ten most critical web application security risks, with the CWEs OWASP maps to each category.",
		Controls: []Control{
			{ID: "A01", Title: "Broken Access Control", CWE: accessCtl},
			{ID: "A02", Title: "Cryptographic Failures", CWE: crypto},
			{ID: "A03", Title: "Injection", CWE: injection},
			{ID: "A04", Title: "Insecure Design", CWE: design},
			{ID: "A05", Title: "Security Misconfiguration", Categories: []string{"iac", "misconfiguration", "binary"}, CWE: misconfig},
			{ID: "A06", Title: "Vulnerable and Outdated Components", Categories: []string{"sca", "container"}, CWE: components},
			{ID: "A07", Title: "Identification and Authentication Failures", Categories: []string{"secrets"}, CWE: authn},
			{ID: "A08", Title: "Software and Data Integrity Failures", Categories: []string{"malware"}, CWE: integrity, Malicious: true},
			{ID: "A09", Title: "Security Logging and Monitoring Failures", CWE: logging},
			{ID: "A10", Title: "Server-Side Request Forgery (SSRF)", CWE: ssrf},
		},
	},
	{
		Key: "owasp_asvs_4", Name: "OWASP ASVS", Version: "4.0.3",
		Description: "Application Security Verification Standard chapters, matched by the CWEs of their requirements.",
		Controls: []Control{
			{ID: "V2", Title: "Authentication", Categories: []string{"secrets"}, CWE: authn},
			{ID: "V3", Title: "Session Management", CWE: sessionCWE},
			{ID: "V4", Title: "Access Control", CWE: accessCtl},
			{ID: "V5", Title: "Validation, Sanitization and Encoding", CWE: injection},
			{ID: "V6", Title: "Stored Cryptography", CWE: crypto},
			{ID: "V7", Title: "Error Handling and Logging", CWE: merge(errorsCWE, logging)},
			{ID: "V8", Title: "Data Protection", CWE: dataProtect},
			{ID: "V9", Title: "Communication", CWE: transport},
			{ID: "V10", Title: "Malicious Code", Categories: []string{"malware"}, CWE: integrity, Malicious: true},
			{ID: "V12", Title: "Files and Resources", CWE: filesCWE},
			{ID: "V13", Title: "API and Web Service", CWE: apiCWE},
			{ID: "V14", Title: "Configuration", Categories: []string{"iac", "sca", "container", "misconfiguration", "binary"}, CWE: misconfig},
		},
	},
	{
		Key: "pci_dss_4", Name: "PCI DSS", Version: "4.0.1", ScopeKey: "pci_dss",
		Description: "Payment Card Industry Data Security Standard requirements on secure software and vulnerability management, for repositories in the PCI DSS compliance scope.",
		Controls: []Control{
			{ID: "2.2.1", Title: "Configuration standards are applied to system components", Categories: []string{"iac", "misconfiguration", "binary"}, CWE: misconfig},
			{ID: "3.5.1", Title: "Stored account data is rendered unreadable (strong cryptography)", CWE: crypto},
			{ID: "4.2.1", Title: "Strong cryptography protects data in transit", CWE: transport},
			{ID: "6.2.4", Title: "Software engineering techniques prevent common software attacks", Categories: []string{"sast", "dast"},
				CWE: merge(injection, accessCtl, ssrf, design)},
			{ID: "6.3.1", Title: "Security vulnerabilities are identified and managed", Categories: []string{"sca", "container", "dast", "sast", "iac", "misconfiguration"}},
			{ID: "6.3.3", Title: "System components are protected from known vulnerabilities by installing patches", Categories: []string{"sca", "container"}, Malicious: true},
			{ID: "6.4.1", Title: "Public-facing web applications are protected against attacks", Categories: []string{"dast"}},
			{ID: "8.3.2", Title: "Strong cryptography renders authentication factors unreadable", CWE: cwes(256, 257, 261, 916)},
			{ID: "8.6.2", Title: "Passwords for system and application accounts are not hard-coded", Categories: []string{"secrets"}, CWE: secretsCWE},
			{ID: "10.2.1", Title: "Audit logs capture events", CWE: logging},
		},
	},
	{
		Key: "iso_27001_2022", Name: "ISO/IEC 27001 Annex A", Version: "2022", ScopeKey: "iso_27001",
		Description: "Annex A controls related to application and supply chain security, for repositories in the ISO 27001 compliance scope.",
		Controls: []Control{
			{ID: "A.5.17", Title: "Authentication information", Categories: []string{"secrets"}, CWE: secretsCWE},
			{ID: "A.5.21", Title: "Managing information security in the ICT supply chain", Categories: []string{"sca", "license", "container", "malware"}, Malicious: true},
			{ID: "A.8.5", Title: "Secure authentication", CWE: authn},
			{ID: "A.8.8", Title: "Management of technical vulnerabilities", Categories: []string{"sca", "container", "dast"}},
			{ID: "A.8.9", Title: "Configuration management", Categories: []string{"iac", "misconfiguration", "binary"}, CWE: misconfig},
			{ID: "A.8.12", Title: "Data leakage prevention", CWE: dataProtect},
			{ID: "A.8.24", Title: "Use of cryptography", CWE: crypto},
			{ID: "A.8.26", Title: "Application security requirements", Categories: []string{"dast"}, CWE: merge(accessCtl, sessionCWE)},
			{ID: "A.8.28", Title: "Secure coding", Categories: []string{"sast"}, CWE: injection},
		},
	},
	{
		Key: "soc2_2017", Name: "SOC 2 Trust Services Criteria", Version: "2017 (rev. 2022)", ScopeKey: "soc_2",
		Description: "Common Criteria related to logical access, malicious software and vulnerability management, for repositories in the SOC 2 compliance scope.",
		Controls: []Control{
			{ID: "CC6.1", Title: "Logical access security software, infrastructure and architectures", Categories: []string{"secrets"}, CWE: merge(authn, accessCtl)},
			{ID: "CC6.7", Title: "Restricts the transmission of information to authorized parties", CWE: merge(transport, dataProtect)},
			{ID: "CC6.8", Title: "Prevents or detects unauthorized or malicious software", Categories: []string{"malware"}, Malicious: true, CWE: integrity},
			{ID: "CC7.1", Title: "Detects configuration changes and newly discovered vulnerabilities", Categories: []string{"sca", "container", "iac", "dast", "sast", "misconfiguration"}},
			{ID: "CC8.1", Title: "Changes are authorized, designed, tested and approved", Categories: []string{"iac", "misconfiguration"}, CWE: misconfig},
		},
	},
}

// Lookup returns a framework by key.
func Lookup(key string) (Framework, bool) {
	for _, f := range Frameworks {
		if f.Key == key {
			return f, true
		}
	}
	return Framework{}, false
}

// LookupControl resolves "<framework>:<control>".
func LookupControl(ref string) (Framework, Control, bool) {
	fk, cid, ok := strings.Cut(ref, ":")
	if !ok {
		return Framework{}, Control{}, false
	}
	f, ok := Lookup(fk)
	if !ok {
		return Framework{}, Control{}, false
	}
	for _, c := range f.Controls {
		if c.ID == cid {
			return f, c, true
		}
	}
	return Framework{}, Control{}, false
}

// MatchSQL renders a control's mapping as a SQL condition on findings f,
// appending bound values. It never matches when the control has no mapping.
func MatchSQL(c Control, placeholder func(v any) string) string {
	var parts []string
	if len(c.Categories) > 0 {
		parts = append(parts, "f.category = ANY("+placeholder(c.Categories)+"::text[])")
	}
	if len(c.CWE) > 0 {
		parts = append(parts, "f.cwe && "+placeholder(c.CWE)+"::text[]")
	}
	if c.Malicious {
		parts = append(parts, "f.malicious")
	}
	if len(parts) == 0 {
		return "false"
	}
	return "(" + strings.Join(parts, " OR ") + ")"
}

// ScopeSQL restricts findings to repositories in a framework's scope.
func ScopeSQL(f Framework, placeholder func(v any) string) string {
	if f.ScopeKey == "" {
		return "true"
	}
	return "EXISTS (SELECT 1 FROM repository_compliance_scopes cs WHERE cs.repository_id = f.repository_id AND cs.scope_key = " + placeholder(f.ScopeKey) + ")"
}
