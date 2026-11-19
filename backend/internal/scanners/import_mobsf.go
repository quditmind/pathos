package scanners

import (
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// MobSF static analysis JSON report (REST API /api/v1/report_json, or the
// report's JSON download), Android (APK/AAB/source) and iOS (IPA/source).
// Sections imported, each in its MobSF 3.x/4.x shape and the older one:
//
//   - code_analysis: one finding per rule and source file (first line as
//     location, every reported line in the description)
//   - manifest_analysis, network_security, certificate_analysis,
//     ats_analysis (iOS): one finding per issue
//   - binary_analysis, macho_analysis: one finding per weakness and binary
//   - file_analysis: hard-coded keystores, certificates and similar files
//   - secrets: possible hard-coded secrets ("key" : "value"); the values
//     are replaced by "[REDACTED:<hash>]" before the report is stored
//   - permissions with status "dangerous", open Firebase databases
//
// MobSF's "secure"/"good" results (controls that are in place) and the
// inventories (android_api/ios_api usage, trackers, NIAP, strings, URLs)
// are not findings; they stay in the stored report.

var (
	mobsfSecretRe   = regexp.MustCompile(`^\s*"?([^"]*?)"?\s*:\s*"?(.*?)"?\s*$`)
	mobsfRedactedRe = regexp.MustCompile(`^\[REDACTED:([0-9a-f]{16})\]$`)
)

func init() {
	registerImportFormat(ImportFormat{ID: "mobsf", Label: "MobSF static analysis JSON", Tool: "MobSF", Category: "mobile", Media: "json", Order: 373,
		match: func(p *importProbe) bool {
			return p.kind == "object" && p.has("code_analysis", "app_type", "md5") && p.hasAny("package_name", "bundle_id", "manifest_analysis", "ats_analysis")
		},
		parse:    parseMobSF,
		sanitize: sanitizeMobSF})
}

// mobsfSev maps MobSF levels; ok is false for passed controls.
func mobsfSev(s string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "secure", "good", "pass", "passed":
		return "", false
	case "high", "dangerous", "insecure", "vulnerability":
		return "high", true
	case "warning", "medium":
		return "medium", true
	case "low":
		return "low", true
	case "critical":
		return "critical", true
	}
	return "info", true
}

// mobsfSecret splits a MobSF secret entry and returns its key and the
// identity of its value.
func mobsfSecret(s string) (key, id string) {
	m := mobsfSecretRe.FindStringSubmatch(s)
	key, val := "", s
	if m != nil {
		key, val = strings.TrimSpace(m[1]), m[2]
	}
	if r := mobsfRedactedRe.FindStringSubmatch(val); r != nil {
		return key, r[1]
	}
	return key, hashOf(val)
}

func sanitizeMobSF(raw []byte) []byte {
	var doc map[string]any
	if json.Unmarshal(raw, &doc) != nil {
		return raw
	}
	if secrets, ok := doc["secrets"].([]any); ok {
		for i, v := range secrets {
			if s, ok := v.(string); ok {
				k, id := mobsfSecret(s)
				secrets[i] = fmt.Sprintf("%q : \"[REDACTED:%s]\"", k, id)
			}
		}
	}
	b, err := json.Marshal(redactHTTPIn(doc))
	if err != nil {
		return raw
	}
	return b
}

type mobsfReport struct {
	FileName            string          `json:"file_name"`
	AppName             string          `json:"app_name"`
	PackageName         string          `json:"package_name"`
	BundleID            string          `json:"bundle_id"`
	CodeAnalysis        json.RawMessage `json:"code_analysis"`
	ManifestAnalysis    json.RawMessage `json:"manifest_analysis"`
	NetworkSecurity     json.RawMessage `json:"network_security"`
	CertificateAnalysis struct {
		Findings [][]string `json:"certificate_findings"`
	} `json:"certificate_analysis"`
	ATSAnalysis    json.RawMessage `json:"ats_analysis"`
	BinaryAnalysis json.RawMessage `json:"binary_analysis"`
	MachoAnalysis  json.RawMessage `json:"macho_analysis"`
	FileAnalysis   []struct {
		Finding string `json:"finding"`
		Issue   string `json:"issue"`
		Files   []any  `json:"files"`
	} `json:"file_analysis"`
	Secrets     []string        `json:"secrets"`
	Permissions json.RawMessage `json:"permissions"`
	Firebase    []struct {
		URL  string `json:"url"`
		Open bool   `json:"open"`
	} `json:"firebase_urls"`
}

type mobsfMeta struct {
	CVSS        any    `json:"cvss"`
	CWE         string `json:"cwe"`
	OWASPMobile string `json:"owasp-mobile"`
	MASVS       string `json:"masvs"`
	Ref         string `json:"ref"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
}

func parseMobSF(raw []byte) ([]importRecord, error) {
	var rep mobsfReport
	if err := json.Unmarshal(raw, &rep); err != nil {
		return nil, fmt.Errorf("mobsf: invalid JSON: %w", err)
	}
	app := firstNonEmpty(rep.FileName, rep.PackageName, rep.BundleID, rep.AppName, "app")
	var out []importRecord
	add := func(f Finding, key string, rec any) {
		if f.Category == "" {
			f.Category = "sast"
		}
		f.Title = markupToText(f.Title)
		out = append(out, importRecord{F: f, SnippetKey: hashOf(key), Raw: rawJSON(rec)})
	}

	// Code analysis: {findings: {rule: {files, metadata}}} or {rule: {...}}.
	var code map[string]json.RawMessage
	_ = json.Unmarshal(rep.CodeAnalysis, &code)
	if fs, ok := code["findings"]; ok {
		code = nil
		_ = json.Unmarshal(fs, &code)
	}
	for _, rule := range mobsfKeys(code) {
		var c struct {
			Files    map[string]string `json:"files"`
			Metadata *mobsfMeta        `json:"metadata"`
		}
		if json.Unmarshal(code[rule], &c) != nil || c.Metadata == nil {
			continue
		}
		sev, ok := mobsfSev(c.Metadata.Severity)
		if !ok {
			continue
		}
		files := c.Files
		if len(files) == 0 {
			files = map[string]string{app: ""}
		}
		for _, file := range mobsfKeys(files) {
			lines := mobsfLines(files[file])
			f := Finding{RuleID: "mobsf:" + rule, Title: firstNonEmpty(c.Metadata.Description, rule), Severity: sev,
				FilePath: NormalizePath(file), CWE: []string{c.Metadata.CWE}, CVSS: mobsfScore(c.Metadata.CVSS)}
			if len(lines) > 0 {
				f.StartLine = intPtr(lines[0])
			}
			f.Description = joinText(c.Metadata.Description, labelled("Lines", strings.Trim(strings.Join(strings.Fields(fmt.Sprint(lines)), ", "), "[]")),
				labelled("OWASP Mobile", c.Metadata.OWASPMobile), labelled("MASVS", c.Metadata.MASVS), labelled("Reference", c.Metadata.Ref))
			add(f, "code|"+file, map[string]any{"section": "code_analysis", "rule": rule, "file": file, "lines": files[file], "metadata": c.Metadata})
		}
	}

	// Manifest: {manifest_findings: [...]} or [...] (title/stat/desc).
	for _, m := range mobsfList(rep.ManifestAnalysis, "manifest_findings") {
		sev, ok := mobsfSev(firstNonEmpty(mobsfStr(m["severity"]), mobsfStr(m["stat"])))
		if !ok {
			continue
		}
		title := markupToText(firstNonEmpty(mobsfStr(m["title"]), mobsfStr(m["name"])))
		rule := firstNonEmpty(mobsfStr(m["rule"]), mobsfStr(m["name"]), title)
		f := Finding{RuleID: "mobsf:manifest:" + rule, Title: title, Severity: sev, FilePath: "AndroidManifest.xml",
			Description: markupToText(firstNonEmpty(mobsfStr(m["description"]), mobsfStr(m["desc"])))}
		add(f, "manifest|"+title, m)
	}

	// Network security config: {network_findings: [...]} or [...].
	for _, m := range mobsfList(rep.NetworkSecurity, "network_findings") {
		sev, ok := mobsfSev(mobsfStr(m["severity"]))
		if !ok {
			continue
		}
		desc := mobsfStr(m["description"])
		scope := fmt.Sprint(m["scope"])
		f := Finding{RuleID: "mobsf:network:" + hashOf(desc), Title: clipText(desc, 200), Severity: sev,
			FilePath: "res/xml/network_security_config.xml", Description: joinText(desc, labelled("Scope", scope)), CWE: []string{"CWE-319"}}
		add(f, "network|"+scope, m)
	}

	// Certificate: [severity, description, title] (or [severity, title]).
	for _, c := range rep.CertificateAnalysis.Findings {
		if len(c) < 2 {
			continue
		}
		sev, ok := mobsfSev(c[0])
		if !ok {
			continue
		}
		title := c[len(c)-1]
		f := Finding{RuleID: "mobsf:certificate:" + title, Title: title, Severity: sev, FilePath: app, Description: c[1]}
		add(f, "certificate|"+title, map[string]any{"section": "certificate_analysis", "finding": c})
	}

	// iOS App Transport Security: {ats_findings: [...]} or [...].
	for _, m := range mobsfList(rep.ATSAnalysis, "ats_findings") {
		sev, ok := mobsfSev(firstNonEmpty(mobsfStr(m["severity"]), mobsfStr(m["status"])))
		if !ok {
			continue
		}
		issue := mobsfStr(m["issue"])
		f := Finding{RuleID: "mobsf:ats:" + issue, Title: issue, Severity: sev, FilePath: "Info.plist", Description: mobsfStr(m["description"]), CWE: []string{"CWE-319"}}
		add(f, "ats|"+issue, m)
	}

	// Binary analysis: Android [{name, <check>: {severity, description}}],
	// iOS {findings: {title: {detailed_desc, severity, cvss, cwe}}} or the
	// map itself.
	var binList []map[string]json.RawMessage
	if json.Unmarshal(rep.BinaryAnalysis, &binList) == nil {
		for _, b := range binList {
			out = append(out, mobsfBinaryChecks(b, app)...)
		}
	} else {
		var bin map[string]json.RawMessage
		_ = json.Unmarshal(rep.BinaryAnalysis, &bin)
		if fs, ok := bin["findings"]; ok {
			bin = nil
			_ = json.Unmarshal(fs, &bin)
		}
		for _, title := range mobsfKeys(bin) {
			var b struct {
				DetailedDesc string `json:"detailed_desc"`
				Severity     string `json:"severity"`
				CVSS         any    `json:"cvss"`
				CWE          string `json:"cwe"`
				OWASPMobile  string `json:"owasp-mobile"`
				MASVS        string `json:"masvs"`
			}
			if json.Unmarshal(bin[title], &b) != nil || (b.Severity == "" && b.DetailedDesc == "") {
				continue
			}
			sev, ok := mobsfSev(b.Severity)
			if !ok {
				continue
			}
			f := Finding{RuleID: "mobsf:binary:" + title, Title: title, Severity: sev, FilePath: app, CWE: []string{b.CWE}, CVSS: mobsfScore(b.CVSS),
				Description: joinText(b.DetailedDesc, labelled("OWASP Mobile", b.OWASPMobile), labelled("MASVS", b.MASVS))}
			add(f, "binary|"+title, map[string]any{"section": "binary_analysis", "title": title, "finding": b})
		}
	}
	var macho map[string]json.RawMessage
	if json.Unmarshal(rep.MachoAnalysis, &macho) == nil && len(macho) > 0 {
		out = append(out, mobsfBinaryChecks(macho, app)...)
	}

	// Files (hard-coded keystores, certificates, ...).
	for _, fa := range rep.FileAnalysis {
		issue := firstNonEmpty(fa.Finding, fa.Issue)
		if issue == "" {
			continue
		}
		sev := "info"
		if l := strings.ToLower(issue); strings.Contains(l, "hardcoded") || strings.Contains(l, "keystore") || strings.Contains(l, "key file") {
			sev = "medium"
		}
		for _, x := range fa.Files {
			file := mobsfStr(x)
			if m, ok := x.(map[string]any); ok {
				file = mobsfStr(m["file_path"])
			}
			if file == "" {
				continue
			}
			f := Finding{RuleID: "mobsf:file:" + issue, Title: issue, Severity: sev, FilePath: NormalizePath(file), Description: issue + ": " + file}
			if sev == "medium" {
				f.CWE = []string{"CWE-321"}
			}
			add(f, "file|"+file, map[string]any{"section": "file_analysis", "issue": issue, "file": x})
		}
	}

	// Possible hard-coded secrets.
	for _, s := range rep.Secrets {
		key, id := mobsfSecret(s)
		f := Finding{Category: "secrets", RuleID: "mobsf:secret", Title: "Possible hard-coded secret " + firstNonEmpty(key, "value") + " in " + app,
			Severity: "medium", FilePath: app, CWE: []string{"CWE-798"}, Confidence: "low",
			Description: fmt.Sprintf("MobSF reports the string resource or constant %q as a possible hard-coded secret (value redacted, id %s). Confirm whether it is a credential.", key, id)}
		add(f, "secret|"+key+"|"+id, map[string]any{"section": "secrets", "key": key, "value": "[REDACTED:" + id + "]"})
	}

	// Dangerous permissions: Android {name: {status, info, description}},
	// iOS [{name, status, description, reason}].
	perms := map[string]map[string]any{}
	var permList []map[string]any
	if json.Unmarshal(rep.Permissions, &permList) == nil {
		for _, p := range permList {
			perms[mobsfStr(p["name"])] = p
		}
	} else {
		_ = json.Unmarshal(rep.Permissions, &perms)
	}
	for _, name := range mobsfKeys(perms) {
		p := perms[name]
		if !strings.EqualFold(mobsfStr(p["status"]), "dangerous") || name == "" {
			continue
		}
		f := Finding{RuleID: "mobsf:permission:" + name, Title: "Dangerous permission " + name, Severity: "low", FilePath: app,
			Description: joinText(mobsfStr(p["info"]), mobsfStr(p["description"]), labelled("Reason", mobsfStr(p["reason"])),
				"Review that the app needs this permission.")}
		add(f, "permission|"+name, map[string]any{"section": "permissions", "name": name, "permission": p})
	}

	for _, fb := range rep.Firebase {
		if !fb.Open {
			continue
		}
		f := Finding{RuleID: "mobsf:firebase-open", Title: "Firebase database is publicly readable", Severity: "high", FilePath: locationOf("", fb.URL),
			CWE: []string{"CWE-284"}, Description: "MobSF found the Firebase database " + fb.URL + " open to unauthenticated reads (/.json)."}
		add(f, "firebase|"+fb.URL, map[string]any{"section": "firebase_urls", "url": fb.URL, "open": fb.Open})
	}
	return out, nil
}

// mobsfBinaryChecks turns one binary's checks ({name, nx: {severity,
// description}, ...}) into findings; checks without a weakness are skipped.
func mobsfBinaryChecks(b map[string]json.RawMessage, app string) []importRecord {
	var name string
	_ = json.Unmarshal(b["name"], &name)
	file := NormalizePath(firstNonEmpty(name, app))
	var out []importRecord
	for _, check := range mobsfKeys(b) {
		if check == "name" {
			continue
		}
		var c struct {
			Severity    string `json:"severity"`
			Description string `json:"description"`
		}
		if json.Unmarshal(b[check], &c) != nil || c.Severity == "" {
			continue
		}
		sev, ok := mobsfSev(c.Severity)
		if !ok || sev == "info" {
			// MobSF reports passed hardening checks as info.
			continue
		}
		f := Finding{Category: "sast", RuleID: "mobsf:binary:" + check, Title: "Binary hardening (" + check + "): " + clipText(c.Description, 150),
			Severity: sev, FilePath: file, Description: c.Description}
		out = append(out, importRecord{F: f, SnippetKey: hashOf("binary|" + check),
			Raw: rawJSON(map[string]any{"section": "binary_analysis", "binary": name, "check": check, "result": json.RawMessage(b[check])})})
	}
	return out
}

func mobsfList(raw json.RawMessage, field string) []map[string]any {
	var list []map[string]any
	if json.Unmarshal(raw, &list) == nil {
		return list
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) == nil {
		_ = json.Unmarshal(obj[field], &list)
	}
	return list
}

func mobsfLines(s string) []int {
	var out []int
	for _, p := range strings.Split(s, ",") {
		if n := atoiLoose(p); n > 0 && !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	sort.Ints(out)
	return out
}

func mobsfScore(v any) *float64 {
	switch t := v.(type) {
	case float64:
		return floatPtr(t)
	case string:
		if f, err := strconv.ParseFloat(t, 64); err == nil {
			return floatPtr(f)
		}
	}
	return nil
}

func mobsfStr(v any) string {
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	case []any:
		parts := make([]string, 0, len(t))
		for _, x := range t {
			parts = append(parts, fmt.Sprint(x))
		}
		return strings.Join(parts, " ")
	case nil:
		return ""
	}
	return fmt.Sprint(v)
}

func mobsfKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
