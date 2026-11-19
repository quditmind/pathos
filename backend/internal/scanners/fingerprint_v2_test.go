package scanners

import "testing"

// Fingerprint version 2: dependency findings of the same package and
// vulnerability merge across tools that name the package or version
// differently. Regression (benchmark 2026-11-19): 18 of 84 merged SCA
// findings were duplicates (Grype's Maven artifact without group, Go
// versions without "v").
func TestFingerprintV2PackageIdentity(t *testing.T) {
	sca := func(key, pkg, ver string) Finding {
		return Finding{ScannerKey: key, Category: "sca", RuleID: "X", CVE: "CVE-2021-44228", PackageName: pkg, PackageVersion: ver, FilePath: "app/pom.xml"}
	}
	same := [][2]Finding{
		{sca("trivy-fs", "golang.org/x/text", "v0.3.5"), sca("osv-scanner", "golang.org/x/text", "0.3.5")},
		{sca("pip-audit", "PyYAML", "5.3.1"), sca("trivy-fs", "pyyaml", "5.3.1")},
		{sca("pip-audit", "zope.interface", "5.0"), sca("trivy-fs", "zope-interface", "5.0")},
		{sca("pip-audit", "typing_extensions", "4.0"), sca("trivy-fs", "Typing-Extensions", "4.0")},
		{sca("npm-audit", "@Babel/core", "7.0.0"), sca("trivy-fs", "@babel/core", "7.0.0")},
	}
	for _, p := range same {
		if Fingerprint(p[0], "") != Fingerprint(p[1], "") {
			t.Errorf("%s@%s and %s@%s must merge", p[0].PackageName, p[0].PackageVersion, p[1].PackageName, p[1].PackageVersion)
		}
	}
	differ := [][2]Finding{
		{sca("trivy-fs", "lodash", "4.17.15"), sca("trivy-fs", "lodash", "4.17.21")},
		{sca("trivy-fs", "log4j-core", "2.14.1"), sca("trivy-fs", "org.apache.logging.log4j:log4j-core", "2.14.1")},
		{sca("trivy-fs", "vue", "3.0.0"), sca("trivy-fs", "vue", "3.0.0-beta")},
	}
	for _, p := range differ {
		if Fingerprint(p[0], "") == Fingerprint(p[1], "") {
			t.Errorf("%s@%s and %s@%s must not merge", p[0].PackageName, p[0].PackageVersion, p[1].PackageName, p[1].PackageVersion)
		}
	}
	// Non-dependency findings keep their version 1 fingerprint.
	f := Finding{ScannerKey: "opengrep", Category: "sast", RuleID: "r", FilePath: "a.py", PackageName: "Ignored_Name"}
	setFingerprint(&f, "k")
	if f.LegacyFingerprint != "" || f.Fingerprint != LegacyFingerprint(f, "k") {
		t.Errorf("SAST fingerprint changed: %+v", f)
	}
	// A dependency finding whose identity is already normalized has no
	// legacy fingerprint; one that changed keeps the old one.
	f = sca("trivy-fs", "lodash", "4.17.15")
	setFingerprint(&f, "")
	if f.LegacyFingerprint != "" {
		t.Error("unchanged identity: no legacy fingerprint")
	}
	f = sca("trivy-fs", "zope.interface", "5.0")
	setFingerprint(&f, "")
	if f.LegacyFingerprint == "" || f.LegacyFingerprint == f.Fingerprint || !f.Matches(f.LegacyFingerprint) || !f.Matches(f.Fingerprint) || f.Matches("") {
		t.Errorf("legacy fingerprint: %+v", f)
	}
}

func TestGrypeMavenGroupFromPURL(t *testing.T) {
	raw := []byte(`{"matches":[{"vulnerability":{"id":"GHSA-jfh8-c2jp-5v3q","severity":"Critical"},
	  "relatedVulnerabilities":[{"id":"CVE-2021-44228"}],
	  "artifact":{"name":"log4j-core","version":"2.14.1","type":"java-archive","locations":[{"path":"/work/j/src/svc/pom.xml"}],
	    "purl":"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"}},
	 {"vulnerability":{"id":"GHSA-p6mc-m468-83gw","severity":"High"},"relatedVulnerabilities":[{"id":"CVE-2020-8203"}],
	  "artifact":{"name":"lodash","version":"4.17.15","type":"npm","locations":[{"path":"/package-lock.json"}],"purl":"pkg:npm/lodash@4.17.15"}}]}`)
	fs, err := ParseGrypeJSON(raw)
	if err != nil || len(fs) != 2 {
		t.Fatalf("%v %d", err, len(fs))
	}
	g := fs[0]
	if g.PackageName != "org.apache.logging.log4j:log4j-core" || g.FilePath != "svc/pom.xml" {
		t.Errorf("maven: %+v", g)
	}
	trivy := Finding{ScannerKey: "trivy-fs", Category: "sca", RuleID: "CVE-2021-44228", CVE: "CVE-2021-44228",
		PackageName: "org.apache.logging.log4j:log4j-core", PackageVersion: "2.14.1", FilePath: "svc/pom.xml"}
	if g.Fingerprint != Fingerprint(trivy, "") {
		t.Error("Grype and Trivy findings of the same Maven package must merge")
	}
	old := Finding{ScannerKey: Grype, Category: "sca", RuleID: "GHSA-jfh8-c2jp-5v3q", CVE: "CVE-2021-44228",
		PackageName: "log4j-core", PackageVersion: "2.14.1", FilePath: "svc/pom.xml"}
	if g.LegacyFingerprint != LegacyFingerprint(old, "") {
		t.Error("the legacy fingerprint is the one stored before (artifact name only)")
	}
	if fs[1].PackageName != "lodash" || fs[1].LegacyFingerprint != "" {
		t.Errorf("npm: %+v", fs[1])
	}
	for _, c := range []struct{ purl, g, a string }{
		{"pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.9.10?type=jar", "com.fasterxml.jackson.core", "jackson-databind"},
		{"pkg:npm/lodash@1", "", ""}, {"pkg:maven/onlyname@1", "", ""},
	} {
		g, a, _ := mavenPURL(c.purl)
		if g != c.g || a != c.a {
			t.Errorf("%s: %q %q", c.purl, g, a)
		}
	}
}
