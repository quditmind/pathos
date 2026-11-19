package scanners

import "slices"

// worker-mobile (workers/mobile): mobile application security testing of
// Android (APK, AAB) and iOS (IPA) packages uploaded as mobile app targets.
// The tools are defined by manifests in workers/mobile/tools.d.

// MobileAppChecks are the PATHOS mobile package checks of the worker-mobile
// image (an androguard-based helper): Android manifest and signing, iOS
// Info.plist and entitlements.
const MobileAppChecks = "mobile-app-checks"

func init() {
	mobile := func(sc *Scanner) {
		sc.AdapterAvailable, sc.TargetOnly, sc.Targets = true, true, []string{"mobile-app"}
	}
	// mobsfscan is in the catalog already; worker-mobile provides it.
	if i := slices.IndexFunc(Catalog, func(sc Scanner) bool { return sc.Key == "mobsfscan" }); i >= 0 {
		sc := &Catalog[i]
		sc.License, sc.Family, sc.OutputFormat = "LGPL-3.0-or-later", "mobile", "sarif"
		sc.Homepage = "https://github.com/MobSF/mobsfscan"
		sc.Notes = "worker-mobile image (tool manifest): runs on the Java sources that jadx decompiles from an APK or AAB; SARIF"
		mobile(sc)
	}
	Catalog = append(Catalog,
		s("apkleaks", "APKLeaks", "mobile", "Apache-2.0", "use", "mobile", mobile, format("json"), home("https://github.com/dwisiswant0/apkleaks"),
			note("worker-mobile image (tool manifest): secrets, URLs and endpoints in an APK (decompiled with jadx); JSON parsed with the apkleaks import parser, secret values redacted")),
		s("quark-engine", "Quark-Engine", "malware", "GPL-3.0-only", "use", "mobile", mobile, format("json"), home("https://github.com/quark-engine/quark-engine"),
			note("worker-mobile image (tool manifest): Android malware behaviour (API call sequences). Ships PATHOS' own Apache-2.0 rules; the community quark-rules set has no licence and is not bundled (an operator can mount it)")),
		s(MobileAppChecks, "Mobile app configuration checks", "mobile", "Apache-2.0", "use", "mobile", mobile, format("json"), home("https://github.com/quditmind/pathos"),
			note("worker-mobile image (PATHOS helper using androguard, Apache-2.0): Android manifest (debuggable, allowBackup, cleartext traffic, exported components without permission, minSdk) and signing schemes; iOS Info.plist (ATS exceptions, URL schemes) and entitlements")),
	)
	TargetScanners["mobile-app"] = []string{BinaryHardening, Cosign}
	mbafAddScanTypeTools("mobile", "apkleaks", "quark-engine", MobileAppChecks)
	mbafAddScanTypeTools("secrets", "apkleaks")
	mbafAddScanTypeTools("malware", "quark-engine")
}

// mbafAddScanTypeTools adds catalog tools to a scan type (used by the
// worker-mobile, -binary, -ai and -fuzz catalog files; the prefix keeps it
// apart from the helpers of other families).
func mbafAddScanTypeTools(id string, keys ...string) {
	for i := range ScanTypes {
		if ScanTypes[i].ID != id {
			continue
		}
		for _, k := range keys {
			if !slices.Contains(ScanTypes[i].Tools, k) {
				ScanTypes[i].Tools = append(ScanTypes[i].Tools, k)
			}
		}
	}
}
