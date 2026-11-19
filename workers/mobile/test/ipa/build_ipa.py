#!/usr/bin/env python3
"""Builds pathos-test.ipa, a deliberately insecure iOS package for the
worker-mobile fixtures: Info.plist with App Transport Security exceptions,
a custom URL scheme and an old MinimumOSVersion; a development provisioning
profile (get-task-allow); and a Mach-O executable (Go, darwin/arm64).

    GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -o PathosTest main.go
    python3 build_ipa.py PathosTest pathos-test.ipa
"""
import plistlib
import sys
import zipfile

exe, out = sys.argv[1], sys.argv[2]
app = "Payload/PathosTest.app/"
info = {
    "CFBundleIdentifier": "org.pathos.testapp", "CFBundleName": "PathosTest", "CFBundleExecutable": "PathosTest",
    "CFBundleShortVersionString": "1.0", "CFBundleVersion": "1", "MinimumOSVersion": "12.0",
    "CFBundleURLTypes": [{"CFBundleURLName": "org.pathos.testapp", "CFBundleURLSchemes": ["pathostest"]}],
    "NSAppTransportSecurity": {
        "NSAllowsArbitraryLoads": True,
        "NSExceptionDomains": {"legacy.pathos-test.invalid": {"NSExceptionAllowsInsecureHTTPLoads": True,
                                                              "NSExceptionMinimumTLSVersion": "TLSv1.0",
                                                              "NSIncludesSubdomains": True}},
    },
}
profile = {"Name": "PATHOS Test Development", "TeamIdentifier": ["PATHOSTEST"],
           "Entitlements": {"application-identifier": "PATHOSTEST.org.pathos.testapp", "get-task-allow": True,
                            "aps-environment": "development", "keychain-access-groups": ["PATHOSTEST.*"]}}
# A real profile is CMS-signed DER around the plist; the checks read the
# embedded XML, so a minimal wrapper is enough here.
mobileprovision = b"\x30\x80PATHOS-TEST-CMS" + plistlib.dumps(profile) + b"\x00\x00"
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
    z.writestr(app + "Info.plist", plistlib.dumps(info, fmt=plistlib.FMT_BINARY))
    z.writestr(app + "embedded.mobileprovision", mobileprovision)
    z.write(exe, app + "PathosTest")
