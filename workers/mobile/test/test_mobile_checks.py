"""Tests of the PATHOS mobile app checks (workers/mobile/bin/pathos_mobile_checks.py).

Run in the worker-mobile image (androguard installed):

    docker run --rm --network none --entrypoint /opt/pathos/mobile/bin/python \
      -v $PWD/workers/mobile:/m:ro pathos-worker-mobile:dev -m unittest discover -s /m/test -v

The APK is test/apk/pathos-test.apk, built from test/apk (build.sh); the IPA
is generated here with a synthetic Mach-O whose code signature carries
entitlements.
"""
import json
import os
import plistlib
import struct
import sys
import tempfile
import unittest
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "bin"))

import pathos_mobile_checks as mc  # noqa: E402


def macho_with_entitlements(ent):
    """A minimal 64-bit Mach-O with one LC_CODE_SIGNATURE load command whose
    superblob holds an entitlements blob."""
    xml = plistlib.dumps(ent)
    blob = struct.pack(">II", 0xFADE7171, 8 + len(xml)) + xml
    superblob = struct.pack(">III", 0xFADE0CC0, 12 + 8 + len(blob), 1) + struct.pack(">II", 5, 20) + blob
    header_size, cmd_size = 32, 16
    sig_off = header_size + cmd_size
    header = struct.pack("<IIIIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 1, cmd_size, 0, 0)
    cmd = struct.pack("<IIII", 0x1D, cmd_size, sig_off, len(superblob))
    return header + cmd + superblob


def build_ipa(path, info, exe=None, profile=None):
    app = "Payload/Test.app/"
    with zipfile.ZipFile(path, "w") as z:
        z.writestr(app + "Info.plist", plistlib.dumps(info))
        if exe is not None:
            z.writestr(app + info["CFBundleExecutable"], exe)
        if profile is not None:
            z.writestr(app + "embedded.mobileprovision", b"\x30\x80CMS" + plistlib.dumps(profile))


def load(path):
    with open(path) as f:
        return json.load(f)


def ids(report):
    return sorted(f["id"] for f in report["findings"])


class AndroidChecks(unittest.TestCase):
    def test_test_apk(self):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "out.json")
            self.assertEqual(mc.main(["x", os.path.join(HERE, "apk", "pathos-test.apk"), out]), 0)
            rep = load(out)
        self.assertEqual(rep["packages"], [{"file": "pathos-test.apk", "id": "org.pathos.testapp"}])
        got = ids(rep)
        for want in ("ANDROID-DEBUGGABLE", "ANDROID-ALLOW-BACKUP", "ANDROID-CLEARTEXT-TRAFFIC", "ANDROID-MIN-SDK",
                     "ANDROID-EXPORTED-ACTIVITY", "ANDROID-EXPORTED-SERVICE", "ANDROID-EXPORTED-PROVIDER", "ANDROID-SIGNING-V1-ONLY"):
            self.assertIn(want, got)
        comps = {f["component"] for f in rep["findings"] if f["id"].startswith("ANDROID-EXPORTED")}
        # The launcher activity and the receiver protected by a permission
        # are not reported.
        self.assertEqual(comps, {".AdminActivity", ".SyncService", ".NotesProvider"})
        sev = {f["id"]: f["severity"] for f in rep["findings"]}
        self.assertEqual(sev["ANDROID-DEBUGGABLE"], "high")
        self.assertEqual(sev["ANDROID-SIGNING-V1-ONLY"], "high")  # minSdk 19 < 24: Janus
        self.assertEqual(sev["ANDROID-EXPORTED-PROVIDER"], "high")
        for f in rep["findings"]:
            self.assertTrue(f["file"].startswith("pathos-test.apk!/"))
            self.assertTrue(f["cwe"].startswith("CWE-"))

    def test_exported_rules(self):
        from lxml import etree

        ns = "http://schemas.android.com/apk/res/android"
        attr = lambda el, name: el.get("{%s}%s" % (ns, name))  # noqa: E731

        # Intent filter without android:exported: exported before Android 12.
        svc = etree.fromstring('<service xmlns:android="%s" android:name=".S"><intent-filter><action android:name="a"/>'
                               '</intent-filter></service>' % ns)
        self.assertIsNotNone(mc.exported_component(svc, "service", 30, attr))
        # Not exported, or protected by a permission.
        off = etree.fromstring('<service xmlns:android="%s" android:name=".S" android:exported="false"/>' % ns)
        self.assertIsNone(mc.exported_component(off, "service", 30, attr))
        perm = etree.fromstring('<provider xmlns:android="%s" android:name=".P" android:exported="true" '
                                'android:readPermission="p"/>' % ns)
        self.assertIsNone(mc.exported_component(perm, "provider", 30, attr))
        # Providers were exported by default before API 17.
        old = etree.fromstring('<provider xmlns:android="%s" android:name=".P"/>' % ns)
        self.assertIsNotNone(mc.exported_component(old, "provider", 16, attr))
        self.assertIsNone(mc.exported_component(old, "provider", 17, attr))

    def test_not_a_package_and_aab(self):
        with tempfile.TemporaryDirectory() as d:
            bad = os.path.join(d, "bad.apk")
            with open(bad, "wb") as f:
                f.write(b"not a zip")
            aab = os.path.join(d, "app.aab")
            with zipfile.ZipFile(aab, "w") as z:
                z.writestr("base/manifest/AndroidManifest.xml", b"\x0a\x00")
            out = os.path.join(d, "out.json")
            mc.main(["x", d, out])
            rep = load(out)
        self.assertEqual(ids(rep), ["MOBILE-AAB-NOT-CHECKED", "MOBILE-NOT-A-PACKAGE"])


class IOSChecks(unittest.TestCase):
    def test_ipa(self):
        info = {"CFBundleIdentifier": "org.example.app", "CFBundleExecutable": "App", "MinimumOSVersion": "12.1",
                "CFBundleURLTypes": [{"CFBundleURLSchemes": ["exampleapp", "fb123"]}],
                "NSAppTransportSecurity": {"NSAllowsArbitraryLoadsInWebContent": True, "NSExceptionDomains": {
                    "old.example.com": {"NSExceptionMinimumTLSVersion": "TLSv1.1"},
                    "ok.example.com": {"NSIncludesSubdomains": True}}}}
        exe = macho_with_entitlements({"get-task-allow": True, "keychain-access-groups": ["TEAM.*"]})
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "app.ipa")
            build_ipa(p, info, exe, profile={"Entitlements": {"aps-environment": "development"}})
            out = os.path.join(d, "out.json")
            mc.main(["x", p, out])
            rep = load(out)
        self.assertEqual(rep["packages"], [{"file": "app.ipa", "id": "org.example.app"}])
        self.assertEqual(ids(rep), ["IOS-APS-DEVELOPMENT", "IOS-ATS-ALLOWSARBITRARYLOADSINWEBCONTENT", "IOS-ATS-EXCEPTION-DOMAIN",
                                    "IOS-GET-TASK-ALLOW", "IOS-KEYCHAIN-WILDCARD", "IOS-MINIMUM-OS", "IOS-URL-SCHEME", "IOS-URL-SCHEME"])
        domains = [f["component"] for f in rep["findings"] if f["id"] == "IOS-ATS-EXCEPTION-DOMAIN"]
        self.assertEqual(domains, ["old.example.com"])
        # Code signature entitlements win over the profile's and name the executable.
        gta = [f for f in rep["findings"] if f["id"] == "IOS-GET-TASK-ALLOW"][0]
        self.assertTrue(gta["file"].endswith("Payload/Test.app/App"))

    def test_fat_binary_and_garbage(self):
        thin = macho_with_entitlements({"get-task-allow": True})
        fat = struct.pack(">II", 0xCAFEBABE, 1) + struct.pack(">IIIII", 0x0100000C, 0, 64, len(thin), 14)
        fat += b"\x00" * (64 - len(fat)) + thin
        self.assertEqual(mc.macho_entitlements(fat), {"get-task-allow": True})
        self.assertEqual(mc.macho_entitlements(b"\x00" * 64), {})
        self.assertEqual(mc.macho_entitlements(thin[:40]), {})

    def test_secure_ipa_has_no_findings(self):
        info = {"CFBundleIdentifier": "org.example.safe", "CFBundleExecutable": "App", "MinimumOSVersion": "16.0"}
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "safe.ipa")
            build_ipa(p, info, macho_with_entitlements({"get-task-allow": False}))
            out = os.path.join(d, "out.json")
            mc.main(["x", p, out])
            self.assertEqual(load(out)["findings"], [])


if __name__ == "__main__":
    unittest.main()
