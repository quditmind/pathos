"""PATHOS mobile app configuration checks (scanner key mobile-app-checks).

Reads Android (APK) and iOS (IPA) packages and reports insecure
configuration as JSON:

  {"tool": "mobile-app-checks", "version": 1, "packages": [...],
   "findings": [{"id", "title", "severity", "description", "file",
                 "component", "cwe", "masvs", "evidence", "package"}]}

Android (androguard): debuggable, allowBackup, cleartext traffic (manifest
and network security configuration), exported components without a
permission, minSdkVersion, signing schemes (v1 only, debug certificate,
unsigned). iOS: App Transport Security exceptions, custom URL schemes,
entitlements (embedded.mobileprovision and the executable's code
signature) and the minimum iOS version. Binary hardening of native code is
reported by PATHOS' binary-hardening scanner, not here.

Nothing in the package is executed; archives are read with zipfile within
size limits. Usage: pathos-mobile-checks <file-or-directory> <output.json>
(a directory is searched, not recursively below two levels, for .apk,
.aab and .ipa files).
"""

import json
import os
import plistlib
import re
import struct
import sys
import zipfile

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
MAX_MEMBER = 64 << 20  # largest file read from a package
MAX_PACKAGES = 20

# Component tags that can be exported.
COMPONENTS = ("activity", "activity-alias", "service", "receiver", "provider")


def finding(fid, title, severity, description, file, cwe="", masvs="", component="", evidence=""):
    return {"id": fid, "title": title, "severity": severity, "description": description, "file": file,
            "component": component, "cwe": cwe, "masvs": masvs, "evidence": evidence[:500]}


def truthy(v):
    return str(v).strip().lower() in ("true", "1")


# --------------------------------------------------------------- Android


def android_checks(path):
    """Checks an APK with androguard; returns (package name, findings)."""
    from loguru import logger  # androguard logs through loguru

    logger.remove()
    from androguard.core.apk import APK

    apk = APK(path)
    pkg = apk.get_package() or os.path.basename(path)
    out = []
    manifest = apk.get_android_manifest_xml()
    app = manifest.find("application") if manifest is not None else None
    if app is None:
        return pkg, [finding("ANDROID-NO-MANIFEST", "The package has no readable AndroidManifest.xml", "info",
                             "androguard could not read the manifest; the configuration checks did not run.", "AndroidManifest.xml")]
    attr = lambda el, name: el.get(ANDROID_NS + name)  # noqa: E731
    min_sdk = int_or(apk.get_min_sdk_version(), 1)
    target_sdk = int_or(apk.get_target_sdk_version(), min_sdk)

    if truthy(attr(app, "debuggable")):
        out.append(finding("ANDROID-DEBUGGABLE", "The app is debuggable", "high",
                           "android:debuggable=\"true\" lets anyone with a USB or ADB connection attach a debugger, read the app's "
                           "private data and run code in its process. Release builds must not be debuggable.",
                           "AndroidManifest.xml", "CWE-489", "MASVS-RESILIENCE-2", evidence='android:debuggable="true"'))
    backup = attr(app, "allowBackup")
    if backup is None or truthy(backup):
        out.append(finding("ANDROID-ALLOW-BACKUP", "App data can be backed up", "medium",
                           "android:allowBackup is " + ("true" if backup is not None else "not set (the default is true)") +
                           ": the app's private files and databases can be copied with adb backup or cloud backup. Set "
                           "android:allowBackup=\"false\" or restrict backups with android:fullBackupContent / dataExtractionRules.",
                           "AndroidManifest.xml", "CWE-530", "MASVS-STORAGE-2", evidence="android:allowBackup=" + str(backup)))
    cleartext = attr(app, "usesCleartextTraffic")
    if truthy(cleartext) or (cleartext is None and target_sdk < 28 and attr(app, "networkSecurityConfig") is None):
        why = "android:usesCleartextTraffic=\"true\"" if cleartext is not None else \
            "targetSdkVersion %d < 28 without a network security configuration (cleartext is allowed by default)" % target_sdk
        out.append(finding("ANDROID-CLEARTEXT-TRAFFIC", "Cleartext HTTP traffic is allowed", "medium",
                           why + ": the app may send data over unencrypted HTTP, readable and modifiable on the network.",
                           "AndroidManifest.xml", "CWE-319", "MASVS-NETWORK-1", evidence=why))
    out += network_security_config(apk, attr(app, "networkSecurityConfig"))
    if min_sdk < 23:
        out.append(finding("ANDROID-MIN-SDK", "The app supports outdated Android versions (minSdkVersion %d)" % min_sdk, "low",
                           "minSdkVersion %d allows installation on Android versions before 6.0 (API 23), which no longer receive "
                           "security updates and lack runtime permissions and current TLS defaults." % min_sdk,
                           "AndroidManifest.xml", "CWE-1104", "MASVS-CODE-3", evidence="minSdkVersion=%d" % min_sdk))
    for tag in COMPONENTS:
        for el in manifest.iter(tag):
            f = exported_component(el, tag, target_sdk, attr)
            if f:
                out.append(f)
    out += signing_checks(apk, min_sdk)
    return pkg, out


def int_or(v, default):
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def exported_component(el, tag, target_sdk, attr):
    name = attr(el, "name") or "?"
    exported = attr(el, "exported")
    filters = el.findall("intent-filter")
    if exported is None:
        # Before Android 12 a component with an intent filter was exported
        # implicitly; providers were exported by default before API 17.
        implicit = bool(filters) or (tag == "provider" and target_sdk < 17)
        if not implicit:
            return None
    elif not truthy(exported):
        return None
    perms = [attr(el, "permission")]
    if tag == "provider":
        perms += [attr(el, "readPermission"), attr(el, "writePermission")]
    if any(perms):
        return None
    for f in filters:  # the launcher activity must be exported
        actions = {attr(a, "name") for a in f.findall("action")}
        cats = {attr(c, "name") for c in f.findall("category")}
        if "android.intent.action.MAIN" in actions and "android.intent.category.LAUNCHER" in cats:
            return None
    kind = {"activity-alias": "activity alias"}.get(tag, tag)
    how = "android:exported=\"true\"" if exported is not None else "an intent filter (exported implicitly)"
    sev = "high" if tag == "provider" else "medium"
    return finding("ANDROID-EXPORTED-" + tag.upper().replace("-", "_"), "Exported %s without a permission: %s" % (kind, name), sev,
                   "The %s %s is exported (%s) and not protected by a permission: any app on the device can start or "
                   "call it. Set android:exported=\"false\" or require a signature-level permission." % (kind, name, how),
                   "AndroidManifest.xml", "CWE-926", "MASVS-PLATFORM-1", component=name, evidence=how)


def network_security_config(apk, ref):
    """Reads res/xml/<config>.xml when the manifest names one."""
    if not ref:
        return []
    out = []
    try:
        from androguard.core.axml import AXMLPrinter

        name = None
        res = apk.get_android_resources()
        if res is not None and str(ref).startswith("@"):
            rid = int(str(ref)[1:], 16)
            for cfg in res.get_resolved_res_configs(rid):
                name = cfg[1]
                break
        name = name or "res/xml/network_security_config.xml"
        raw = apk.get_file(name)
        xml = AXMLPrinter(raw).get_xml().decode("utf-8", "replace")
    except Exception:  # noqa: BLE001 - an unreadable configuration is not a finding
        return []
    if re.search(r'cleartextTrafficPermitted="true"', xml):
        out.append(finding("ANDROID-NSC-CLEARTEXT", "The network security configuration permits cleartext traffic", "medium",
                           "cleartextTrafficPermitted=\"true\" in " + name + " allows unencrypted HTTP.", name, "CWE-319", "MASVS-NETWORK-1",
                           evidence='cleartextTrafficPermitted="true"'))
    if re.search(r'<certificates[^>]+src="user"', xml):
        out.append(finding("ANDROID-NSC-USER-CA", "The app trusts user-installed CA certificates", "medium",
                           name + " trusts certificates the user (or malware) installs, which allows interception of TLS traffic.",
                           name, "CWE-295", "MASVS-NETWORK-2", evidence='<certificates src="user"/>'))
    return out


def signing_checks(apk, min_sdk):
    out = []
    v1, v2, v3 = apk.is_signed_v1(), apk.is_signed_v2(), apk.is_signed_v3()
    if not (v1 or v2 or v3):
        return [finding("ANDROID-UNSIGNED", "The package is not signed", "medium",
                        "The APK has no v1, v2 or v3 signature; it cannot be installed and its integrity cannot be verified.",
                        "META-INF", "CWE-347", "MASVS-RESILIENCE-2")]
    if v1 and not (v2 or v3):
        sev = "high" if min_sdk < 24 else "medium"
        out.append(finding("ANDROID-SIGNING-V1-ONLY", "Signed with the v1 (JAR) scheme only", sev,
                           "The APK has only a v1 (JAR) signature. v1 does not protect the whole file: on Android 5.0-8.0 the Janus "
                           "vulnerability (CVE-2017-13156) lets an attacker prepend DEX code without breaking the signature. Sign with "
                           "the v2 or v3 scheme (apksigner).", "META-INF", "CWE-347", "MASVS-RESILIENCE-2",
                           evidence="v1=%s v2=%s v3=%s minSdk=%d" % (v1, v2, v3, min_sdk)))
    try:
        certs = apk.get_certificates()
    except Exception:  # noqa: BLE001
        certs = []
    for c in certs:
        subject = c.subject.human_friendly if hasattr(c, "subject") else ""
        if "Android Debug" in subject:
            out.append(finding("ANDROID-DEBUG-CERTIFICATE", "Signed with the Android debug certificate", "high",
                               "The signing certificate is the SDK's debug certificate (" + subject + "); anyone can sign updates "
                               "with the publicly known debug key.", "META-INF", "CWE-321", "MASVS-RESILIENCE-2", evidence=subject))
            break
    return out


# ------------------------------------------------------------------- iOS


def ios_checks(path):
    """Checks an IPA; returns (bundle identifier, findings)."""
    out = []
    with zipfile.ZipFile(path) as z:
        names = z.namelist()
        apps = sorted({m.group(1) for n in names for m in [re.match(r"^(Payload/[^/]+\.app)/", n)] if m})
        if not apps:
            return os.path.basename(path), [finding("IOS-NO-APP", "The package has no Payload/*.app bundle", "info",
                                                    "No application bundle was found; the checks did not run.", "Payload")]
        app = apps[0]
        info_name = app + "/Info.plist"
        info = read_plist(z, info_name)
        if info is None:
            return os.path.basename(path), [finding("IOS-NO-INFO-PLIST", "Info.plist is missing or unreadable", "info",
                                                    "The checks did not run.", info_name)]
        bundle = str(info.get("CFBundleIdentifier") or os.path.basename(path))
        out += ats_checks(info, info_name)
        for t in info.get("CFBundleURLTypes") or []:
            for scheme in (t.get("CFBundleURLSchemes") or []) if isinstance(t, dict) else []:
                out.append(finding("IOS-URL-SCHEME", "Custom URL scheme: %s://" % scheme, "low",
                                   "The app registers the custom URL scheme %s://. Any app can register the same scheme and receive "
                                   "the URLs, and any web page or app can open it with attacker-chosen parameters: validate every "
                                   "parameter and prefer universal links for sensitive actions." % scheme,
                                   info_name, "CWE-939", "MASVS-PLATFORM-1", component=str(scheme), evidence=str(scheme) + "://"))
        mos = str(info.get("MinimumOSVersion") or "")
        if mos and version_lt(mos, (14, 0)):
            out.append(finding("IOS-MINIMUM-OS", "The app supports outdated iOS versions (MinimumOSVersion %s)" % mos, "low",
                               "iOS versions before 14 no longer receive security updates.", info_name, "CWE-1104", "MASVS-CODE-3",
                               evidence="MinimumOSVersion=" + mos))
        ent, ent_file = {}, ""
        prov = app + "/embedded.mobileprovision"
        if prov in names:
            p = embedded_plist(read_member(z, prov))
            if isinstance(p, dict) and isinstance(p.get("Entitlements"), dict):
                ent, ent_file = p["Entitlements"], prov
        exe = info.get("CFBundleExecutable")
        if exe and (app + "/" + exe) in names:
            e = macho_entitlements(read_member(z, app + "/" + exe))
            if e:
                ent, ent_file = {**ent, **e}, app + "/" + exe
        out += entitlement_checks(ent, ent_file)
    return bundle, out


def ats_checks(info, file):
    out = []
    ats = info.get("NSAppTransportSecurity")
    if not isinstance(ats, dict):
        return out
    if truthy(ats.get("NSAllowsArbitraryLoads")):
        out.append(finding("IOS-ATS-ARBITRARY-LOADS", "App Transport Security is disabled (NSAllowsArbitraryLoads)", "high",
                           "NSAllowsArbitraryLoads=true turns off App Transport Security: the app may load content over cleartext "
                           "HTTP and weak TLS.", file, "CWE-319", "MASVS-NETWORK-1", evidence="NSAllowsArbitraryLoads=true"))
    for key in ("NSAllowsArbitraryLoadsInWebContent", "NSAllowsArbitraryLoadsForMedia", "NSAllowsLocalNetworking"):
        if truthy(ats.get(key)) and key != "NSAllowsLocalNetworking":
            out.append(finding("IOS-ATS-" + key[2:].upper(), "App Transport Security exception: " + key, "medium",
                               key + "=true allows cleartext or weak TLS connections for this kind of content.", file, "CWE-319",
                               "MASVS-NETWORK-1", evidence=key + "=true"))
    for domain, cfg in (ats.get("NSExceptionDomains") or {}).items():
        if not isinstance(cfg, dict):
            continue
        reasons = []
        for k in ("NSExceptionAllowsInsecureHTTPLoads", "NSThirdPartyExceptionAllowsInsecureHTTPLoads"):
            if truthy(cfg.get(k)):
                reasons.append(k + "=true")
        for k in ("NSExceptionMinimumTLSVersion", "NSThirdPartyExceptionMinimumTLSVersion"):
            v = str(cfg.get(k) or "")
            if v in ("TLSv1.0", "TLSv1.1"):
                reasons.append(k + "=" + v)
        for k in ("NSExceptionRequiresForwardSecrecy", "NSThirdPartyExceptionRequiresForwardSecrecy"):
            if k in cfg and not truthy(cfg.get(k)):
                reasons.append(k + "=false")
        if reasons:
            out.append(finding("IOS-ATS-EXCEPTION-DOMAIN", "App Transport Security exception for " + domain, "medium",
                               "Connections to %s (subdomains: %s) are exempt from App Transport Security: %s." %
                               (domain, "yes" if truthy(cfg.get("NSIncludesSubdomains")) else "no", ", ".join(reasons)),
                               file, "CWE-319", "MASVS-NETWORK-1", component=domain, evidence="; ".join(reasons)))
    return out


def entitlement_checks(ent, file):
    out = []
    if not ent:
        return out
    if truthy(ent.get("get-task-allow")):
        out.append(finding("IOS-GET-TASK-ALLOW", "The app can be debugged (get-task-allow entitlement)", "high",
                           "get-task-allow=true lets a debugger attach to the app; it is set in development builds and must not be "
                           "in a release build.", file, "CWE-489", "MASVS-RESILIENCE-2", evidence="get-task-allow=true"))
    if str(ent.get("aps-environment") or "") == "development":
        out.append(finding("IOS-APS-DEVELOPMENT", "Development push notification environment", "low",
                           "aps-environment=development: the package was built with a development provisioning profile.",
                           file, "CWE-489", "MASVS-RESILIENCE-2", evidence="aps-environment=development"))
    groups = ent.get("keychain-access-groups") or []
    if any(str(g).endswith("*") for g in groups):
        out.append(finding("IOS-KEYCHAIN-WILDCARD", "Wildcard keychain access group", "medium",
                           "The keychain access groups include a wildcard (%s): keychain items may be shared with every app of "
                           "the team." % ", ".join(map(str, groups)), file, "CWE-732", "MASVS-STORAGE-1",
                           evidence=", ".join(map(str, groups))))
    return out


def version_lt(v, ref):
    parts = []
    for p in v.split(".")[:2]:
        parts.append(int_or(re.sub(r"\D.*", "", p), 0))
    while len(parts) < 2:
        parts.append(0)
    return tuple(parts) < ref


def read_member(z, name):
    info = z.getinfo(name)
    if info.file_size > MAX_MEMBER:
        return b""
    with z.open(info) as f:
        return f.read(MAX_MEMBER)


def read_plist(z, name):
    try:
        return plistlib.loads(read_member(z, name))
    except (KeyError, plistlib.InvalidFileException, ValueError, OverflowError):
        return None


def embedded_plist(raw):
    """The XML plist inside a CMS-signed provisioning profile."""
    i, j = raw.find(b"<?xml"), raw.find(b"</plist>")
    if i < 0 or j < i:
        return None
    try:
        return plistlib.loads(raw[i:j + 8])
    except (plistlib.InvalidFileException, ValueError):
        return None


def macho_entitlements(raw):
    """Entitlements of the first Mach-O slice's code signature."""
    if len(raw) < 32:
        return {}
    magic = struct.unpack(">I", raw[:4])[0]
    if magic in (0xCAFEBABE, 0xCAFEBABF):  # fat binary: first slice
        n = struct.unpack(">I", raw[4:8])[0]
        if n == 0 or len(raw) < 28:
            return {}
        if magic == 0xCAFEBABE:
            off, size = struct.unpack(">II", raw[16:24])
        else:
            off, size = struct.unpack(">QQ", raw[16:32])
        raw = raw[off:off + size]
        if len(raw) < 32:
            return {}
    m = struct.unpack("<I", raw[:4])[0]
    if m not in (0xFEEDFACE, 0xFEEDFACF):
        return {}
    ncmds = struct.unpack("<I", raw[16:20])[0]
    pos = 32 if m == 0xFEEDFACF else 28
    for _ in range(min(ncmds, 512)):
        if pos + 8 > len(raw):
            return {}
        cmd, size = struct.unpack("<II", raw[pos:pos + 8])
        if cmd == 0x1D and pos + 16 <= len(raw):  # LC_CODE_SIGNATURE
            off, _ = struct.unpack("<II", raw[pos + 8:pos + 16])
            return code_signature_entitlements(raw, off)
        if size < 8:
            return {}
        pos += size
    return {}


def code_signature_entitlements(raw, off):
    if off + 12 > len(raw) or struct.unpack(">I", raw[off:off + 4])[0] != 0xFADE0CC0:
        return {}
    count = struct.unpack(">I", raw[off + 8:off + 12])[0]
    for k in range(min(count, 64)):
        e = off + 12 + 8 * k
        if e + 8 > len(raw):
            break
        btype, boff = struct.unpack(">II", raw[e:e + 8])
        b = off + boff
        if btype == 5 and b + 8 <= len(raw) and struct.unpack(">I", raw[b:b + 4])[0] == 0xFADE7171:
            length = struct.unpack(">I", raw[b + 4:b + 8])[0]
            try:
                return plistlib.loads(raw[b + 8:b + length])
            except (plistlib.InvalidFileException, ValueError):
                return {}
    return {}


# ------------------------------------------------------------------ main


def packages(target):
    if os.path.isfile(target):
        return [target]
    found = []
    for root, dirs, files in os.walk(target):
        depth = root[len(target):].count(os.sep)
        if depth >= 2:
            dirs[:] = []
        dirs[:] = [d for d in dirs if not d.startswith(".")]
        for f in sorted(files):
            if f.lower().endswith((".apk", ".aab", ".ipa")):
                found.append(os.path.join(root, f))
    return sorted(found)[:MAX_PACKAGES]


def check(path):
    rel = os.path.basename(path)
    if not zipfile.is_zipfile(path):
        return rel, [finding("MOBILE-NOT-A-PACKAGE", "Not a ZIP-based mobile package", "info", rel + " is not an APK, AAB or IPA.", rel)]
    if path.lower().endswith(".ipa"):
        return ios_checks(path)
    if path.lower().endswith(".aab"):
        return rel, [finding("MOBILE-AAB-NOT-CHECKED", "Android App Bundle manifest not checked", "info",
                             "The manifest of an App Bundle (.aab) is stored as protocol buffers; build an APK set with bundletool "
                             "and upload a universal APK to run the manifest and signing checks.", rel)]
    return android_checks(path)


def main(argv):
    if len(argv) == 2 and argv[1] == "--version":
        from importlib.metadata import version

        print("pathos-mobile-checks 1 (androguard %s)" % version("androguard"))
        return 0
    if len(argv) != 3:
        print("usage: pathos-mobile-checks <file-or-directory> <output.json>", file=sys.stderr)
        return 2
    report = {"tool": "mobile-app-checks", "version": 1, "packages": [], "findings": []}
    pkgs = packages(argv[1])
    if not pkgs:
        print("no .apk, .aab or .ipa file found", file=sys.stderr)
    for p in pkgs:
        name = os.path.basename(p)
        try:
            ident, fs = check(p)
        except Exception as e:  # noqa: BLE001 - one broken package must not hide the others
            ident, fs = name, [finding("MOBILE-ANALYSIS-ERROR", "The package could not be analysed", "info",
                                       "%s: %s" % (type(e).__name__, str(e)[:300]), name)]
        report["packages"].append({"file": name, "id": ident})
        for f in fs:
            f["package"] = ident
            f["file"] = name + "!/" + f["file"]
            report["findings"].append(f)
    with open(argv[2], "w") as fh:
        json.dump(report, fh, indent=1)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
