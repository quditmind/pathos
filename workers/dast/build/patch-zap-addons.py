#!/usr/bin/env python3
"""Replace vulnerable libraries bundled in ZAP add-ons (build time only).

ZAP add-ons (.zap files) are jar files that bundle their libraries either
merged into the add-on ("shaded": the library's classes and its
META-INF/maven/<group>/<artifact>/pom.properties sit in the add-on itself)
or as separate jars under libs/ (listed in ZapAddOn.xml). The add-on
versions pinned in the Dockerfile still bundle library versions with fixed
HIGH/CRITICAL CVEs (netty, Jackson, Guava). This script swaps those
libraries for patched releases of the same major line, downloaded from
Maven Central and verified by SHA-256 in the Dockerfile:

  network     netty 4.1.134.Final -> 4.1.141.Final (shaded)
  commonlib   Jackson 2.22.2      -> 2.22.4 (shaded)
  openapi     Guava 32.1.3-jre    -> 33.7.2-jre (shaded)
  graphql     Guava 32.1.2-jre    -> 33.7.2-jre (shaded)
  database    Jackson 2.19.1      -> 2.22.4 (libs/*.jar)

usage: patch-zap-addons.py <plugin dir> <directory of the replacement jars>

The script fails when an add-on or a jar it expects is missing, or when an
old version is still recorded in an add-on afterwards.
"""
import os
import re
import sys
import zipfile

NETTY = "4.1.141.Final"
JACKSON = "2.22.4"
JACKSON_ANNOTATIONS = "2.22"
GUAVA = "33.7.2-jre"

NETTY_JARS = [f"netty-{m}-{NETTY}.jar" for m in (
    "buffer", "codec", "codec-http", "codec-http2", "common", "handler", "resolver", "transport", "transport-native-unix-common")]
JACKSON_JARS = [f"jackson-{m}-{JACKSON}.jar" for m in (
    "core", "databind", "dataformat-xml", "dataformat-yaml", "datatype-jdk8", "datatype-jsr310")] + [
    f"jackson-annotations-{JACKSON_ANNOTATIONS}.jar"]

# add-on file prefix -> (path prefixes of the shaded library, replacement jars)
SHADED = {
    "network-": (["io/netty/", "META-INF/maven/io.netty/", "META-INF/native-image/io.netty/",
                  "META-INF/io.netty.versions.properties"], NETTY_JARS),
    "commonlib-": (["com/fasterxml/jackson/", "META-INF/maven/com.fasterxml.jackson.",
                    "META-INF/services/com.fasterxml.jackson."], JACKSON_JARS),
    "openapi-": (["com/google/common/", "com/google/thirdparty/", "META-INF/maven/com.google.guava/guava/"],
                 [f"guava-{GUAVA}.jar"]),
    "graphql-": (["com/google/common/", "com/google/thirdparty/", "META-INF/maven/com.google.guava/guava/"],
                 [f"guava-{GUAVA}.jar"]),
}
# add-on file prefix -> {old libs/ jar: replacement jar}
LIBS = {
    "database-": {"jackson-core-2.19.1.jar": f"jackson-core-{JACKSON}.jar",
                  "jackson-databind-2.19.1.jar": f"jackson-databind-{JACKSON}.jar",
                  "jackson-annotations-2.19.1.jar": f"jackson-annotations-{JACKSON_ANNOTATIONS}.jar"},
}
# Versions that must be gone afterwards (pom.properties "version=" lines).
OLD = re.compile(r"^version=(4\.1\.134\.Final|2\.22\.2|2\.19\.1|32\.1\.[23]-jre)\s*$", re.M)

VERSIONED = re.compile(r"^META-INF/versions/\d+/")


def strip_versioned(name):
    return VERSIONED.sub("", name)


def replaced(name, prefixes):
    n = strip_versioned(name)
    return any(n.startswith(p) or n == p.rstrip("/") for p in prefixes)


def skip_from_library(name):
    # The add-on keeps its own manifest, signatures, module descriptors and
    # licence files.
    n = strip_versioned(name)
    return (name.startswith("META-INF/MANIFEST.MF") or n == "module-info.class" or name.endswith((".SF", ".RSA", ".DSA"))
            or name.endswith("/"))


def rewrite(path, drop, add):
    """Rewrites the zip at path without the entries drop() selects, plus add
    (a list of (name, bytes))."""
    tmp = path + ".tmp"
    seen = set()
    with zipfile.ZipFile(path) as src, zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as dst:
        for info in src.infolist():
            if drop(info.filename):
                continue
            dst.writestr(info, src.read(info.filename))
            seen.add(info.filename)
        for name, data in add:
            if name in seen:
                continue
            seen.add(name)
            dst.writestr(zipfile.ZipInfo(name, date_time=(1980, 2, 1, 0, 0, 0)), data, zipfile.ZIP_DEFLATED)
    os.replace(tmp, path)


def library_entries(jars_dir, jars):
    out = []
    for j in jars:
        with zipfile.ZipFile(os.path.join(jars_dir, j)) as z:
            for info in z.infolist():
                if not skip_from_library(info.filename):
                    out.append((info.filename, z.read(info.filename)))
    return out


def find(plugin_dir, prefix):
    hits = [f for f in os.listdir(plugin_dir) if f.startswith(prefix) and f.endswith(".zap")]
    if len(hits) != 1:
        sys.exit(f"patch-zap-addons: expected one {prefix}*.zap add-on, found {hits}")
    return os.path.join(plugin_dir, hits[0])


def check(path):
    with zipfile.ZipFile(path) as z:
        for n in z.namelist():
            if n.endswith("pom.properties") and OLD.search(z.read(n).decode("utf-8", "replace")):
                sys.exit(f"patch-zap-addons: {os.path.basename(path)} still records an old version in {n}")
            if n.startswith("libs/") and n.endswith(".jar"):
                inner = os.path.basename(n)
                if any(inner == old for libs in LIBS.values() for old in libs):
                    sys.exit(f"patch-zap-addons: {os.path.basename(path)} still contains {n}")


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    plugin_dir, jars_dir = sys.argv[1], sys.argv[2]
    for prefix, (prefixes, jars) in SHADED.items():
        path = find(plugin_dir, prefix)
        rewrite(path, lambda n, p=prefixes: replaced(n, p), library_entries(jars_dir, jars))
        check(path)
        print(f"patched {os.path.basename(path)}: {', '.join(jars)}")
    for prefix, libs in LIBS.items():
        path = find(plugin_dir, prefix)
        with zipfile.ZipFile(path) as z:
            names = set(z.namelist())
            manifest = z.read("ZapAddOn.xml").decode("utf-8")
        add = []
        for old, new in libs.items():
            if "libs/" + old not in names:
                sys.exit(f"patch-zap-addons: {os.path.basename(path)} has no libs/{old}")
            with open(os.path.join(jars_dir, new), "rb") as f:
                add.append(("libs/" + new, f.read()))
            manifest = manifest.replace(f"<lib>libs/{old}</lib>", f"<lib>libs/{new}</lib>")
        add.insert(0, ("ZapAddOn.xml", manifest.encode("utf-8")))
        rewrite(path, lambda n, o=libs: n == "ZapAddOn.xml" or (n.startswith("libs/") and n[5:] in o), add)
        check(path)
        print(f"patched {os.path.basename(path)}: {', '.join(libs.values())}")


if __name__ == "__main__":
    main()
