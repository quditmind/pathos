#!/bin/sh
# Builds pathos-test.apk (run in eclipse-temurin:21-jdk with the Android SDK
# command-line tools; see README). Signed with a throwaway key, v1 (JAR)
# signature only, so the weak-signing check has something to report.
set -eux
SDK=${ANDROID_HOME:-/sdk}; BT=$SDK/build-tools/35.0.0; JAR=$SDK/platforms/android-35/android.jar
W=$(mktemp -d)
javac --release 11 -cp "$JAR" -d $W/classes $(find src -name '*.java')
$BT/d8 --min-api 19 --output $W $(find $W/classes -name '*.class') --lib "$JAR"
$BT/aapt2 link --manifest AndroidManifest.xml -I "$JAR" -o $W/base.apk
(cd $W && zip -q base.apk classes.dex)
$BT/zipalign -f 4 $W/base.apk $W/aligned.apk
keytool -genkeypair -keystore $W/test.jks -storepass pathostest -keypass pathostest -alias test -keyalg RSA -keysize 2048 \
  -validity 3650 -dname "CN=PATHOS Test, O=PATHOS" >/dev/null
$BT/apksigner sign --ks $W/test.jks --ks-pass pass:pathostest --v1-signing-enabled true --v2-signing-enabled false \
  --v3-signing-enabled false --v4-signing-enabled false --min-sdk-version 19 --out pathos-test.apk $W/aligned.apk
$BT/apksigner verify --verbose pathos-test.apk | head -5
