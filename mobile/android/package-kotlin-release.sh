#!/bin/sh
# Lays out a release of the OID4VCWallet Kotlin library for
# github.com/IDFoundry/OID4VCgo-wallet-kotlin, whose releases carry it:
# builds the release AAR (never the mobiletest build), packages the
# library — the AAR with the Kotlin API and the Go library, and its
# sources jar — into ASSET_DIR for the GitHub release, and mirrors the
# Kotlin sources and writes the README into the checkout. Before that it
# builds an app on the AAR as the README tells app developers to: the
# file, and the dependencies it lists.
#
#   ./package-kotlin-release.sh VERSION PACKAGE_DIR ASSET_DIR
#
# VERSION is the release's (1.2.3, no "v"): the Swift package's, from the
# same commit. PACKAGE_DIR is a checkout of the package repository.
# SKIP_AAR_BUILD=1 reuses an existing build/release AAR.
set -eu
[ $# -eq 3 ] || { echo "usage: $0 VERSION PACKAGE_DIR ASSET_DIR" >&2; exit 2; }
VERSION="$1"
PKG="$(cd "$2" && pwd)"
mkdir -p "$3"
ASSETS="$(cd "$3" && pwd)"
REPO="${OID4VC_WALLET_KOTLIN_REPO:-IDFoundry/OID4VCgo-wallet-kotlin}"
echo "$VERSION" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$' || { echo "not a version: $VERSION" >&2; exit 2; }
cd "$(dirname "$0")"
HERE="$PWD"

if [ "${SKIP_AAR_BUILD:-}" != 1 ]; then
	../build-aar.sh
fi
AAR=../build/release/mobile.aar
[ -f "$AAR" ] || { echo "no $AAR" >&2; exit 1; }
# Never publish the test build, whatever the directory holds: it carries
# an in-process test issuer and Verifier (TestEnv).
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
unzip -p "$AAR" classes.jar > "$WORK/go.jar"
if unzip -l "$WORK/go.jar" | grep -q TestEnv; then
	echo "$AAR is the mobiletest build: rebuild it without SKIP_AAR_BUILD" >&2
	exit 1
fi

# The library and its sources jar, as Gradle publishes them; the POM
# says which libraries an app needs beside the file.
./gradlew -q --console=plain :OID4VCWallet:publishReleasePublicationToReleaseRepository \
	-Poid4vc.version="$VERSION" -Poid4vc.publishTo="$WORK/maven"
OUT="$WORK/maven/dev/idfoundry/oid4vcwallet/$VERSION"
LIBRARY="$OUT/oid4vcwallet-$VERSION.aar"
SOURCES="$OUT/oid4vcwallet-$VERSION-sources.jar"
[ -f "$LIBRARY" ] && [ -f "$SOURCES" ] || { echo "nothing published in $OUT" >&2; exit 1; }
# Each dependency the POM names but the Kotlin standard library (which
# an app's Kotlin brings), as group:artifact:version.
DEPS="$(awk '
	/<dependency>/ { g = ""; a = ""; v = "" }
	/<groupId>/ { sub(/.*<groupId>/, ""); sub(/<\/groupId>.*/, ""); g = $0 }
	/<artifactId>/ { sub(/.*<artifactId>/, ""); sub(/<\/artifactId>.*/, ""); a = $0 }
	/<version>/ { sub(/.*<version>/, ""); sub(/<\/version>.*/, ""); v = $0 }
	/<\/dependency>/ { if (a != "kotlin-stdlib") print g ":" a ":" v }
' "$OUT/oid4vcwallet-$VERSION.pom")"
[ -n "$DEPS" ] || { echo "the POM names no dependencies" >&2; exit 1; }
DEPLINES="$(for d in $DEPS; do echo "    implementation(\"$d\")"; done)"

# An app on the AAR, as the README says: the file, and those libraries.
APP="$WORK/consumer"
mkdir -p "$APP/app/src/main/kotlin/consumer" "$APP/app/libs"
cp -R gradle gradlew "$APP/"
cp "$LIBRARY" "$APP/app/libs/"
AGP="$(sed -n 's/^agp = "\(.*\)"/\1/p' gradle/libs.versions.toml)"
cat > "$APP/settings.gradle.kts" <<EOF
pluginManagement { repositories { google(); mavenCentral(); gradlePluginPortal() } }
dependencyResolutionManagement { repositories { google(); mavenCentral() } }
include(":app")
EOF
cat > "$APP/build.gradle.kts" <<EOF
plugins { id("com.android.application") version "$AGP" apply false }
EOF
cat > "$APP/app/build.gradle.kts" <<EOF
plugins { id("com.android.application") }
android {
    namespace = "dev.idfoundry.consumer"
    compileSdk = 37
    defaultConfig { applicationId = "dev.idfoundry.consumer"; minSdk = 26; targetSdk = 37 }
}
dependencies {
    implementation(files("libs/oid4vcwallet-$VERSION.aar"))
$DEPLINES
}
EOF
cat > "$APP/app/src/main/AndroidManifest.xml" <<'EOF'
<manifest xmlns:android="http://schemas.android.com/apk/res/android"><application /></manifest>
EOF
cat > "$APP/app/src/main/kotlin/consumer/Use.kt" <<'EOF'
package consumer

import dev.idfoundry.oid4vcwallet.OID4VC

fun abi(): Int = OID4VC.abiVersion
EOF
cp local.properties "$APP/" 2>/dev/null || true
(cd "$APP" && ./gradlew -q --console=plain :app:assembleDebug)
unzip -l "$APP/app/build/outputs/apk/debug/app-debug.apk" | grep -q 'lib/arm64-v8a/libgojni.so' || { echo "the app has no Go library" >&2; exit 1; }

cp "$LIBRARY" "$SOURCES" "$ASSETS/"

rm -rf "$PKG/sources"
mkdir -p "$PKG/sources"
cp -R OID4VCWallet/src/main/kotlin OID4VCWallet/src/main/AndroidManifest.xml OID4VCWallet/consumer-rules.pro "$PKG/sources/"
# The guides (docs/*.md), which GitHub renders there.
rm -rf "$PKG/docs"
cp -R docs "$PKG/docs"

cat > "$PKG/README.md" <<EOF
# OID4VCgo-wallet-kotlin

\`OID4VCWallet\`: the Kotlin library of [OID4VCgo](https://github.com/IDFoundry/OID4VCgo)'s
mobile wallet, for Android 8 (API 26) and later. It receives credentials
over OpenID4VCI 1.0 and presents them over OpenID4VP 1.0, under HAIP 1.0,
with SD-JWT VC and ISO mdoc credentials, from links and, through
Credential Manager, from Chrome's Digital Credentials API. OID4VCgo is
OpenID Certified for those roles (over links). It also presents in
person over Bluetooth (ISO/IEC 18013-5), as the holder or as the
reader.

The protocols run in OID4VCgo's Go code, compiled with gomobile into the
library. Your app owns the keys, the storage and the UI:

- **Keys:** \`AndroidKeystoreKeyStore\` keeps them in StrongBox where the
  device has it, else the TEE. Holder keys ask for the holder's
  fingerprint or screen lock to present (\`BiometricPromptAuthenticator\`),
  from Android 11 (API 30); below it, the app authenticates the holder
  itself. [What each API level guarantees](https://github.com/IDFoundry/OID4VCgo/blob/main/mobile/README.md#what-each-platform-supports).
- **Storage:** \`FileCredentialStore\` encrypts each record under a key
  that works only while the device is unlocked, out of backups.
- **Wallet Provider:** you implement \`WalletProvider\`, which attests the
  wallet.

## Install

Download \`oid4vcwallet-$VERSION.aar\` from [the release](https://github.com/$REPO/releases/tag/$VERSION)
(and \`oid4vcwallet-$VERSION-sources.jar\`, to browse its sources in
Android Studio) into your app module's \`libs/\`, and add it with the
libraries it uses:

\`\`\`kotlin
// app/build.gradle.kts
dependencies {
    implementation(files("libs/oid4vcwallet-$VERSION.aar"))
$DEPLINES
}
\`\`\`

Check the download against the release's \`SHA256SUMS\`
(\`sha256sum -c SHA256SUMS\`), and its provenance with the GitHub CLI:
\`gh attestation verify oid4vcwallet-$VERSION.aar --repo IDFoundry/OID4VCgo\`.

In-person presentation needs Bluetooth permissions, which the
library's manifest adds to your app's: request
\`ProximityPermissions.holder\` or \`.reader\` at runtime before starting
a session.

The AAR goes in an app module: an Android library can't depend on a
local AAR. It holds the Go library for arm64 and x86_64 (the emulator),
and an app can hold only one gomobile library. It's compiled for Kotlin
2.2 and later.

## Documentation

- [Guides](docs/GettingStarted.md): getting started, receiving
  credentials, presenting from a link, to Chrome and in person,
  handling errors, and going to production.
- [The API reference](https://$(echo "${REPO%%/*}" | tr '[:upper:]' '[:lower:]').github.io/${REPO#*/}/$VERSION/), for this
  release.
- [The Android library's sources](https://github.com/IDFoundry/OID4VCgo/tree/main/mobile/android/OID4VCWallet),
  mirrored in \`sources/\`.
- [OID4VCgo's \`mobile/\`](https://github.com/IDFoundry/OID4VCgo/tree/main/mobile):
  what each platform supports, in-person presentation, the Go side and
  its [ABI](https://github.com/IDFoundry/OID4VCgo/blob/main/mobile/ABI.md).
- [MOBILE.md](https://github.com/IDFoundry/OID4VCgo/blob/main/mobile/MOBILE.md): the design.
- [The demo wallet app](https://github.com/IDFoundry/OID4VCgo/tree/main/mobile/android/DemoWallet):
  a complete app on this library.

## Contributing

This repository is generated: OID4VCgo's \`wallet-kotlin-release\`
workflow publishes every release here from
[\`mobile/android\`](https://github.com/IDFoundry/OID4VCgo/tree/main/mobile/android).
Issues and pull requests belong in [OID4VCgo](https://github.com/IDFoundry/OID4VCgo).

## License

MIT. See [LICENSE](LICENSE).
EOF
cd "$HERE/.."
echo "OID4VCWallet $VERSION: ABI $(sed -n 's/^const ABIVersion = //p' mobile.go), oid4vcwallet-$VERSION.aar, with $(echo $DEPS | tr ' ' ',')"
