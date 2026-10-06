#!/bin/sh
# Lays out a release of the OID4VCWallet Kotlin library for
# github.com/IDFoundry/OID4VCgo-wallet-kotlin, whose GitHub Pages serve
# it as a Maven repository: builds the release AAR (never the mobiletest
# build), publishes dev.idfoundry:oid4vcwallet into the checkout's maven/
# directory beside its earlier versions, mirrors the Kotlin sources and
# writes the README, and copies the AAR to ASSET_DIR for the GitHub
# release. Before that it builds an app depending on the published
# version, as an app developer's would.
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
OWNER="$(echo "${REPO%/*}" | tr '[:upper:]' '[:lower:]')"
NAME="${REPO#*/}"
MAVEN_URL="https://$OWNER.github.io/$NAME/maven"
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

# The library, into a staging repository first: it's checked before the
# checkout's repository is touched.
./gradlew -q --console=plain :OID4VCWallet:publishReleasePublicationToReleaseRepository \
	-Poid4vc.version="$VERSION" -Poid4vc.publishTo="$WORK/maven"
PUBLISHED="$WORK/maven/dev/idfoundry/oid4vcwallet/$VERSION/oid4vcwallet-$VERSION.aar"
[ -f "$PUBLISHED" ] || { echo "nothing published at $PUBLISHED" >&2; exit 1; }

# An app depending on it, as an app developer's would: from the Maven
# repository, by its coordinates.
APP="$WORK/consumer"
mkdir -p "$APP/app/src/main/kotlin/consumer"
cp -R gradle gradlew "$APP/"
cat > "$APP/settings.gradle.kts" <<EOF
pluginManagement { repositories { google(); mavenCentral(); gradlePluginPortal() } }
dependencyResolutionManagement {
    repositories { maven { url = uri("file://$WORK/maven") }; google(); mavenCentral() }
}
include(":app")
EOF
AGP="$(sed -n 's/^agp = "\(.*\)"/\1/p' gradle/libs.versions.toml)"
cat > "$APP/build.gradle.kts" <<EOF
plugins { id("com.android.application") version "$AGP" apply false }
EOF
cat > "$APP/app/build.gradle.kts" <<EOF
plugins { id("com.android.application") }
android {
    namespace = "dev.idfoundry.consumer"
    compileSdk = 37
    defaultConfig { applicationId = "dev.idfoundry.consumer"; minSdk = 30; targetSdk = 37 }
}
dependencies { implementation("dev.idfoundry:oid4vcwallet:$VERSION") }
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

# Checked: into the package repository, beside the earlier versions.
mkdir -p "$PKG/maven/dev/idfoundry/oid4vcwallet"
if [ -e "$PKG/maven/dev/idfoundry/oid4vcwallet/$VERSION" ]; then
	echo "$PKG already has version $VERSION" >&2
	exit 1
fi
./gradlew -q --console=plain :OID4VCWallet:publishReleasePublicationToReleaseRepository \
	-Poid4vc.version="$VERSION" -Poid4vc.publishTo="$PKG/maven"
cp "$PUBLISHED" "$ASSETS/oid4vcwallet-$VERSION.aar"

rm -rf "$PKG/sources"
mkdir -p "$PKG/sources"
cp -R OID4VCWallet/src/main/kotlin OID4VCWallet/src/main/AndroidManifest.xml OID4VCWallet/consumer-rules.pro "$PKG/sources/"
touch "$PKG/.nojekyll"

cat > "$PKG/README.md" <<EOF
# OID4VCgo-wallet-kotlin

\`OID4VCWallet\`: the Kotlin library of [OID4VCgo](https://github.com/IDFoundry/OID4VCgo)'s
mobile wallet, for Android 11 (API 30) and later. It receives credentials
over OpenID4VCI 1.0 and presents them over OpenID4VP 1.0, under HAIP 1.0,
with SD-JWT VC and ISO mdoc credentials. OID4VCgo is OpenID Certified for
those roles.

The protocols run in OID4VCgo's Go code, compiled with gomobile into the
library. Your app owns the keys, the storage and the UI:

- **Keys:** \`AndroidKeystoreKeyStore\` keeps them in StrongBox where the
  device has it, else the TEE. Holder keys ask for the holder's
  fingerprint or screen lock to present (\`BiometricPromptAuthenticator\`).
- **Storage:** \`FileCredentialStore\` encrypts each record under a key
  that works only while the device is unlocked, out of backups.
- **Wallet Provider:** you implement \`WalletProvider\`, which attests the
  wallet.

## Install

\`\`\`kotlin
// settings.gradle.kts
dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
        maven("$MAVEN_URL")
    }
}

// build.gradle.kts
dependencies {
    implementation("dev.idfoundry:oid4vcwallet:$VERSION")
}
\`\`\`

An app can hold only one gomobile library.

## Documentation

- [The Android library's sources](https://github.com/IDFoundry/OID4VCgo/tree/main/mobile/android/OID4VCWallet),
  mirrored in \`sources/\`.
- [OID4VCgo's \`mobile/\`](https://github.com/IDFoundry/OID4VCgo/tree/main/mobile):
  the Go side and its [ABI](https://github.com/IDFoundry/OID4VCgo/blob/main/mobile/ABI.md).
- [MOBILE.md](https://github.com/IDFoundry/OID4VCgo/blob/main/MOBILE.md): the design.
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
echo "OID4VCWallet $VERSION: ABI $(sed -n 's/^const ABIVersion = //p' mobile.go), dev.idfoundry:oid4vcwallet:$VERSION at $MAVEN_URL"
