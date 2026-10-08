#!/bin/sh
# Checks the OID4VCWallet Kotlin library's documentation:
#
# 1. builds its API reference with Dokka, failing on any Dokka warning
#    (OID4VCWallet/build.gradle.kts), and checks the site has its front
#    page and a class page. DOKKA_OUTPUT, if set, is where the HTML site
#    is copied.
# 2. compiles each guide's ```kotlin code blocks (docs/*.md), concatenated
#    in order, as a file of the demo app's unit-test sources
#    (DemoWallet/src/test/kotlin/guideexamples, which git ignores): the
#    demo depends on the library and on what the guides use beside it
#    (androidx.browser, Credential Manager). A block that isn't Kotlin to
#    compile is fenced without a language. Names are shared across
#    guides: each guide's must be its own.
#
# It needs the release Go library (../build-aar.sh), as the library
# compiles against it.
set -eu
cd "$(dirname "$0")"
[ -f ../build/release/mobile.aar ] || { echo "no ../build/release/mobile.aar: run ../build-aar.sh" >&2; exit 1; }

if ! ./gradlew -q :OID4VCWallet:dokkaGenerate; then
    # Dokka reports its warnings in its worker's log, not on the console.
    find OID4VCWallet/build -name 'dokka-worker.log' -exec grep -h -i -E 'warn|error' {} + >&2 || true
    exit 1
fi
SITE=OID4VCWallet/build/dokka/html
[ -f "$SITE/index.html" ] || { echo "the reference has no front page" >&2; exit 1; }
WALLET="$(find "$SITE" -path '*/dev.idfoundry.oid4vcwallet/-wallet/index.html' | head -1)"
[ -n "$WALLET" ] || { echo "the reference has no page for Wallet" >&2; exit 1; }
echo "Wallet's page: ${WALLET#"$SITE"/}"
if [ -n "${DOKKA_OUTPUT:-}" ]; then
    rm -rf "$DOKKA_OUTPUT"
    cp -R "$SITE" "$DOKKA_OUTPUT"
fi

EXAMPLES=DemoWallet/src/test/kotlin/guideexamples
rm -rf "$EXAMPLES"
mkdir -p "$EXAMPLES"
trap 'rm -rf "$EXAMPLES"' EXIT
for guide in docs/*.md; do
    name="$(basename "$guide" .md)"
    awk '/^```kotlin[[:space:]]*$/ { inside = 1; next } /^```/ { inside = 0; next } inside { print }' "$guide" > "$EXAMPLES/$name.kt"
    [ -s "$EXAMPLES/$name.kt" ] || rm "$EXAMPLES/$name.kt"
done
./gradlew -q :DemoWallet:compileDebugUnitTestKotlin
# Each guide's file compiled to its own class (GettingStarted.kt to
# GettingStartedKt, …), so the examples really were built.
for example in "$EXAMPLES"/*.kt; do
    class="$(basename "$example" .kt)Kt.class"
    [ -n "$(find DemoWallet/build -name "$class" -path '*UnitTest*' | head -1)" ] || { echo "no $class: the guides' examples weren't compiled" >&2; exit 1; }
done
echo "OID4VCWallet API reference: built, and the guides' examples compile"
