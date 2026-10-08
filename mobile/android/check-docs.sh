#!/bin/sh
# Builds the OID4VCWallet Kotlin library's API reference with Dokka,
# failing on any Dokka warning (OID4VCWallet/build.gradle.kts), and
# checks the site has its front page and a class page. DOKKA_OUTPUT, if
# set, is where the HTML site is copied.
#
# It needs the release Go library (../build-aar.sh), as the library
# compiles against it.
set -eu
cd "$(dirname "$0")"
[ -f ../build/release/mobile.aar ] || { echo "no ../build/release/mobile.aar: run ../build-aar.sh" >&2; exit 1; }

./gradlew -q :OID4VCWallet:dokkaGenerate
SITE=OID4VCWallet/build/dokka/html
for page in index.html oid4vcwallet/dev.idfoundry.oid4vcwallet/-wallet/index.html; do
    [ -f "$SITE/$page" ] || { echo "the reference has no $page" >&2; exit 1; }
done
if [ -n "${DOKKA_OUTPUT:-}" ]; then
    rm -rf "$DOKKA_OUTPUT"
    cp -R "$SITE" "$DOKKA_OUTPUT"
fi
echo "OID4VCWallet API reference: built"
