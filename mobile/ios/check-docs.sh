#!/bin/sh
# Checks the OID4VCWallet package's DocC documentation:
#
# 1. builds it with xcodebuild docbuild, failing on any DocC warning (a
#    link to a symbol that doesn't exist, say), and
# 2. compiles each article's ```swift code blocks, concatenated in
#    order, as a file of a package depending on OID4VCWallet, for the
#    iOS Simulator (so iOS-only frameworks such as
#    IdentityDocumentServices are checked too), so the examples can't
#    drift from the API. A block that isn't Swift to compile is fenced
#    without a language. Names are shared across articles: each
#    article's must be its own.
#
# It needs the release framework (../build-xcframework.sh), as the
# package links it. DOCC_OUTPUT, if set, is where the .doccarchive is
# copied.
set -eu
cd "$(dirname "$0")"
HERE="$PWD"
CATALOG=OID4VCWallet/Sources/OID4VCWallet/OID4VCWallet.docc
[ -d ../build/release/Mobile.xcframework ] || { echo "no ../build/release/Mobile.xcframework: run ../build-xcframework.sh" >&2; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

(cd OID4VCWallet && xcodebuild docbuild -scheme OID4VCWallet -destination 'generic/platform=iOS Simulator' \
    -derivedDataPath "$WORK/derived" OTHER_DOCC_FLAGS="--warnings-as-errors" -quiet)
ARCHIVE="$(find "$WORK/derived" -name OID4VCWallet.doccarchive -type d | head -1)"
[ -n "$ARCHIVE" ] || { echo "docbuild made no OID4VCWallet.doccarchive" >&2; exit 1; }
if [ -n "${DOCC_OUTPUT:-}" ]; then
    rm -rf "$DOCC_OUTPUT"
    cp -R "$ARCHIVE" "$DOCC_OUTPUT"
fi

mkdir -p "$WORK/examples/Sources/DocExamples"
for article in "$CATALOG"/*.md; do
    name="$(basename "$article" .md)"
    awk '/^```swift[[:space:]]*$/ { inside = 1; next } /^```/ { inside = 0; next } inside { print }' "$article" \
        > "$WORK/examples/Sources/DocExamples/$name.swift"
    [ -s "$WORK/examples/Sources/DocExamples/$name.swift" ] || rm "$WORK/examples/Sources/DocExamples/$name.swift"
done
if ls "$WORK/examples/Sources/DocExamples/"*.swift >/dev/null 2>&1; then
    cat > "$WORK/examples/Package.swift" <<MANIFEST
// swift-tools-version:6.0
import PackageDescription

let package = Package(
    name: "DocExamples",
    platforms: [.iOS(.v16), .macOS(.v13)],
    products: [.library(name: "DocExamples", targets: ["DocExamples"])],
    dependencies: [.package(path: "$HERE/OID4VCWallet")],
    targets: [.target(name: "DocExamples", dependencies: ["OID4VCWallet"])]
)
MANIFEST
    (cd "$WORK/examples" && xcodebuild build -scheme DocExamples -destination 'generic/platform=iOS Simulator' \
        -derivedDataPath "$WORK/examples-derived" -quiet)
fi
echo "OID4VCWallet docs: built, and their examples compile"
