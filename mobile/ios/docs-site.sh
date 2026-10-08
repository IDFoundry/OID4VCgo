#!/bin/sh
# Lays out the OID4VCWallet documentation for GitHub Pages, from a DocC
# archive (check-docs.sh's DOCC_OUTPUT):
#
#   ./docs-site.sh VERSION ARCHIVE OUT_DIR
#
# OUT_DIR gets VERSION/ and latest/, each the whole site transformed for
# static hosting under its own path, an index.html at the root sending
# readers to latest/, and a .nojekyll so Pages serves DocC's files as
# they are. The release workflow copies the two directories onto the
# package repository's gh-pages branch, keeping earlier versions. REPO
# (owner/name, OID4VC_WALLET_SWIFT_REPO) sets the hosting base path, the
# repository's name.
set -eu
[ $# -eq 3 ] || { echo "usage: $0 VERSION ARCHIVE OUT_DIR" >&2; exit 2; }
VERSION="$1"
ARCHIVE="$2"
OUT="$3"
REPO="${OID4VC_WALLET_SWIFT_REPO:-IDFoundry/OID4VCgo-wallet-swift}"
NAME="${REPO#*/}"
echo "$VERSION" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$' || { echo "not a version: $VERSION" >&2; exit 2; }
[ -d "$ARCHIVE" ] || { echo "no archive $ARCHIVE" >&2; exit 1; }

rm -rf "$OUT"
mkdir -p "$OUT"
for path in "$VERSION" latest; do
    xcrun docc process-archive transform-for-static-hosting "$ARCHIVE" \
        --output-path "$OUT/$path" --hosting-base-path "$NAME/$path"
    [ -f "$OUT/$path/documentation/oid4vcwallet/index.html" ] || { echo "no documentation page in $OUT/$path" >&2; exit 1; }
done
cat > "$OUT/index.html" <<'HTML'
<!doctype html>
<meta charset="utf-8">
<title>OID4VCWallet documentation</title>
<meta http-equiv="refresh" content="0; url=latest/documentation/oid4vcwallet/">
<link rel="canonical" href="latest/documentation/oid4vcwallet/">
<p><a href="latest/documentation/oid4vcwallet/">OID4VCWallet documentation</a></p>
HTML
touch "$OUT/.nojekyll"
echo "OID4VCWallet $VERSION documentation: $OUT/$VERSION and $OUT/latest"
