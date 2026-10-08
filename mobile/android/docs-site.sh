#!/bin/sh
# Lays out the OID4VCWallet Kotlin library's API reference for GitHub
# Pages, from Dokka's HTML site (check-docs.sh's DOKKA_OUTPUT):
#
#   ./docs-site.sh VERSION SITE OUT_DIR
#
# OUT_DIR gets VERSION/ and latest/, each a copy of the site (Dokka's
# links are relative, so it needs no base path), an index.html at the
# root sending readers to latest/, and a .nojekyll so Pages serves the
# files as they are. The release workflow copies the two directories
# onto the package repository's gh-pages branch, keeping earlier
# versions.
set -eu
[ $# -eq 3 ] || { echo "usage: $0 VERSION SITE OUT_DIR" >&2; exit 2; }
VERSION="$1"
SITE="$2"
OUT="$3"
echo "$VERSION" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$' || { echo "not a version: $VERSION" >&2; exit 2; }
[ -f "$SITE/index.html" ] || { echo "no Dokka site at $SITE" >&2; exit 1; }

rm -rf "$OUT"
mkdir -p "$OUT"
for path in "$VERSION" latest; do
    cp -R "$SITE" "$OUT/$path"
done
cat > "$OUT/index.html" <<'HTML'
<!doctype html>
<meta charset="utf-8">
<title>OID4VCWallet for Android: API reference</title>
<meta http-equiv="refresh" content="0; url=latest/">
<link rel="canonical" href="latest/">
<p><a href="latest/">OID4VCWallet for Android: API reference</a></p>
HTML
touch "$OUT/.nojekyll"
echo "OID4VCWallet $VERSION API reference: $OUT/$VERSION and $OUT/latest"
