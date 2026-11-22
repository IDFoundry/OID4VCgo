#!/bin/sh
# Writes a mobile library release's "What's new" as Markdown: the feat,
# fix and perf commits between the commit the previous release was built
# from and this one that touched what the library ships. That's the Go
# code gomobile compiles into it (the OID4VCgo packages mobile/ imports,
# as go list sees them at this commit, tests aside), go.mod and go.sum,
# the platform library's own sources, and its build script, whose flags
# shape the binary: mobile/android/OID4VCWallet and build-aar.sh, or
# mobile/ios/OID4VCWallet and build-xcframework.sh. Demo apps and
# docs-only commits aren't listed. Oldest first.
#
#   mobile/release-notes.sh <previous-commit> <this-commit> android|ios
#
# The commits are Conventional Commits (CONTRIBUTING.md), so their
# headers are fit to list. A header repeated, as release-please's
# multiple-changes form repeats one, is listed once, at its first commit.
#
# A breaking change is one whose header has "!" or whose body has a line
# starting BREAKING CHANGE: or BREAKING-CHANGE:, as release-please reads
# them. Git's trailer parsing can't see that footer: it's a paragraph of
# its own above Co-Authored-By. An app can't call the Go API, so only a
# breaking change to what it can call is listed as breaking: one that
# touches the platform library or mobile/*.go (the gomobile API and its
# ABI). Any other breaking commit is listed with the rest.
#
# Both libraries compile the same Go code, but NFC engagement is
# Android's alone: iOS's list leaves out commits whose header names NFC,
# TNEP or Android and that change nothing in the Swift package, and says
# how many. One that changes the Swift package too is listed: its header
# names only the Android side of a change both libraries ship.
set -eu
[ $# -eq 3 ] || { echo "usage: $0 <previous-commit> <this-commit> android|ios" >&2; exit 2; }
PREV=$1 THIS=$2 PLATFORM=$3
case $PLATFORM in
android) LIB=mobile/android/OID4VCWallet BUILD=mobile/build-aar.sh ;;
ios) LIB=mobile/ios/OID4VCWallet BUILD=mobile/build-xcframework.sh ;;
*) echo "the platform is android or ios, not $PLATFORM" >&2; exit 2 ;;
esac
cd "$(git rev-parse --show-toplevel)"
git cat-file -e "$PREV^{commit}" 2>/dev/null || { echo "no commit $PREV: fetch the full history" >&2; exit 1; }

# Each OID4VCgo package the library compiles, as a pathspec for its own
# Go files: github.com/idfoundry/oid4vcgo/internal/jose is internal/jose/*.go.
PACKAGES=$(cd mobile && go list -deps . | sed -n 's|^github\.com/idfoundry/oid4vcgo||p' |
	sed 's|^/||; s|^\(..*\)$|\1/|; s|^\(.*\)$|:(glob)\1*.go|')
[ -n "$PACKAGES" ] || { echo "go list found no OID4VCgo packages in mobile/" >&2; exit 1; }

# One record per commit (RS, \036): its short hash, header and body, then
# the files it changed among those above (FS, \037 between them).
# shellcheck disable=SC2086 # PACKAGES is one pathspec per word.
git log --reverse --no-merges --name-only --format='%x1e%h%x1f%s%x1f%B%x1f' "$PREV..$THIS" -- \
	$PACKAGES go.mod go.sum mobile/go.mod mobile/go.sum "$LIB" "$BUILD" ':!*_test.go' |
	awk -v RS='\036' -v FS='\037' -v lib="$LIB/" -v platform="$PLATFORM" '
	# Whether one of files, newline-separated paths, is under dir.
	function touches(files, dir,    n, i, changed) {
		n = split(files, changed, "\n")
		for (i = 1; i <= n; i++) if (index(changed[i], dir) == 1) return 1
		return 0
	}
	NF < 4 { next }
	{ hash = $1; header = $2; body = $3; files = $4 }
	header !~ /^(feat|fix|perf)(\([^)]*\))?!?: / { next }
	platform == "ios" && header ~ /(NFC|TNEP|Android)/ && !touches(files, lib) { if (!(header in left)) { left[header]; nl++ } next }
	seen[header]++ { next }
	{
		breaking = header ~ /^[a-z]+(\([^)]*\))?!: /
		n = split(body, lines, "\n")
		for (i = 1; i <= n; i++) if (lines[i] ~ /^BREAKING[ -]CHANGE: /) breaking = 1
		app = 0
		n = split(files, changed, "\n")
		for (i = 1; i <= n; i++) {
			if (changed[i] ~ /^mobile\/[^\/]*\.go$/ || index(changed[i], lib) == 1) app = 1
		}
		line = "- " header " (" hash ")"
		if (breaking && app) b[nb++] = line; else if (header ~ /^feat/) f[nf++] = line; else x[nx++] = line
	}
	END {
		if (nb + nf + nx == 0) print "No changes to the library since the previous release.\n"
		if (nb) { print "### Breaking changes\n"; for (i = 0; i < nb; i++) print b[i]; print "" }
		if (nf) { print "### Features\n"; for (i = 0; i < nf; i++) print f[i]; print "" }
		if (nx) { print "### Fixes\n"; for (i = 0; i < nx; i++) print x[i]; print "" }
		if (nl) print "Left out: " nl " change(s) to NFC or Android alone, which reach only the Kotlin library.\n"
	}'
