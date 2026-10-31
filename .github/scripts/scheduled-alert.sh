#!/usr/bin/env bash
# Reports an unattended workflow run (a schedule, a dispatch, a push to
# main) on a GitHub issue carrying the workflow's own label, so a red run
# can't go unnoticed: none of these runs is on a PR, and nothing else
# alerts on them.
#
# On a failed run it opens an issue listing the failing jobs and their
# logs, or comments on the open issue with that label if there already
# is one. On a passing run it comments on and closes that issue, if any.
# Any other result (a cancelled run) is left alone. Each workflow needs a
# label of its own: a passing run closes whatever issue has its label.
#
# Usage: scheduled-alert.sh <result> <label> <title> [fuzz]
#   <result> is the result of the jobs the alert job needs: success,
#   failure, cancelled or skipped.
#   <label> labels the issue (created if missing); <title> titles it.
#   fuzz: the run is fuzz.yml's, whose matrix jobs are named
#   "fuzz (<id>, <module>, <pkg>, <FuzzName>)"; the issue then lists the
#   failing targets with the commands to replay each one's input.
# Environment: GH_TOKEN and GH_REPO (for gh), RUN_ID, RUN_NUMBER,
# RUN_URL, and WORKFLOW (the workflow's name, for the text).
set -euo pipefail

result=$1
label=$2
title=$3
kind=${4:-}

open_issue() {
	gh issue list --label "$label" --state open --limit 1 --json number --jq '.[0].number // empty'
}

# failed_jobs prints one tab-separated "<name> <conclusion> <url>" line
# per finished job of this run that didn't pass (the alert job itself
# hasn't finished, so it isn't one).
failed_jobs() {
	gh api --paginate "repos/$GH_REPO/actions/runs/$RUN_ID/jobs?per_page=100" \
		--jq '.jobs[]
			| select(.conclusion != null and .conclusion != "success" and .conclusion != "skipped")
			| [.name, .conclusion, .html_url] | @tsv'
}

jobs_body() {
	local jobs=$1 name conclusion url
	echo "$WORKFLOW run #$RUN_NUMBER failed: $RUN_URL"
	echo
	echo "| Job | Result | Log |"
	echo "| --- | --- | --- |"
	if [[ -z "$jobs" ]]; then
		echo "| ? | failure | $RUN_URL (no failed job found; see the run) |"
	fi
	while IFS=$'\t' read -r name conclusion url; do
		[[ -n "$name" ]] || continue
		echo "| $name | $conclusion | [log]($url) |"
	done <<<"$jobs"
	echo
	echo "This issue closes itself on the next $WORKFLOW run that passes."
}

fuzz_body() {
	local jobs=$1 name conclusion url id module pkg target
	local -a failed=()
	echo "$WORKFLOW run #$RUN_NUMBER failed: $RUN_URL"
	echo
	echo "| Module | Package | Target | Result | Log |"
	echo "| --- | --- | --- | --- | --- |"
	while IFS=$'\t' read -r name conclusion url; do
		[[ -n "$name" ]] || continue
		if [[ "$name" =~ ^fuzz\ \(([^,]+),\ ([^,]+),\ ([^,]+),\ ([^\)]+)\)$ ]]; then
			id=${BASH_REMATCH[1]} module=${BASH_REMATCH[2]} pkg=${BASH_REMATCH[3]} target=${BASH_REMATCH[4]}
			failed+=("$id"$'\t'"$module"$'\t'"$pkg"$'\t'"$target")
			echo "| \`$module\` | \`$pkg\` | \`$target\` | $conclusion | [job]($url) |"
		else
			echo "| | | $name | $conclusion | [job]($url) |"
		fi
	done <<<"$jobs"
	if [[ -z "$jobs" ]]; then
		echo "| ? | ? | ? | failure | $RUN_URL (no failed job found; see the run) |"
	fi
	cat <<EOF

To reproduce, from the repository root, download a target's
\`fuzz-failure-<id>\` artifact, which puts the failing input at
\`<module>/<pkg>/testdata/fuzz/<Target>/<file>\` (there is none if the
job failed without writing one), and replay it from the module's
directory with \`go test <pkg> -run '<Target>/<file>'\`, or every seed
of the target with \`-run '<Target>'\`:

\`\`\`sh
EOF
	local entry
	for entry in ${failed[@]+"${failed[@]}"}; do
		IFS=$'\t' read -r id module pkg target <<<"$entry"
		echo "gh run download $RUN_ID -n fuzz-failure-$id && (cd $module && go test $pkg -run '$target')"
	done
	cat <<EOF
\`\`\`

Fix the bug and commit the input with the fix, where it stays as a
regression seed that every \`go test\` run replays. This issue closes
itself on the next $WORKFLOW run that passes.
EOF
}

case "$result" in
failure)
	jobs=$(failed_jobs)
	body=$(mktemp)
	trap 'rm -f "$body"' EXIT
	if [[ "$kind" == fuzz ]]; then
		fuzz_body "$jobs" >"$body"
	else
		jobs_body "$jobs" >"$body"
	fi
	issue=$(open_issue)
	if [[ -n "$issue" ]]; then
		gh issue comment "$issue" --body-file "$body"
	else
		gh label create "$label" --color d93f0b \
			--description "$WORKFLOW failures" --force
		gh issue create --title "$title" --label "$label" --body-file "$body"
	fi
	;;
success)
	issue=$(open_issue)
	if [[ -n "$issue" ]]; then
		gh issue close "$issue" --comment "$WORKFLOW run #$RUN_NUMBER passed: $RUN_URL"
	fi
	;;
*)
	echo "$WORKFLOW's result is \"$result\"; nothing to report."
	;;
esac
