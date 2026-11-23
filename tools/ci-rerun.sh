#!/bin/sh
# Runs again the jobs of a CI run that GitHub had no runner for, as it happens when its macOS
# runners are short: such a job ends cancelled with not one of its steps run, and the run with it
# as failed, though nothing was tested. Only when that is all that went wrong: a job that ran and
# failed is a failure to look at, and is not run again.
#
#	tools/ci-rerun.sh <owner/repository> <run id>
#
# The rerun workflow does it, when a CI run ends. DRY_RUN=1 only tells what it would do. It asks
# GitHub with gh.
set -eu
repo=$1 run=$2

# The jobs of the run's last attempt that did not pass, each with whether GitHub says it had no
# runner for it.
verdicts=$(gh api "repos/$repo/actions/runs/$run/jobs?per_page=100" \
	--jq '.jobs[] | select(.conclusion != null and .conclusion != "success" and .conclusion != "skipped") | "\(.id) \(.name)"' |
	while read -r id name; do
		if gh api "repos/$repo/check-runs/$id/annotations" --jq '.[].message' | grep -q "was not acquired by Runner"; then
			echo "no-runner $name"
		else
			echo "failed $name"
		fi
	done)

if [ -z "$verdicts" ]; then
	echo "ci-rerun: every job passed"
	exit 0
fi
echo "$verdicts" | sed 's/^/ci-rerun: /'
if echo "$verdicts" | grep -q "^failed "; then
	echo "ci-rerun: a job ran and failed: not run again"
	exit 0
fi
if [ -n "${DRY_RUN:-}" ]; then
	echo "ci-rerun: would run them again"
	exit 0
fi
gh run rerun "$run" --repo "$repo" --failed
echo "ci-rerun: run again"
