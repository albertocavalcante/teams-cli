#!/bin/sh
set -eu

# Read one subject per line. The local commit-msg hook and CI use this same rule.
export LC_ALL=C
count=0
while IFS= read -r subject || [ -n "$subject" ]; do
	count=$((count + 1))
	if [ "${#subject}" -gt 72 ] || ! printf '%s\n' "$subject" |
		grep -Eq '^(build|chore|ci|docs|feat|fix|perf|refactor|revert|style|test)(\([a-z0-9._/-]+\))?(!)?: .+'; then
		printf 'Invalid commit subject: %s\n' "$subject" >&2
		printf 'Use a Conventional Commit subject of at most 72 characters.\n' >&2
		exit 1
	fi
done

if [ "$count" -eq 0 ]; then
	printf 'No commit subjects to check.\n' >&2
	exit 1
fi
