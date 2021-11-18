#!/bin/bash

# This scripts checks that no tabs is present in the changeset and is used as
# part of github actions. However, it is not github-action specific.

# It takes two arguments: the ref name of the target branch and the SHA1 of the
# commit, e.g.:
# scripts/check-no-tabs.sh main e7f58691

target=$1
head=$2

set -o errexit
set -o pipefail

LINES_WITH_TABS=$(
    git diff ${target}..${head} --                               \
        '*.cpp' '*.c' '*.h' '*.hpp' '*.yaml' ':!/3rdparty'       \
    | (grep '^+' || :)                                           \
    | sed -ne '/.*/{ /^+++ b\//{ s/^+++ b\//In file /; s/$/:/; h }; /\t/{ x; p; x; p; }}'
)
if [[ ${LINES_WITH_TABS} ]]; then
    echo "::error:: Changeset adds tabs. Change them to spaces."
    echo "------"
    echo "${LINES_WITH_TABS}"
    echo "------"
    exit 1
fi
exit 0
