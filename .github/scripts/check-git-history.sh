#!/bin/bash

# This script checks the sanity of the history on the branch:
#   * there are no merge commits on the branch;
#   * all the commits have sign-off-by as required.

# It takes two arguments: the ref name of the target branch and the commit-ish
# of the branch being merged, e.g.:
# scripts/check-git-history.sh main e7f58691

target=$1
head=$2
err=0

base=$(git merge-base ${target} ${head})

# check there are no merges on the branch
merges=$(git log --oneline --merges ${base}..${head})

if [[ -n "${merges}" ]]; then
    echo "::error:: The branch contains merge commits. Rebase your work on top of current ${target}."
    err=1
fi

# look sign offs in all the non-merge commits
for sha in $(git log --no-merges --format=%H ${base}..${head}); do
    signoff=$(git show -s --format=%B ${sha} | grep '^Signed-off-by:')
    if [[ -z "${signoff}" ]]; then
        echo "::error:: Commit ${sha} does not contain Signed-off-by. Rebase and amend with 'git commit --amend --signoff'."
        err=1
    fi
done
exit $err
