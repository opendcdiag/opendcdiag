#!/bin/bash

# This script checks the sanity of the history on the branch:
#   * there are no merge commits on the branch;
#   * all the commits have sign-off-by as required.

# When the PR branch is checked out in CI actions, it's a temporary merge
# commit. This script looks at the right parent to see if all the non-merge
# commit follow the requirements.

target=$1
head=$2
err=0


read left right <<<$(git show -s --pretty=%P ${head})

if [[ -z "${right}" ]]; then
    echo "::error:: ${head} is expected to merge commit for the PR. (Cannot retrieve tip of the branch.)"
fi

base=$(git merge-base origin/${target} ${right})

# check there are no merges on the branch
merges=$(git log --oneline --merges ${base}..${right})

if [[ -n "${merges}" ]]; then
    echo "::error:: The branch contains merge commits. Rebase your work on top of current ${target}."
    err=1
fi

# look sign offs in all the non-merge commits
for sha in $(git log --no-merges --format=%H ${base}..${right}); do
    signoff=$(git show -s --format=%B ${sha} | grep '^Signed-off-by:')
    if [[ -z "${signoff}" ]]; then
        echo "::error:: Commit ${sha} does not contain Signed-off-by. Rebase and amend with 'git commit --amend --signoff'."
        err=1
    fi
done
exit $err
