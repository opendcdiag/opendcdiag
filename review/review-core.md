# OpenDCDiag Patch Review Protocol


## OpenDCDiag overview
OpenDCDiag is a tool to find defects in CPU cores by running tests which
compare the output of a computation to known good values. OpenDCDiag
contains Apache licensed code only.

The source code is open source and will be shared with customers;
comments, variable names, etc. should use professional language standards.


## Patch review steps

This protocol guides systematic review of OpenDCDiag patches for correctness,
coding style, optimization opportunities and potential regressions.

There are 4 phases to this code review:
1. Context gathering and preparation
2. Targeted Code review
3. Deep review of context of the code
4. Result reporting


# Phase 1: Context gathering and preparation

## Review instructions source

All review instruction files (`review/*.md`) must always be loaded as a
combination of `origin/main` and any branch-specific changes, using the
following procedure:

1. Run `git fetch origin` to ensure `origin/main` is up to date.
2. Find the merge base (the commit where the branch diverged from main):
   `MERGE_BASE=$(git merge-base origin/main HEAD)`
3. Check whether the branch introduces any `review/` changes on top of that
   merge base: `git diff $MERGE_BASE -- review/` (compares the working tree,
   including unstaged edits, against the merge base).
4. If that diff is **empty**: read every instruction file directly from
   `origin/main` using `git show origin/main:review/<file>`.
5. If the diff is **non-empty**: for each modified `review/` file, read both
   the `origin/main` version (`git show origin/main:review/<file>`) and the
   working-tree version, then mentally merge them — treating both as parallel
   evolutions from the same ancestor. Use the merged result as the effective
   instructions. Read all other `review/` files solely from `origin/main`.

## Authoritative commit for pull request reviews

When reviewing a pull request, always begin by fetching the authoritative HEAD
commit SHA directly from GitHub:

```
gh pr view <N> --repo <owner>/<repo> --json headRefOid --jq '.headRefOid'
```

Record this SHA and use it exclusively for all `git show`, `git diff`, and
`Reviewed-at` references throughout the review. Never use a local branch HEAD
as a substitute — local branches may be out of date or may have been rebased
onto newer main commits, leading to review of code that is not part of the PR.

## Pre-review context setup

Before beginning the review:
1. Load subsystem-specific files based on changed code (see triggers below)
2. Load `style.md` for coding style checks
3. Load `modernize.md` for code modernization patterns
4. Load `general-c++.md` for general C++ language patterns

Load subsystem files based on code locations and patterns:

| Trigger | File to Load |
|---------|--------------|
| `tests/` | `test.md` |
| `framework/` | `framework.md` |

## Previous reviews

When reviewing a pull request, get the whole pull request from GitHub, and
note any prior review findings from this pull request for detailed analysis
in the Phase 3 tasks.

The review output file for a pull request is named `review-<PR_NUMBER>.txt`
(e.g. `review-3397.txt`) in the current working directory. If that file exists,
read it and take note of any prior review findings for use in the Phase 3 tasks.

When no PR exists yet (e.g. a developer is reviewing work in progress on a branch),
the review output file may instead be named `review-<BRANCH_NAME>.txt`
(e.g. `review-my-feature-branch.txt`). Check for this file using the current branch
name; if it exists, treat it the same as `review-<PR_NUMBER>.txt`.

## Identify Changed Functions and load into the context

Use available tools to identify all functions modified by the patch:
- For pull requests: diff against the authoritative PR HEAD SHA obtained in
  Phase 1 (e.g. `git diff <base>...<authoritative-sha>` or
  `git show <authoritative-sha>:path/to/file` for full file context)
- For git commits: examine the diff at the specific commit SHA
- List each modified function with its file location
- Manually find function definitions and relationships with the
    `function-lookup` skill, and fall back to grep and other tools
- Document any missing context that affects research quality

Never use fragments of code from the diff without first trying to find the
entire function or type in the sources.  Always prefer full context over
diff fragments.

# Phase 2: Targeted Code review 

Perform a full code review on the identified code:

- [ ] All normal and general code review checks
- [ ] Verify conformance to the coding style of all changes
- [ ] Perform all subsystem specific tasks as identified in Phase 1

Only mark complete after all verification checks are performed; do not terminate early

At the end of the review task, check that all review checks have been
performed, and correct any missed items.

Label every issue with a severity level of "none", "nit", "low", "medium", "high" or "critical"

Severity "nit" means a trivial cosmetic issue that does not affect correctness
or readability.

Prepare all needed information for reporting later, by putting all findings into your
context. In addition, write out a preliminary report file using the format
defined in Phase 4, which can then be updated in Phase 3.

# Phase 3: Deep review of context of the code

In this third phase, a second, deeper round of code review is performed, using the results of phase 2
as context.

In this phase, perform a thorough contextual review:

- [ ] Review all functions that are being modified entirely and thoroughly,
      even the lines that are not modified by this pull request.
- [ ] Check any function these functions call, or are called by.

Use all subsystem rules and context loaded in Phase 1 as guide, but also go beyond these
tasks to do the most thorough review possible.

Label every issue with a severity level of "none", "nit", "low", "medium", "high" or "critical"

Prepare any issues found for reporting later in a separate reporting
section.


# Phase 4: Result reporting

**Goal**: Create a clear, actionable report

Create `review-<PR_NUMBER>.txt` (e.g. `review-3397.txt`) in the current working
directory, never in the review/ rules directory. If no PR exists yet, use
`review-<BRANCH_NAME>.txt` (e.g. `review-my-feature-branch.txt`) instead — this
file will serve as prior context once a PR is opened. Always overwrite the file completely
from scratch — delete all prior content first, then write the new review
as the sole content. Never append to or partially edit an existing file.

Use Markdown format for the whole report and prefer plain ascii characters.

Create a set of sections:
1. Review task summary
2. Issues found (phase 2)
3. Additional issues found (phase 3)
4. Executed checks
5. Notes

If no issues are found in Phase 2 or Phase 3, state this explicitly in
sections 2 and 3 and omit the Output Format details below.

**If issues are found**
1. Label every issue with a severity level of "none", "nit", "low", "medium", "high" or "critical"
2. Follow the protocol described in the False Positive Check section below
3. Follow the format described in the Output Format section
4. Create a one sentence explanation for your issue severity score. If there
are no issues, just use "none"

## Review task summary section
Start the file by stating the task you were given.
Then mention the name and version of the model being used using the
following sentence:
"This AI review was performed by model <name> version <version>."
Also record the HEAD commit SHA at the time of the review using the
following line:
"Reviewed-at: <full commit SHA>"


## Output Format (Sections 2 and 3)

Issues are divided into two categories:

**Code-specific issues** (tied to a file and line number):
Do not number these issues -- they are identified by their location.
For each issue:
1. File and line number
2. Severity level
3. Description of the issue
4. Suggested fix (if applicable)
5. For each issue that was pre-existing (i.e. not introduced by any of the
   commits under review), use "git blame -w" to find the commit that
   introduced the issue. Report both the git commit hash and the one-line
   subject of each such commit

If multiple code-specific issues are inter-related, consolidate them into
a single issue covering all affected locations, rather than listing them
separately.

**Design/structural issues** (no specific file or line):
Present these as an unordered bullet list. Do not number them.
If issues are inter-related, merge them into a single bullet item that
captures the full scope. Keep the total number of such items to a minimum.



## Executed Checks section
Create an "Executed checks" section that lists all the checks that were
performed in a checklist format, while numbering the tests.

## Notes section

Create a separate "Notes" section for all "none" severity items.


## False Positive Check

Before reporting any issue:
1. Verify the issue can actually occur in practice
2. Trace the execution path to confirm


## Creating pull requests

Never create pull requests automatically. After completing the review, ask
the user whether pull requests should be created for the issues found.

If the user agrees to create pull requests, only address high and critical
severity items unless the user explicitly requests fixes for lower severity
issues as well.

When creating pull requests, create one pull request per found issue. If a
single issue impacts multiple independent locations, create a separate git
commit for each location. In the commit message and pull request
description, provide the full analysis of the issue consistent with the
Output Format section.

Start the pull request description with this sentence:
"These issues were found and the PR created using AI analysis by model <name> version <version>."

Before finalizing the pull request, verify that any coding style fix
does not change behavior of the code, only the style.

Apply the "AI" label to the pull request to disclose the AI origin of the
PR.


## Reviewing pull requests

If you were asked to review a pull request, after writing the
`review-<PR_NUMBER>.txt` file, perform the following deduplication and
posting steps.

### Step 0: Verify PR HEAD has not advanced

Before deduplicating or posting, re-fetch the current PR HEAD SHA from GitHub
and compare it to the SHA used during the review (recorded in `Reviewed-at`):

- If they are **the same**: proceed to Step 1.
- If they **differ**: compute the diff between the reviewed SHA and the current
  HEAD (`git diff <reviewed-sha> <current-head>`). Examine whether the diff
  touches any file and line where a finding was raised:
  - If **none** of the finding locations are affected: the findings still apply;
    update the `Reviewed-at` line to the new HEAD SHA with a note such as
    `(findings validated through this commit, not a full re-review)` and
    proceed to Step 1.
  - If **any** finding location is affected: re-review those areas against the
    new HEAD before proceeding. Update `Reviewed-at` to the new HEAD SHA (no
    qualification needed — the affected areas were actively re-reviewed) and
    update the affected findings accordingly, then proceed to Step 1.

### Step 1: Deduplicate against existing PR comments
Fetch all existing review comments on the pull request using the GitHub
API. Drop any finding that has already been raised by any reviewer,
regardless of who posted it. Also review the full PR comment history:
if prior reviewers raised issues that are still relevant to your findings,
note them; if they have been addressed or dismissed, do not re-raise them.

### Step 2: Post net-new findings
Post only the findings that survived both deduplication steps:

- **Inline comments**: for each finding with a specific file and line
  number, post it as an inline review comment on the pull request.

- **Review summary**: collect any findings that are structural or
  design-level (no specific file/line) into a pull request review
  summary. Submit the review with verdict:
  - `REQUEST_CHANGES` if any summary finding is severity "high" or
    "critical"
  - `COMMENT` in all other cases
  - Never use `APPROVE` -- PR approval is reserved for human reviewers

If there are no design-level findings, submit inline comments without a
summary review, or with a brief neutral `COMMENT` body noting the scope
of the review.


## Commit messages

Follow the standard Linux kernel commit message format. Include `Signed-off-by:` trailer (required per `CONTRIBUTING.md`).

In each commit message, explicitly mention the name and version of the LLM model used to find the
issue using the sentence 
"This issue was found and the PR created using AI analysis by model <name> version <version>."



