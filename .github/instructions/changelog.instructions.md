# ChangeLog tag rules

When reviewing commits or pull requests, check whether the change is
"critical" — i.e. it has an impact on user-visible behavior — and
suggest that the commit message includes a `[ChangeLog]` tag if one is
missing.

## What counts as a critical change

A change is critical and **must** carry a `[ChangeLog]` tag when it does
any of the following:

- [ ] Introduces a new command-line option or changes/removes an existing one
- [ ] Changes the default value of an existing option or behavior
- [ ] Adds a new feature or capability visible to the user
- [ ] Changes the format or content of log output (YAML, TAP, or text)
- [ ] Fixes a bug that affected user-visible behavior or results
- [ ] Removes or deprecates a feature, option, or API
- [ ] Modifies system-level behavior (e.g. signal handling, process
      management, memory allocation strategy)
- [ ] Changes how the tool interacts with the operating system or
      hardware topology
- [ ] Fixes a bug that affect a test's causing crashes, hangs, or incorrect results

## What does NOT need a ChangeLog tag

- Pure refactoring with no user-visible effect
- Internal code cleanup or dead code removal that does not change behavior
- Test-only changes (new unit tests, selftest adjustments) unless they
  expose a new user-visible feature
- Build system or CI-only changes with no runtime impact
- Comment or documentation-only changes

## Tag format

The tag is placed in the commit message body (not the subject line) on
its own line, wrapped in square brackets:

```
[ChangeLog] Brief description of the user-visible change.
```

An optional scope can be added to categorize the change:

```
[ChangeLog][Framework] Description of a framework-level change.
[ChangeLog][Logging] Description of a logging change.
[ChangeLog][TestName] Description of a test-specific change.
```

### Rules for the tag

- [ ] Exactly one `[ChangeLog]` entry per logical user-visible change.
      A commit that makes multiple independent user-visible changes
      should have one tag per change.
- [ ] The description must be written from the user's perspective —
      describe what changed for the person running the tool, not the
      internal implementation detail.
- [ ] Use the optional scope (e.g. `[Framework]`, `[Logging]`) when the
      change clearly belongs to a specific subsystem.
- [ ] If a commit is clearly critical (per the checklist above) but has
      no `[ChangeLog]` tag, flag it during review and suggest one.
