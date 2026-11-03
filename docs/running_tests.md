# Running tests

## Per-entry seeds in test-list files

Files passed to `--test-list-file` accept one test per line:

```text
test_name[:duration] [seed=ENGINE:STATE] # optional comment
```

Existing lists without seeds remain valid, including blank lines, comments,
duplicate tests, and `default` or empty durations. For example:

```text
simple_add:100ms seed=LCG:560936296
simple_add seed=LCG:1234 # a separate invocation of the same test
simple_add:default
```

A row seed overrides `-s` for that entry and is pinned: the framework restores it
before initialization on every fracture, retry, and cycle through the list.
Shuffling keeps each seed with its entry. Entries without seeds keep the usual
RNG behavior. Seed advancement after an entry is unchanged, so a following
unseeded entry continues from the outgoing state rather than restoring the CLI
seed.

Row seeds must contain a complete serialized state for an available engine:
`LCG` accepts values from 1 through 2147483646, and `AES` accepts exactly 64
hexadecimal digits on systems with AES support. Filenames, entropy requests,
`help`, `list`, incomplete states, and trailing tokens are not accepted as row
seeds. Invalid row seeds produce a startup error identifying the line, with exit
status 64.

The `-s` option also requires complete, valid explicit states. It continues to
support `help`, `list`, seed files, and engine-only entropy requests such as
`LCG` or `LCG:`. It handles `help` and `list` before trying seed files; otherwise,
seed files are tried before interpreting the argument as an engine name or
explicit state.

YAML failure metadata includes `fail.test-list-line`, a scalar such as
`simple_add seed=LCG:560936296` that can be copied directly into a test-list file.
It contains only the test name and canonical attempt-start seed, not duration or
execution flags. Reusing the seed does not restore other execution settings or
guarantee identical scheduling.
