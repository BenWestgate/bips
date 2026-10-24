# Contributing Guidelines

Keep each pull request focused on one independently reviewable change.
Separate unrelated behavior changes, refactoring, and formatting before coding.
Match the surrounding style in code and documentation, and avoid unrelated
rewrites.

## Typos

Among other tasks, the CI verifies that changes do not contain common typos.
This check is done using [`typos`](https://github.com/crate-ci/typos).
To run this task locally, install [`typos`](https://github.com/crate-ci/typos)
and then run in the root directory:

```bash
typos
```
