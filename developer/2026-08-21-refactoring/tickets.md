# Refactoring epic — ticket processing order

## Processing contract

This index is the only execution order for the refactoring epic. Complete one
numbered ticket in the named file, commit it with the git-commit skill, and
only then begin the next numbered ticket or file. Do not begin a later file
while an earlier file still has an unfinished ticket.

For every ticket, work in vertical red-green-refactor cycles: begin with one
public behavioural test, make only that test pass, then take the next
behaviour. Refactor only while the suite is green. Tests must use public CLI,
SSH, runtime, identity, and persistence interfaces; do not add tests which
assert private calls, module layout, or mocked application collaboration.

The refactor preserves the regression contract in `refactoring-review.md`.
It does not approve new authentication, certificate, issuance, authorization,
or operator-visible behaviour. A discovered behaviour change needs a separate
reviewed ticket.

Before completing every ticket run:

```console
uv run ruff format
uv run ruff check --fix
uv run ty check
uv run pytest
```

## File order

1. [`tickets-r8.md`](tickets-r8.md) — shared public-behaviour test fixtures.
2. [`tickets-r7.md`](tickets-r7.md) — domain policy and typed failures.
3. [`tickets-r1.md`](tickets-r1.md) — SQLite persistence boundaries.
4. [`tickets-r3.md`](tickets-r3.md) — issuer identity interfaces and demo
   administration.
5. [`tickets-r4.md`](tickets-r4.md) — single issuance and agent workflow.
6. [`tickets-r2.md`](tickets-r2.md) — CLI application workflows.
7. [`tickets-r5.md`](tickets-r5.md) — runtime lifecycle facade.
8. [`tickets-r6.md`](tickets-r6.md) — obsolete tracer removal.

## Refactoring guidance

Use extraction only to remove demonstrated duplication, move behaviour to the
module which owns its data, and create deeper modules with smaller public
interfaces. Do not split modules to meet a line-count target, create a generic
repository framework, introduce a generic `utils` module, or add a migration
framework. Use the focused architecture regression tests defined by R1 and R7
instead of a new architecture-testing dependency.
