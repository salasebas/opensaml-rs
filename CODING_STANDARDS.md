# Coding standards

## Doc comments

A doc comment says what the caller can do with the item.

The OASIS section, the obligated actor, and a note that a check is library
policy go in the pull request or in `docs/`.

## Caller-visible changes

The same pull request updates `docs/migrations/` when a caller must change
code, handle a new error, or extend an exhaustive `match`. A new public enum
variant is that change.

Follow [How to add a migration guide](CONTRIBUTING.md#how-to-add-a-migration-guide).
A compatible addition stays in the commit message. release-plz writes
`CHANGELOG.md`.

## Stricter than the cited section

When the diff rejects a message the cited section accepts, the pull request
says so in its own sentence: library policy, the section it exceeds, and why
the looser rule cannot be applied.
