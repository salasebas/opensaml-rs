# Issue tracking: public GitHub and private Linear

This repo deliberately uses two issue trackers:

- **GitHub Issues** is the public intake and collaboration surface.
- The **private `OpenSaml` Linear team** is the maintainer's planning surface
  for private engineering work.

An item has one canonical tracker. Do not mirror whole issues, comments, or
private planning between trackers.

## Routing

Choose the tracker before the first write:

| Work | Canonical tracker |
| --- | --- |
| Public bug report or feature request | GitHub |
| `/triage`, including every raw external request | GitHub |
| A GitHub URL, `#<number>`, or public contributor task | GitHub |
| Private planning initiated by the maintainer | Linear |
| Maintainer-initiated `/to-tickets` or `/wayfinder` | Linear |
| A Linear URL or issue identifier | Linear |
| `/implement` | The tracker of the supplied ticket |

When a private planning flow starts from a public GitHub issue, the GitHub
issue remains the canonical public conversation and status. Private planning
and child tickets may live in Linear and may link **to** the GitHub issue.
Never add the private Linear link or private planning detail back to GitHub.

If routing is still ambiguous, ask the maintainer before publishing. Reading
the codebase and drafting work locally do not require that clarification.

## Public GitHub operations

Infer the repository from `git remote -v` and use the `gh` CLI.

- **Create**: `gh issue create --title "..." --body "..."`
- **Read**: `gh issue view <number> --comments`
- **List**: `gh issue list --state open --json number,title,body,labels,comments`
- **Comment**: `gh issue comment <number> --body "..."`
- **Label**: `gh issue edit <number> --add-label "..."` or
  `--remove-label "..."`
- **Close**: `gh issue close <number> --comment "..."`

Public tickets produced specifically for an external collaborator remain on
GitHub and use the triage labels in `docs/agents/triage-labels.md`.

### Pull requests as a triage surface

**PRs as a request surface: no.**

Pull requests remain public code-review artifacts, but `/triage` does not
discover them as incoming requests. Resolve an explicitly supplied bare
`#<number>` with `gh pr view <number>` and fall back to
`gh issue view <number>`.

## Private Linear operations

Use the connected Linear app, resolve the team by the exact name `OpenSaml`,
and use the returned opaque identifier for that session. Do not commit the
workspace or team UUID, a private issue URL, or exported private issue data.

The maintainer has approved `OpenSaml` as the private planning destination; do
not ask for a URL or re-confirm the destination on every write. If Linear
reports that the team is visible beyond the intended workspace membership,
stop before publishing and ask the maintainer to correct its visibility.

For `/to-tickets`:

1. Create issues in dependency order in `OpenSaml`.
2. Set each ready ticket to `Todo` and apply `ready-for-agent`.
3. Express blocking edges with Linear's native `blockedBy` relationships.
4. If the source is public, attach its GitHub URL from Linear only.
5. Do not create a matching GitHub issue.

For a Linear ticket passed to `/implement`, fetch its full description and
relationships, assign it to the acting maintainer when work starts, and move it
through `In Progress`, `In Review`, and `Done` as those states become true.
The code and pull request may still be public; keep their prose limited to
information intentionally ready for publication.

## Cross-tracker privacy

- Do not enable automatic GitHub Issues sync for this workflow.
- Do not copy Linear titles, descriptions, comments, URLs, or identifiers into
  public GitHub issues, commits, branch names, or pull requests.
- Do not use Linear-generated branch names for private tickets.
- Do not use GitHub magic words that link a public PR to a private Linear issue.
- Public updates derived from private planning must be deliberately rewritten
  as standalone, sanitized summaries.
- Existing GitHub issues stay on GitHub; setup never imports, closes, or
  duplicates them.

Collaborators and agents without Linear access work only from GitHub. If a
private Linear ticket is required but cannot be accessed, do not create a
public fallback ticket; report the access blocker to the maintainer.

## Linear wayfinding operations

Used by maintainer-initiated `/wayfinder`:

- **Map**: one Linear issue in `OpenSaml`, labelled `wayfinder:map`.
- **Child ticket**: a Linear sub-issue of the map, labelled
  `wayfinder:research`, `wayfinder:prototype`, `wayfinder:grilling`, or
  `wayfinder:task`.
- **Blocking**: Linear's native `blockedBy` relationships. An issue is
  unblocked only when every blocker is complete.
- **Frontier**: open child issues with no incomplete blocker and no assignee,
  in map order.
- **Claim**: assign the issue to the acting maintainer and move it to
  `In Progress` before doing any work.
- **Resolve**: post the resolution, move the issue to `Done`, and append a
  one-line linked gist to the map's `Decisions so far`.

Never resolve more than one non-research wayfinding ticket per session.
