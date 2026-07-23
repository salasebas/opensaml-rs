# Triage Labels

The skills use five canonical state roles. Keep the same label strings on
GitHub and Linear so tickets retain their meaning without exposing private
content.

| Role | GitHub label | Linear label | Meaning |
| --- | --- | --- | --- |
| `needs-triage` | `needs-triage` | `needs-triage` | Maintainer evaluation is required |
| `needs-info` | `needs-info` | `needs-info` | Waiting for more information |
| `ready-for-agent` | `ready-for-agent` | `ready-for-agent` | Ready for an AFK agent |
| `ready-for-human` | `ready-for-human` | `ready-for-human` | Requires human implementation |
| `wontfix` | `wontfix` | `wontfix` | Will not be actioned |

`/triage` operates only on public GitHub issues. Linear uses the same
vocabulary for tickets created by private planning flows;
`/to-tickets` applies `ready-for-agent` by default.

## Linear status mapping

Labels communicate the workflow role; Linear statuses communicate execution:

| Condition | Linear status |
| --- | --- |
| Unshaped or waiting for information | `Backlog` |
| Ready to start | `Todo` |
| Claimed and being implemented | `In Progress` |
| Implementation under review | `In Review` |
| Completed | `Done` |
| Rejected or abandoned | `Canceled` |

Use exactly one canonical state-role label on a triaged GitHub issue. On
Linear, replace a previous canonical state-role label when the role changes;
do not accumulate contradictory roles.
