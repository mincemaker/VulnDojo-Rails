# VulnDojo-Rails — Workflow Rules

## Branching & Commits
- Never commit directly to main. Create a feature branch before any implementation work, even for small fixes.
- For multi-step changes that will become a PR, confirm the branch strategy before starting.
- Commit tests and implementation together in the same commit.

## TDD Workflow
- Always use TDD (RED → GREEN → REFACTOR) for new features.
- A server startup failure is NOT a valid RED state — write a failing test first.
