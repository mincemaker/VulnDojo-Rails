# VulnDojo-Rails — Workflow Rules

## Branching & Commits
- Never commit directly to main. Create a feature branch before any implementation work, even for small fixes.
- For multi-step changes that will become a PR, confirm the branch strategy before starting.
- Commit tests and implementation together in the same commit.

## TDD Workflow
- Always use TDD (RED → GREEN → REFACTOR) for new features.
- A server startup failure is NOT a valid RED state — write a failing test first.

## Upgrading Ruby

When upgrading the Ruby version, also update Bundler to avoid constant redefinition
warnings (`Gem::Platform::WINDOWS`) that occur when the old Bundler is incompatible
with the new Ruby's RubyGems.

1. Update `ARG RUBY_VERSION` in `Dockerfile`
2. Update `ruby "x.y.z"` in `Gemfile`
3. Update `.ruby-version`
4. Rebuild the image: `docker compose build`
5. Update Bundler in `Gemfile.lock`: `docker compose run --rm web bundle update --bundler`
6. Commit all four files together
