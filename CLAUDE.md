# VulnDojo-Rails — Notes for Claude

## Running Tests

Always run tests inside the container via docker compose or podman compose.
Running `bin/rails test` directly on the host will fail due to environment mismatches.

```bash
docker compose run --rm web bin/rails test
docker compose run --rm web bin/rails test test/integration/vulnerabilities/
```

## Starting the App

```bash
docker compose up   # or: podman compose up
```

Setting `VULN_CHALLENGES=all` in `.env` enables all vulnerability challenges at once.

## TDD Workflow

Write failing tests first (RED), then implement the fix (GREEN).
Commit tests and implementation together in the same commit.

1. Write tests that reproduce the problem — confirm they fail
2. Implement the fix — confirm tests pass
3. Run the full suite to check for regressions
4. Commit tests and implementation together
