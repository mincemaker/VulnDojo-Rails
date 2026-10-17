# VulnDojo-Rails — Notes for Claude

## Running Tests

Always run tests inside the container via docker compose or podman compose.
Running `bin/rails test` directly on the host will fail due to environment mismatches.

```bash
docker compose run --rm web bin/rails test
docker compose run --rm web bin/rails test test/integration/vulnerabilities/
```

Browser tests use e2e and run in a dedicated Docker service:

```bash
docker compose -f compose.yaml -f compose.e2e.yaml build e2e
docker compose -f compose.yaml -f compose.e2e.yaml run --rm e2e npm ci
docker compose -f compose.yaml -f compose.e2e.yaml run --rm e2e npx @e2e-dev/web install chromium
docker compose -f compose.yaml -f compose.e2e.yaml run --rm e2e npx e2e run
```

Run Minitest and e2e sequentially because they share the SQLite test database.
The current browser tests are deterministic and require no model credentials.
Do not run `e2e init` for a fresh checkout: the project is already initialized.

Agent skills are managed by `apm.yml` and `apm.lock.yaml`. Run
`apm install --frozen` on the host to deploy the e2e and migration skills for
Claude Code and Codex. Do not commit the generated skill directories.
Read `.agents/skills/e2e/SKILL.md` before writing or running browser tests;
`npx e2e guide <topic>` inside the e2e container also provides the installed
package's instructions.

For failures, read the runner's trace page and `.e2e/logs/rails-<port>-app.log`
and `rails-<port>-process.log`. Server logs persist after the app copies and
containers are removed.

## Starting the App

```bash
docker compose up   # or: podman compose up
```

Setting `VULN_CHALLENGES=all` in `.env` enables all vulnerability challenges at once.


@AGENTS.md
