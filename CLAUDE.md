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
