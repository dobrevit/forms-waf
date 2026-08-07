# Contributing

Thanks for considering a contribution.

## Before you start

For anything beyond a small fix, open an issue first. This is a security product
with a defence engine whose scoring is calibrated against real traffic patterns,
and a change that looks harmless can shift the boundary between "flag" and
"block" for every deployment. Discussing the shape of a change first saves
rework.

**Security issues do not belong in pull requests or public issues.** See
[SECURITY.md](SECURITY.md).

## Development

The stack runs under Docker Compose; see [README.md](README.md). `CLAUDE.md`, if
present in your checkout, carries working notes on the architecture.

```bash
docker compose up -d --build
docker compose exec redis sh /init-data.sh     # seed defaults
```

## The checks your change must pass

CI runs these on every pull request, and all of them block:

```bash
# Lua unit tests (busted, on LuaJIT -- see openresty/spec/README.md)
docker build -t forms-waf-lua-test -f openresty/Dockerfile.test ./openresty
docker run --rm -v "$PWD/openresty/lua:/app/lua:ro" \
                -v "$PWD/openresty/spec:/app/spec:ro" \
                forms-waf-lua-test --verbose /app/spec

# Admin UI
cd admin-ui && npm ci && npm run typecheck && npm run lint && npm run audit:gate

# Integration suite (needs a running stack, and admin credentials so it can
# raise the rate limits it would otherwise trip)
WAF_ADMIN_USER=admin WAF_ADMIN_PASS=... ./scripts/test-waf.sh

# API contract, against a running stack
python3 scripts/check-api-contract.py
```

Syntax-check Lua with **LuaJIT**, not the system `luac`. Several modules use
`goto`/`::continue::`, which PUC Lua 5.1 rejects and Lua 5.4 accepts — neither
matches the runtime.

## Things that are easy to get wrong

These have each caused a shipped defect, so they are worth knowing up front.

**A new endpoint config key must be added to `config_resolver.resolve()`.** That
function builds its result from an explicit allowlist, and anything not named
there is silently dropped before the request path sees it. Three features were
inert for exactly this reason. `openresty/tests/config_contract_spec.lua` guards
the seam — add your key to it.

**A new Admin API route needs an RBAC entry.** `rbac.check_permission()`
default-denies any route with no mapping, so a registered-but-unmapped handler
returns 403 for every role including admin. The startup audit will log the gap;
do not ignore it.

**A change to an API response shape needs the OpenAPI spec updated.**
`docs/openapi.yaml` is validated against a live server, and the admin UI's types
are generated from it. Both directions are enforced.

**Defaults are a security decision.** Shipping something permissive "so the
tests pass" is how the allowlist ended up disabling the WAF. If a test and a
default disagree, work out which one is wrong.

## Commits and pull requests

- `type: Subject` — `feat:`, `fix:`, `docs:`, `test:`, `chore:`, `ci:`
- Explain *why*, not just what. A commit that says what the diff already says is
  a wasted opportunity.
- Say what you verified, and how. "Tests pass" is weaker than the numbers.
- Branch from `main`, open a PR against `main`.

## Contributor License Agreement

Contributions require a signed CLA — see [CLA.md](CLA.md). This lets the project
relicense or dual-license in future without tracking down every past
contributor. You keep the copyright in your contribution.
