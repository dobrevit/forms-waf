# Lua unit tests

Run against LuaJIT — the interpreter that serves traffic — via a test-only
image. `openresty/Dockerfile` is untouched, so the production image carries no
test tooling.

```bash
docker build -t forms-waf-lua-test -f openresty/Dockerfile.test ./openresty

# everything
docker run --rm -v "$PWD/openresty/lua:/app/lua:ro" \
                -v "$PWD/openresty/spec:/app/spec:ro" \
                forms-waf-lua-test --verbose /app/spec

# one file
docker run --rm -v "$PWD/openresty/lua:/app/lua:ro" \
                -v "$PWD/openresty/spec:/app/spec:ro" \
                forms-waf-lua-test --verbose /app/spec/rbac_spec.lua
```

Sources are mounted, so editing a module or a spec needs no rebuild.

## Writing a spec

`spec_helper` installs a minimal `ngx` and stubs the modules that would
otherwise reach Redis, MaxMind or OpenSSL. Install them *before* requiring the
module under test, and clear it from `package.loaded` so it re-runs against the
fresh stubs:

```lua
local helper = require "spec_helper"

describe("my_module", function()
    local my_module

    before_each(function()
        helper.install_ngx()
        helper.stub_external_modules()
        package.loaded["my_module"] = nil
        my_module = require "my_module"
    end)
end)
```

`ngx.logged` collects log calls, so a spec can assert on what was logged rather
than only on return values.

## Scope

These cover pure logic: config resolution, permission mapping, pattern scoring,
matching. Anything needing real Redis, MaxMind or a live request belongs in
`scripts/test-waf.sh`, and the seam between the resolver and the defense
mechanisms is covered separately by `openresty/tests/config_contract_spec.lua`.

The modules chosen first are the ones that actually shipped defects: silently
dropped config keys, unreachable routes, and scoring that decides
flag-versus-block.
