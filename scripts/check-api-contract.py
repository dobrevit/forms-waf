#!/usr/bin/env python3
"""
Validate the Admin API against docs/openapi.yaml.

A specification that nobody executes drifts exactly like the hand-written
TypeScript client did. This calls every documented GET endpoint on a running
instance and checks the response against its schema, so the spec is only ever
as stale as the last CI run.

Deliberately implements the small JSON Schema subset the spec uses -- type,
required, properties, items and $ref -- rather than pulling in a validator, so
it runs anywhere python3 does.

Usage: check-api-contract.py [admin_url] [username] [password]
"""
import json
import sys
import urllib.error
import urllib.request

try:
    import yaml
except ImportError:
    print("PyYAML is required: pip install pyyaml", file=sys.stderr)
    sys.exit(2)

ADMIN_URL = (sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8082").rstrip("/")
USERNAME = sys.argv[2] if len(sys.argv) > 2 else "admin"
PASSWORD = sys.argv[3] if len(sys.argv) > 3 else "changeme"

SPEC_PATH = "docs/openapi.yaml"


def resolve(schema, root):
    """Follow a local $ref."""
    seen = 0
    while isinstance(schema, dict) and "$ref" in schema:
        seen += 1
        if seen > 10:
            raise ValueError("circular $ref")
        node = root
        for part in schema["$ref"].lstrip("#/").split("/"):
            node = node[part]
        schema = node
    return schema


def validate(value, schema, root, path="response"):
    """Return a list of human-readable mismatches."""
    schema = resolve(schema, root)
    errors = []
    expected = schema.get("type")

    checks = {
        "object": lambda v: isinstance(v, dict),
        "array": lambda v: isinstance(v, list),
        "string": lambda v: isinstance(v, str),
        "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
        "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
        "boolean": lambda v: isinstance(v, bool),
    }
    if expected in checks and not checks[expected](value):
        return [f"{path}: expected {expected}, got {type(value).__name__}"]

    if expected == "object" or (expected is None and isinstance(value, dict)):
        for name in schema.get("required", []):
            if name not in value:
                errors.append(
                    f"{path}.{name}: required by the spec but absent from the response"
                )
        for name, subschema in (schema.get("properties") or {}).items():
            if name in value and value[name] is not None:
                errors += validate(value[name], subschema, root, f"{path}.{name}")

    if expected == "array" and schema.get("items") and value:
        # One element is enough to catch a shape change.
        errors += validate(value[0], schema["items"], root, f"{path}[0]")

    return errors


def request(url, data=None, cookie=None):
    body = json.dumps(data).encode() if data is not None else None
    req = urllib.request.Request(url, data=body, method="POST" if data is not None else "GET")
    if body:
        req.add_header("Content-Type", "application/json")
    if cookie:
        req.add_header("Cookie", cookie)
    with urllib.request.urlopen(req, timeout=15) as resp:
        return resp.status, resp.read(), resp.headers.get("Set-Cookie", "")


def main():
    with open(SPEC_PATH) as fh:
        spec = yaml.safe_load(fh)

    try:
        _, _, set_cookie = request(
            f"{ADMIN_URL}/api/auth/login",
            {"username": USERNAME, "password": PASSWORD},
        )
    except urllib.error.URLError as exc:
        print(f"cannot reach the Admin API at {ADMIN_URL}: {exc}", file=sys.stderr)
        return 2

    cookie = set_cookie.split(";")[0] if set_cookie else ""
    if not cookie:
        print("login did not return a session cookie", file=sys.stderr)
        return 2

    base = spec["servers"][0]["url"].rstrip("/")
    if base.startswith("http"):
        base = "/" + base.split("/", 3)[3] if len(base.split("/", 3)) > 3 else ""

    failures, checked = [], 0
    for path, methods in spec["paths"].items():
        if "get" not in methods:
            continue
        url = f"{ADMIN_URL}{base}{path}"
        try:
            status, raw, _ = request(url, cookie=cookie)
        except urllib.error.HTTPError as exc:
            failures.append(f"GET {path}: HTTP {exc.code} (documented as 200)")
            continue
        except urllib.error.URLError as exc:
            failures.append(f"GET {path}: unreachable ({exc})")
            continue

        schema = (
            methods["get"].get("responses", {})
            .get("200", {}).get("content", {})
            .get("application/json", {}).get("schema")
        )
        if not schema:
            continue

        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            failures.append(f"GET {path}: response is not JSON ({exc})")
            continue

        errors = validate(payload, schema, spec, f"GET {path}")
        checked += 1
        failures.extend(errors)

    print("API contract check")
    print("==================")
    print(f"  endpoints validated : {checked}")
    for f in failures:
        print(f"  MISMATCH            : {f}")

    if failures:
        print(f"\n{len(failures)} contract mismatch(es) between docs/openapi.yaml and the running API.")
        print("Either the API changed and the spec was not updated, or the spec is wrong.")
        return 1

    print("\nThe running API matches the documented contract.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
