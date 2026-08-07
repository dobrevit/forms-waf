#!/usr/bin/env python3
"""
Guard the seam between openresty/conf/nginx.conf and the Helm chart's own copy
of it in templates/openresty-configmap.yaml.

Why this exists
---------------
The chart does not mount the image's nginx.conf; it ships its own in a
ConfigMap. So every `env NAME;` declaration and every `lua_shared_dict` has to
be added in two places, and forgetting the second one fails silently and only
on Kubernetes:

  * A missing `env NAME;` makes os.getenv("NAME") return nil inside Lua, so a
    value an operator sets in values.yaml is quietly ignored. HAPROXY_TIMEOUT
    was in exactly this state -- set by the deployment, undeclared in the
    ConfigMap, therefore dead.

  * A missing lua_shared_dict makes ngx.shared.NAME nil. Modules guard on that
    and return early, so the feature does not crash, it just never does
    anything. Shadow mode shipped in this state.

Both are the "silently inert" class this codebase has been bitten by before,
and neither shows up in the compose stack, which is where testing happens.

Exit codes: 0 in sync, 1 drifted.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NGINX_CONF = ROOT / "openresty" / "conf" / "nginx.conf"
HELM_CONFIGMAP = ROOT / "helm" / "forms-waf" / "templates" / "openresty-configmap.yaml"

ENV_RE = re.compile(r"^\s*env\s+([A-Z_][A-Z0-9_]*)\s*;", re.MULTILINE)
DICT_RE = re.compile(r"^\s*lua_shared_dict\s+([a-z_][a-z0-9_]*)\s", re.MULTILINE)


def extract(path, pattern):
    if not path.exists():
        print(f"error: {path} not found", file=sys.stderr)
        sys.exit(1)
    return set(pattern.findall(path.read_text()))


def report(kind, missing_in_helm, missing_in_conf, consequence):
    problems = 0
    if missing_in_helm:
        problems += len(missing_in_helm)
        print(f"\n  {kind} declared in nginx.conf but MISSING from the Helm ConfigMap:")
        for name in sorted(missing_in_helm):
            print(f"    - {name}")
        print(f"    {consequence}")
        print(f"    Fix: add it to {HELM_CONFIGMAP.relative_to(ROOT)}")
    if missing_in_conf:
        problems += len(missing_in_conf)
        print(f"\n  {kind} in the Helm ConfigMap but MISSING from nginx.conf:")
        for name in sorted(missing_in_conf):
            print(f"    - {name}")
        print("    The compose stack and the image will not have it.")
        print(f"    Fix: add it to {NGINX_CONF.relative_to(ROOT)}")
    return problems


def main():
    conf_env = extract(NGINX_CONF, ENV_RE)
    helm_env = extract(HELM_CONFIGMAP, ENV_RE)
    conf_dicts = extract(NGINX_CONF, DICT_RE)
    helm_dicts = extract(HELM_CONFIGMAP, DICT_RE)

    print("Helm / nginx.conf drift check")
    print("=" * 30)
    print(f"  env declarations : {len(conf_env)} in nginx.conf, {len(helm_env)} in the chart")
    print(f"  shared dicts     : {len(conf_dicts)} in nginx.conf, {len(helm_dicts)} in the chart")

    problems = 0
    problems += report(
        "env declarations",
        conf_env - helm_env,
        helm_env - conf_env,
        "Consequence: os.getenv() returns nil in Lua on Kubernetes, so the setting is ignored.",
    )
    problems += report(
        "lua_shared_dict",
        conf_dicts - helm_dicts,
        helm_dicts - conf_dicts,
        "Consequence: ngx.shared.<name> is nil on Kubernetes, so the feature is silently inert.",
    )

    print()
    if problems:
        print(f"FAILED: {problems} declaration(s) out of sync.")
        return 1
    print("The chart's nginx.conf matches the image's.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
