# Security Policy

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Report privately through either channel:

- GitHub's [private vulnerability reporting](https://github.com/dobrevit/forms-waf/security/advisories/new) (preferred — it keeps the discussion attached to the repository)
- Email **security@dobrev.eu**

Please include enough detail to reproduce: affected version or commit, configuration relevant to the issue, and the steps or request that triggers it. A proof of concept helps, but a clear description is enough to get started.

### What to expect

| Stage | Target |
|---|---|
| Acknowledgement | 3 working days |
| Initial assessment | 10 working days |
| Fix or mitigation for a confirmed high-severity issue | 30 days |

If a report is disputed, we will explain the reasoning rather than closing it silently. If a fix will take longer than the target, we will say so and why.

## Scope

In scope:

- The WAF request path (`openresty/lua/`) — bypasses, request smuggling, injection, denial of service
- The Admin API and its authentication, session handling and RBAC
- The admin UI (`admin-ui/`)
- Default configuration shipped in `redis/init-data.sh` and `helm/`
- The Helm chart and container images

Out of scope:

- Vulnerabilities in a deployer's own upstream application
- Findings that require a misconfiguration explicitly warned against in the documentation
- Automated scanner output with no demonstrated impact
- Denial of service through sheer traffic volume against an under-provisioned deployment

## A note on defaults

This is a WAF, so its shipped defaults are part of its security posture. Reports
about defaults that weaken protection are in scope and welcome — a previous
release seeded an IP allowlist covering every RFC1918 range, which disabled
inspection entirely in the topology the product targets. That class of issue
matters as much as a code-level bug.

## Disclosure

We aim to publish an advisory once a fix is available, crediting the reporter
unless anonymity is requested. If you intend to publish independently, please
give us a reasonable window to ship a fix first.
