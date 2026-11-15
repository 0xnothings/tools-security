# tools-security

A collection of zero-dependency Node.js security tools. Recon, web-app testing, credential hygiene, CVE intel, and audit helpers — every one runs with `node tools/<name>.js` and nothing but the Node standard library.

```bash
node tools/portscan.js 10.0.0.1 --ports 1-1024 --banner
node tools/headers.js https://example.com
node tools/secretscan.js ./src --json
```

Requirements: Node.js 18+ (uses `fetch`, `AbortController`, ESM). No `npm install`.

## How it works

```
_ lib.js      shared argv parser, table renderer, stdin/line helpers
tools/*.js    one file per tool, self-contained, --help on every one
index-tools.js   rescans tools/ and regenerates the catalogue below
smoke.js      runs every tool with --help and reports pass/fail
catalogue.json   machine-readable catalogue for scripting
```

Each tool declares its own metadata in a header comment:

```js
// @tool headers
// @desc Audit HTTP security headers and grade the response
// @usage node tools/headers.js https://example.com --json
// @tags security,web,audit
```

`node index-tools.js` reads those blocks, so adding a tool means adding one file and re-running the indexer. No registry to edit.

Every tool supports `--json` for machine consumption and prints a human table otherwise.

## Discipline

- Exit codes are meaningful: `0` clean, `1` findings/blocked, `2` CI gate tripped. Safe to use in pipelines.
- Read-only by default. Tools that change state (`backup`, `certgen`, `dotenvgen`, `dockerclean`) write to files you name and never touch a remote host.
- Rate and volume defaults are deliberately conservative. Raise them yourself if you own the target.
- These are diagnostic instruments. Point them at systems you own or are engaged to test.

## Catalogue

<!-- CATALOGUE:START -->

**35 tools**

| Tool | Description | Tags | Usage |
|---|---|---|---|
| [`cidr`](tools/cidr.js) | Expand, collapse, split and test IPv4/IPv6 networks; check whether an IP is inside a range | security, network, ipam | `node tools/cidr.js 10.0.0.0/24 --split 26 --json` |
| [`corscheck`](tools/corscheck.js) | Probe endpoints for CORS origin reflection, wildcard + credentials, and null-origin bypass | security, web, cors | `node tools/corscheck.js https://api.example.com --paths /,/api/user --json` |
| [`cvedb`](tools/cvedb.js) | Fetch CVE detail from NVD, exploit status from CISA KEV, and exploitation likelihood from EPSS | security, cve, intel | `node tools/cvedb.js CVE-2024-3400 CVE-2023-34362 --json` |
| [`dirb`](tools/dirb.js) | HTTP path/directory brute-forcer with automatic soft-404 detection and extension expansion | security, web, recon | `node tools/dirb.js https://example.com --wordlist paths.txt --ext php,html,bak --json` |
| [`dnsdump`](tools/dnsdump.js) | Dump A/AAAA/MX/NS/TXT/SOA/CNAME/CAA/SRV records; decode SPF+DMARC; optional PTR and zone-transfer test | security, dns, recon | `node tools/dnsdump.js example.com --json` |
| [`envleak`](tools/envleak.js) | Check hosts for exposed .env, .git, .svn, backup archives, phpinfo and CI config files | security, web, exposure | `node tools/envleak.js https://example.com --json` |
| [`gitleak`](tools/gitleak.js) | Walk `git log -p` and flag secrets that were committed (even if later removed) plus .env/.pem blobs | security, git, secrets | `node tools/gitleak.js ./repo --since 1.year --json` |
| [`graphqlscan`](tools/graphqlscan.js) | Detect live GraphQL endpoints, test introspection exposure, and list queries/mutations/subscriptions | security, api, graphql | `node tools/graphqlscan.js https://api.example.com/graphql --json` |
| [`hashid`](tools/hashid.js) | Identify hash type by format/prefix/length, or generate md5/sha1/sha256/sha512 for input | security, crypto, forensics | `node tools/hashid.js '$2y$10$abc...' --gen sha256 --text hello` |
| [`headers`](tools/headers.js) | Audit HTTP security headers (HSTS/CSP/XFO/Referrer-Policy...) and grade the response | security, web, audit | `node tools/headers.js https://example.com --json` |
| [`hostheader`](tools/hostheader.js) | Test Host / X-Forwarded-Host / X-Forwarded-For handling for cache poisoning and reset-poisoning risk | security, web, cachepoisoning | `node tools/hostheader.js https://example.com/reset --json` |
| [`jsenum`](tools/jsenum.js) | Extract API paths, hidden routes, domains, cloud buckets and secret-like strings from JS files | security, recon, js | `node tools/jsenum.js https://example.com/app.js --json` |
| [`jwtpeek`](tools/jwtpeek.js) | Decode JWT header/payload, flag alg=none, missing expiry, weak claims, and HMAC-crackable secrets | security, auth, jwt | `node tools/jwtpeek.js eyJhbGci... --wordlist secrets.txt` |
| [`openapiscan`](tools/openapiscan.js) | Fetch an OpenAPI spec and report auth coverage, sensitive endpoints, and unauthenticated operations | security, api, openapi | `node tools/openapiscan.js https://api.example.com/openapi.json --json` |
| [`paramfuzz`](tools/paramfuzz.js) | Probe a URL with candidate parameters to find hidden/reflected/reachable ones | security, web, fuzzing | `node tools/paramfuzz.js https://example.com/search --wordlist params.txt --reflect` |
| [`payloadx`](tools/payloadx.js) | Encode/decode payloads for filters: url, double-url, base64, hex, unicode, html-entity, sql-comment, leet | security, payload, encoding | `node tools/payloadx.js encode --in "<script>alert(1)</script>" --via url,unicode --json` |
| [`portscan`](tools/portscan.js) | Async TCP connect port scanner with service banner grab and JSON/CSV output | security, recon, network | `node tools/portscan.js 10.0.0.1 --ports 1-1024 --timeout 800 --banner` |
| [`probe`](tools/probe.js) | Probe many hosts at once: status, title, server, tech, TLS expiry, redirect chain — CSV/JSON out | security, recon, http | `node tools/probe.js hosts.txt --concurrency 50 --json` |
| [`ratelimit`](tools/ratelimit.js) | Sequentially probe a login/OTP endpoint to measure throttling, lockout and Retry-After behaviour | security, auth, ratelimit | `node tools/ratelimit.js https://site.com/api/login --field email --value you@x.com --attempts 15` |
| [`redirectcheck`](tools/redirectcheck.js) | Test URL parameters for open-redirect behaviour with a payload matrix and 3xx/Location evidence | security, web, redirect | `node tools/redirectcheck.js "https://site.com/login?next=1" --json` |
| [`robtex`](tools/robtex.js) | Pull RDAP registration data plus reverse-IP co-hosted domains for infrastructure mapping | security, osint, passivedns | `node tools/robtex.js example.com --json` |
| [`secretscan`](tools/secretscan.js) | Scan source trees for hardcoded secrets: AWS/GCP/Stripe/Slack keys, private keys, JWTs, DB URLs | security, secrets, audit | `node tools/secretscan.js ./src --json --exclude node_modules,.git` |
| [`sqli`](tools/sqli.js) | Parametric SQLi triage: error signatures, boolean differential, and time-delay probes with evidence | security, web, sqli | `node tools/sqli.js "https://site.com/item?id=1" --delay 5 --json` |
| [`ssrfprobe`](tools/ssrfprobe.js) | Inject internal/loopback URLs into params to spot SSRF: timing, error text and metadata echoes | security, web, ssrf | `node tools/ssrfprobe.js "https://site.com/fetch?url=1" --json` |
| [`statusfuzz`](tools/statusfuzz.js) | Build a route x method status matrix (no-auth vs bogus-token) to find open endpoints | security, api, accesscontrol | `node tools/statusfuzz.js https://api.example.com --paths-file routes.txt --json` |
| [`subdomain`](tools/subdomain.js) | Concurrent DNS subdomain brute-forcer with wildcard detection and JSON output | security, recon, dns | `node tools/subdomain.js example.com --wordlist words.txt --concurrency 100` |
| [`takeover`](tools/takeover.js) | Resolve subdomains, match response bodies against 40+ dangling-service fingerprints, report CNAME target | security, recon, takeover | `node tools/takeover.js subdomains.txt --concurrency 20 --json` |
| [`techstack`](tools/techstack.js) | Query the OSV.dev API for known vulnerabilities affecting a package+version across ecosystems | security, supplychain, cve | `node tools/techstack.js --pkg lodash --eco npm --ver 4.17.20 --json` |
| [`tlsinfo`](tools/tlsinfo.js) | Inspect a host's TLS certificate: subject, SANs, issuer, expiry countdown, protocol version | security, tls, recon | `node tools/tlsinfo.js example.com:443 --json` |
| [`vulncheck`](tools/vulncheck.js) | Static audit of a web project: dangerous sinks, missing auth checks, insecure randoms, upload handling | security, sast, audit | `node tools/vulncheck.js ./src --json` |
| [`wafdetect`](tools/wafdetect.js) | Identify WAF/CDN by headers, cookies and blocked-payload behaviour; report likely bypass posture | security, recon, waf | `node tools/wafdetect.js https://example.com --json` |
| [`wayback`](tools/wayback.js) | Harvest historical URLs for a domain from the Wayback CDX index, filtered and deduped by path | security, recon, osint | `node tools/wayback.js example.com --filter js,php,json --limit 5000 --json` |
| [`webfinger`](tools/webfinger.js) | Passive tech fingerprint: server, framework, CMS, JS libs, analytics, CDN, WAF | security, recon, fingerprint | `node tools/webfinger.js https://example.com --json` |
| [`wordgen`](tools/wordgen.js) | Generate context-aware wordlists (names/dates/company/leet/mutations) for authorised recovery testing | security, wordlist, osint | `node tools/wordgen.js --name "Budi Santoso" --nick budi --year 1998 --domain acme.id --out words.txt` |
| [`xssprobe`](tools/xssprobe.js) | Send a canary into parameters/headers and report reflected contexts that can break out | security, web, xss | `node tools/xssprobe.js "https://site.com/?q=1" --json` |

<!-- CATALOGUE:END -->

## Adding a tool

1. Drop `tools/<name>.js` with the header block above.
2. `import { args, get, num, flag, die, inputLines, table } from '../_lib.js';`
3. Handle `--help` first, then parse, then do the work, then print.
4. `node smoke.js && node index-tools.js`.

## License

MIT — Copyright (c) 2026 0xnothings
