# Sentinel

A responsive code-security dashboard with browser-local source scanning, live npm dependency review, configurable release checks, finding remediation guidance, and JSON/text report exports.

## Run locally

Requires Python 3 for the static server and Node.js 20+ for tests. The app has no build dependencies.

```sh
npm run dev
```

Open http://localhost:4173. Choose **New scan**, select a project folder or files, or paste a source file. Include `package-lock.json` for exact installed dependency versions. The initial dashboard is clearly marked demo data; a real scan replaces it.

```sh
npm run check
npm test
```

## Checks and privacy

- Source patterns detect potential credentials, private keys, dynamic evaluation, HTML injection, disabled TLS verification, possible command injection, weak hashes, HTTP endpoints, and Python debug mode.
- npm lockfile v1/v2/v3 dependencies, including transitive versions, are checked against the OSV API. Exact versions in `package.json` are supported. Ranged versions remain unresolved.
- npm's `latest` metadata identifies potential updates; major versions may require migrations. Updates are recommendations and are not installed automatically.
- Source is processed in browser memory. Only package names and versions are sent to OSV and npm. Last 10 redacted reports and policy preferences are stored in this browser's localStorage. Clearing history removes those saved reports. Exports are user-managed files.
- Limits: 2,000 supported files, 2 MB per file, 30 MB total, 300 unique npm package/version pairs. Generated directories are skipped. Limits and failures produce warnings and prevent a passing result.

## Scope

This is a working first version, not a complete SAST platform. Source rules are heuristic and require contextual review. No application code is executed. Tests, type checking, full data-flow analysis, non-npm package scanning, GitHub connections, multi-user shared history, automatic fixes, and CI/deployment enforcement are not included. Passing the configured checks does not certify bug-free or secure code.

API availability and browser CORS support affect live dependency checks. An unavailable check is displayed as incomplete. Advisory pagination is followed; unresolved severity is flagged for review.

## Deployment

Static files live in `dist/`. `.openai/hosting.json` retains the private Site identity. The source repository is synchronized through the Sites workflow.
