# Security Policy

## Supported Versions

Inventa is a prototype / early-stage tool. Security fixes are applied to the
latest `main` branch only. Older tags are not maintained.

| Version | Supported |
| ------- | --------- |
| latest `main` | ✅ |
| older tags | ❌ |

## Reporting a Vulnerability

Please report security issues **privately** — do not open a public issue,
pull request, or discussion for an unfixed vulnerability.

- Preferred: use GitHub's **"Report a vulnerability"** button under the
  repository's **Security** tab (Private Vulnerability Reporting).
- Include: affected file/function, a description of the impact, and a minimal
  reproduction if possible.

Please allow a reasonable period for a fix before any public disclosure. We
will acknowledge your report and keep you updated on remediation.

Do **not** include real credentials, API keys, private scan results, or
personal data in a report.

## Scope & Responsible Use

Inventa performs active network reconnaissance and scanning. It is intended
**only** for systems you own or are explicitly authorised to assess. Running it
against systems without permission may be illegal. See the "Authorized Use"
section of the README. Misuse of this tool is the sole responsibility of the
user, not the project or its contributors.

## Handling of Secrets

- Inventa reads API keys from a local `.env` file that is **git-ignored**.
- Never commit `.env`, private keys (`*.pem`, `*.key`), or scan results.
- If you believe a credential was ever committed, treat it as compromised:
  rotate/revoke it immediately and purge it from history before publishing.
