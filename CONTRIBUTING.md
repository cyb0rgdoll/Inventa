# Contributing to Inventa

Thanks for your interest in improving Inventa. This is a defensive asset
discovery tool; contributions should keep authorised, lawful use front and
centre.

## Ground rules

- **Never commit secrets.** No `.env`, API keys, tokens, private keys
  (`*.pem`, `*.key`), or real scan results. `.env.example` (placeholders only)
  is the sole environment file in Git.
- **Never commit private target data.** Real IPs, hostnames, `my_scope.txt`,
  `my_targets.txt`, and files under `results/` stay local.
- **User-controlled targets must never become command-line options.** Any code
  that passes a target to an external tool (nmap, masscan, arp-scan, external
  recon utilities) must first call `core.targets.validate_targets(...)` and use
  a `--` end-of-options marker when building the argument list.

## Development setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

External scanners (nmap, masscan, and the optional recon tools) are installed
separately — see `SETUP_TOOLS.md`.

## Before you open a pull request

1. Run the test suite:
   ```bash
   python3 -m pytest -q
   ```
2. Keep changes focused and described in the PR body.
3. If you change dependencies, update `requirements.in` and regenerate
   `requirements.txt` (see the header of that file).
4. Do not add third-party tool source to the repository. Reference the upstream
   project and add install steps to `SETUP_TOOLS.md` instead.

## Reporting security issues

See `SECURITY.md` — report privately, not in a public issue or PR.
