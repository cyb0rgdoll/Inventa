"""
Target validation (single source of truth).

Every module that hands a user-supplied target to an external command
(nmap, masscan, arp-scan, external recon utilities) MUST route it through
`validate_targets` first. The security rule is:

    User-controlled target data must never become command-line options.

A value beginning with "-" is rejected outright so it can never be parsed as
a flag by the downstream tool (CWE-88, argument injection). Callers should
additionally place a literal "--" end-of-options marker before the targets
when building the argument list, as defence in depth.
"""

import ipaddress
import re
from typing import List, Sequence

# RFC 1123 hostname (letters, digits, hyphens; labels 1-63 chars).
_HOSTNAME_RE = re.compile(
    r"^[a-zA-Z0-9]"
    r"([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(\.[a-zA-Z0-9]"
    r"([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
)


def validate_targets(targets: Sequence[str]) -> List[str]:
    """Return the targets unchanged if every one is a plain IP, CIDR, or
    hostname. Raise ValueError on the first value that is not, or that could be
    interpreted as a command-line option.
    """
    validated: List[str] = []

    for target in targets:
        target = target.strip()

        if not target or target.startswith("-"):
            raise ValueError(f"Unsafe target (empty or option-like): {target!r}")

        try:
            ipaddress.ip_address(target)
            validated.append(target)
            continue
        except ValueError:
            pass

        try:
            ipaddress.ip_network(target, strict=False)
            validated.append(target)
            continue
        except ValueError:
            pass

        if _HOSTNAME_RE.fullmatch(target):
            validated.append(target)
            continue

        raise ValueError(
            f"Invalid target; expected IP, CIDR, or hostname: {target!r}"
        )

    return validated
