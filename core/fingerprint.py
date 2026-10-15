"""S5: MX provider fingerprint table (offline data lookup, PRD 4 / 7.5)."""
from __future__ import annotations

from typing import Dict, List, Optional

# (substring, provider, is_gateway). Gateways accept all mail for their
# customers, so SMTP-level proof is meaningless behind them (E501).
_MX_TABLE = [
    ("mimecast", "Mimecast", True),
    ("pphosted", "Proofpoint", True),
    ("proofpoint", "Proofpoint", True),
    ("barracudanetworks", "Barracuda", True),
    ("messagelabs", "Symantec Cloud", True),
    ("mailprotect", "Bitdefender", True),
    ("irondport", "Cisco IronPort", True),
    ("ironport", "Cisco IronPort", True),
    ("forcepoint", "Forcepoint", True),
    ("sophos", "Sophos", True),
    ("trendmicro", "Trend Micro", True),
    ("mailcontrol", "Clearswift", True),
    ("synchronoss", "Synchronoss", True),
    ("google", "Google", False),
    ("googlemail", "Google", False),
    ("outlook", "Microsoft", False),
    ("protection.outlook", "Microsoft", False),
    ("yahoo", "Yahoo", False),
    ("yahoodns", "Yahoo", False),
    ("zoho", "Zoho", False),
    ("fastmail", "Fastmail", False),
    ("tutanota", "Tutanota", False),
    ("protonmail", "Proton", False),
    ("amazonses", "Amazon SES", False),
    ("sendgrid", "SendGrid", False),
    ("mailgun", "Mailgun", False),
    ("postmark", "Postmark", False),
]


def fingerprint(mx_hosts: List[str]) -> Dict[str, Optional[str]]:
    """Return {"provider": name_or_None, "gateway": name_or_None}."""
    for host in mx_hosts:
        h = host.lower().rstrip(".")
        for needle, provider, is_gateway in _MX_TABLE:
            if needle in h:
                return {"provider": provider,
                        "gateway": provider if is_gateway else None}
    return {"provider": None, "gateway": None}


def is_gateway(mx_hosts: List[str]) -> Optional[str]:
    return fingerprint(mx_hosts).get("gateway")
