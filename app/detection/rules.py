"""
Explainable detection rules for SSH-HoneyGuard (Phase 6).

Kept as a standalone data module — deliberately NOT mixed into engine.py —
so the rule table itself is the documentation. Every severity decision the
detection engine makes traces back to a single line in this file, which is
the point of "explainable, rule-based" (Phase 0 Section 6, Explainability
NFR): no hidden weights, no learned thresholds, no ML.

Categories not listed in SUSPICIOUS_CATEGORIES (recon, network,
file_activity, unclassified, empty) are still logged and classified by
app.fake_shell, but do NOT generate a security_alert on their own — this
keeps alert volume meaningful (routine recon commands are extremely common
and alerting on every one would drown out real signal). Recon activity is
still visible for triage via command_entered logs; it just isn't paged.
"""

from __future__ import annotations

# Category -> severity, for command-based alerts (Phase 6 requirement A).
# Only categories present in this dict generate an immediate alert when a
# matching command is entered.
CATEGORY_SEVERITY: dict[str, str] = {
    "credential": "HIGH",
    "destructive": "HIGH",
    "privesc": "HIGH",
    "persistence": "HIGH",
    "download": "MEDIUM",
}

SUSPICIOUS_CATEGORIES: frozenset[str] = frozenset(CATEGORY_SEVERITY.keys())

# Severity for the two cross-event alert types (Phase 6 requirements B & C).
BRUTE_FORCE_SEVERITY = "HIGH"
MULTI_STAGE_SEVERITY = "HIGH"

# Human-readable reason strings, so every alert's "reason" field is
# consistent and traceable to this file rather than composed ad hoc at each
# call site.
CATEGORY_ALERT_REASONS: dict[str, str] = {
    "credential": "Command targeting credential material (e.g. /etc/shadow, passwd) was entered.",
    "destructive": "Command with destructive potential (e.g. rm -rf, mkfs, dd) was entered.",
    "privesc": "Command attempting privilege escalation (e.g. sudo, chmod +s) was entered.",
    "persistence": "Command attempting to establish persistence (e.g. crontab, systemctl) was entered.",
    "download": "Command attempting to download remote content (e.g. curl, wget) was entered.",
}
