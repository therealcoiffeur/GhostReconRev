from __future__ import annotations

"""Deterministic scope evaluation for discovered hostnames/domains."""

import re
from dataclasses import dataclass

_HOST_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def canonicalize_hostname(value: str) -> str:
    """Normalize hostnames to a canonical lowercase IDNA-safe form."""

    # Remove accidental surrounding whitespace/trailing dots.
    cleaned = value.strip().strip(".").lower()
    if not cleaned:
        raise ValueError("hostname is empty")
    if len(cleaned) > 253:
        raise ValueError("hostname too long")
    # Validate label presence and per-label length limits before IDNA conversion.
    labels = cleaned.split(".")
    if any(not label or len(label) > 63 for label in labels):
        raise ValueError("invalid hostname label")
    # Convert unicode domains into deterministic ASCII representation.
    ascii_name = cleaned.encode("idna").decode("ascii")
    if len(ascii_name) > 253:
        raise ValueError("hostname too long")
    ascii_labels = ascii_name.split(".")
    if any(not label or len(label) > 63 or not _HOST_LABEL_RE.fullmatch(label) for label in ascii_labels):
        raise ValueError("invalid hostname characters")
    return ascii_name


@dataclass(slots=True)
class ScopeDecision:
    """Final decision for a candidate hostname against scope rules."""

    allowed: bool
    reason: str


@dataclass(slots=True)
class ScopeRules:
    """Compiled policy rules used by evaluate_scope()."""

    allow_exact: set[str]
    allow_suffixes: set[str]
    deny_exact: set[str]
    deny_suffixes: set[str]
    regex_deny: list[re.Pattern[str]]

    @classmethod
    def from_lists(
        cls,
        allow_exact: list[str],
        allow_suffixes: list[str],
        deny_exact: list[str],
        deny_suffixes: list[str],
        regex_deny: list[str],
    ) -> "ScopeRules":
        """Compile raw policy lists into canonical, runtime-efficient sets/regex."""
        return cls(
            allow_exact={canonicalize_hostname(x) for x in allow_exact if x.strip()},
            allow_suffixes={canonicalize_hostname(x) for x in allow_suffixes if x.strip()},
            deny_exact={canonicalize_hostname(x) for x in deny_exact if x.strip()},
            deny_suffixes={canonicalize_hostname(x) for x in deny_suffixes if x.strip()},
            regex_deny=[re.compile(x, flags=re.IGNORECASE) for x in regex_deny if x.strip()],
        )


def _matches_suffix(value: str, suffixes: set[str]) -> bool:
    """Return True when hostname equals suffix or is a subdomain of it."""
    for suffix in suffixes:
        if value == suffix or value.endswith("." + suffix):
            return True
    return False


def evaluate_scope(hostname: str, rules: ScopeRules) -> ScopeDecision:
    """Apply deny-first deterministic scope policy to a candidate hostname."""

    candidate = canonicalize_hostname(hostname)

    # Deny lists always have priority over all allow rules.
    if candidate in rules.deny_exact:
        return ScopeDecision(False, "deny_exact")
    if _matches_suffix(candidate, rules.deny_suffixes):
        return ScopeDecision(False, "deny_suffix")
    if any(p.search(candidate) for p in rules.regex_deny):
        return ScopeDecision(False, "regex_deny")
    # Allow rules apply only after deny checks pass.
    if candidate in rules.allow_exact:
        return ScopeDecision(True, "allow_exact")
    if _matches_suffix(candidate, rules.allow_suffixes):
        return ScopeDecision(True, "allow_suffix")

    # Safe default: block anything not explicitly allowed.
    return ScopeDecision(False, "default_deny")
