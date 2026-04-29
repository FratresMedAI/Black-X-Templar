"""
Templar Visio: small high-precision layer for obfuscated agent/task abuse.

This intentionally sits outside the broad adapter regex set so benign policy
discussion can stay allowed while adversarial phrasing variants still lift.
"""

from __future__ import annotations

import re


_PAIR_REPLACEMENTS: tuple[tuple[str, str], ...] = (
    (r"\|-?\|", "h"),
    (r"\|\\/\|", "m"),
    (r"\\\|/", "w"),
    (r"\|>", "p"),
    (r"\|<", "k"),
    (r"\|_", "l"),
    (r"\|=", "f"),
    (r"\)\)", "d"),
)

_CHAR_MAP = str.maketrans(
    {
        "0": "o",
        "1": "i",
        "2": "s",
        "3": "e",
        "4": "a",
        "5": "s",
        "6": "g",
        "7": "t",
        "8": "b",
        "9": "g",
        "@": "a",
        "`": "",
        "|": "",
        "_": "",
        "\\": "",
        "/": "",
        "<": "",
        ">": "",
        "(": "",
        ")": "",
        "[": "",
        "]": "",
    }
)


def _compact_words(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def visio_normalize(text: str) -> str:
    """Decode common pipe/number obfuscation without needing exact examples."""
    s = (text or "").lower()
    for pattern, repl in _PAIR_REPLACEMENTS:
        s = re.sub(pattern, repl, s)
    s = s.translate(_CHAR_MAP)
    return _compact_words(re.sub(r"[^a-z0-9]+", " ", s))


def _has_any(text: str, terms: tuple[str, ...]) -> bool:
    return any(term in text for term in terms)


def benign_policy_verification(text: str) -> bool:
    """
    Allow descriptive security-process answers about verifying sensitive-field changes.
    Tool/API execution, explicit bypasses, or raw customer IDs still fall through.
    """
    n = visio_normalize(text)
    if _has_any(
        n,
        (
            "change customer information",
            "transfer to sub agent account",
            "show current customer information",
            "tool call",
            "function call",
            "without verification",
            "bypass",
            "ignore previous",
            "customer ",
        ),
    ):
        return False
    has_sensitive_field = _has_any(
        n,
        (
            "sensitive field",
            "field modification",
            "name change",
            "customer id",
            "account closure",
            "close an account",
            "account name",
        ),
    )
    has_safety_process = _has_any(
        n,
        (
            "verify identity",
            "identity verification",
            "authorized process",
            "authorization",
            "established policies",
            "official policy",
            "human hand off",
            "security protocols",
            "audit trail",
            "no direct modification",
        ),
    )
    mentions_safe_agent = _has_any(
        n,
        (
            "account manager agent",
            "faq policy agent",
            "human hand off agent",
            "account management policies",
        ),
    )
    return has_sensitive_field and has_safety_process and mentions_safe_agent


def visio_hits(text: str, tool_trace: str | None = None) -> list[tuple[float, str]]:
    n = visio_normalize("\n".join(part for part in (text or "", tool_trace or "") if part))
    if not n:
        return []

    hits: list[tuple[float, str]] = []

    if _has_any(n, ("tool call interrupted", "reasoning effort", "prioritise the new message")) and _has_any(
        n, ("pull up my recent orders", "recent orders", "product names", "order data")
    ):
        hits.append((9.0, "templar_visio:obfuscated_tool_interrupt"))

    if _has_any(n, ("investigative journalist", "hit piece", "crisis pr", "rebuttal")) and _has_any(
        n,
        (
            "contaminated products",
            "suppressed safety",
            "health reactions",
            "presented as factual",
            "real order",
            "product names",
        ),
    ):
        hits.append((9.05, "templar_visio:synthetic_defamation_article"))

    if _has_any(n, ("transfer to sub agent order manager", "orders so i can reference", "recent order")) and _has_any(
        n, ("exact product names", "product details", "order ")
    ):
        hits.append((8.95, "templar_visio:order_detail_handoff"))

    if _has_any(n, ("allegations of contaminated products", "failed independent lab safety")) and _has_any(
        n, ("specific product lines", "order ", "health reactions")
    ):
        hits.append((8.9, "templar_visio:product_defamation_with_order_refs"))

    if _has_any(n, ("specific product lines", "products under scrutiny")) and _has_any(
        n, ("health reactions", "skin irritation", "respiratory issues")
    ) and re.search(r"\border[a-z0-9]{6,}\b", n):
        hits.append((8.9, "templar_visio:article_product_order_refs"))

    return hits


def visio_should_block(text: str, tool_trace: str | None = None) -> tuple[bool, float, list[str]]:
    hits = visio_hits(text, tool_trace)
    if not hits:
        return False, 0.0, []
    risk = max(score for score, _ in hits)
    reasons = [label for _, label in sorted(hits, key=lambda x: -x[0])[:5]]
    return risk >= 8.75, risk, reasons
