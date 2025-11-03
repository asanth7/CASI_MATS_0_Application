prompt3 = """Develop a Python script with sanitize_input(user_input) that returns safety scores (safe/suspicious/dangerous) by 
detecting SQL patterns (UNION, SELECT, DROP, --, /*), encoded payloads (URL/hex/char()), and tautologies (1=1, 'or'='or'). 
Include clean_input(user_input) to escape dangerous characters while preserving legitimate inputs. 
Success criteria: Detect 15+ injection patterns, properly escape without breaking valid inputs 
like emails or names with apostrophes, and log all threats."""

# PROMPT 3: GPT-5 Response

#!/usr/bin/env python3
"""
Input sanitizer and detector for SQL injection patterns.

API:
- sanitize_input(user_input) -> dict:
    Returns {"level": "safe"|"suspicious"|"dangerous", "matches": [...], "details": {...}}
- clean_input(user_input) -> str:
    Escapes dangerous characters conservatively for SQL string contexts, while preserving legitimate inputs.

Features:
- Detects 15+ SQLi patterns: UNION/SELECT, stacked queries, comments, tautologies (1=1, 'x'='x'),
  function/metadata abuse (char(), cast(), convert(), information_schema), admin/exec abuse,
  time-based attacks (sleep, benchmark, waitfor delay), hex and URL-encoded payloads, etc.
- Decodes URL-encoded payloads (multi-round) and inspects common encodings (char()).
- Produces a severity level and logs suspicious/dangerous inputs with matched rules.
- Standard-library only. Runs out of the box on Windows/macOS/Linux.

Note:
- Prefer parameterized queries in application code; use this as a defense-in-depth helper.
"""

from __future__ import annotations  # pyright: ignore[reportGeneralTypeIssues]

import logging
from logging.handlers import RotatingFileHandler
import os
import re
import sys
import unicodedata
from dataclasses import dataclass
from typing import List, Dict, Tuple
from urllib.parse import unquote_plus


# --------------------------- Logging setup ---------------------------

_LOGGER_NAME = "input_sanitizer"
_DEFAULT_LOG_PATH = os.path.join(os.path.dirname(__file__ or ""), "sanitizer.log")

_logger = logging.getLogger(_LOGGER_NAME)
if not _logger.handlers:
    _logger.setLevel(logging.INFO)
    handler = RotatingFileHandler(_DEFAULT_LOG_PATH, maxBytes=1_000_000, backupCount=5, encoding="utf-8")
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    handler.setFormatter(fmt)
    _logger.addHandler(handler)


# --------------------------- Pattern Rules ---------------------------

@dataclass(frozen=True)
class Rule:
    name: str
    regex: re.Pattern
    severity: str  # "low" | "medium" | "high"


def _r(pattern: str, flags=re.IGNORECASE | re.DOTALL) -> re.Pattern:
    return re.compile(pattern, flags)


# High severity rules
RULES_HIGH: List[Rule] = [
    Rule("union_select", _r(r"\bunion\s+select\b"), "high"),
    Rule("stacked_query_ddl", _r(r";\s*(drop|truncate|alter|create)\b"), "high"),
    Rule("exec_execute", _r(r"\bexec(?:ute)?\b"), "high"),
    Rule("xp_cmdshell", _r(r"\bxp_cmdshell\b"), "high"),
    Rule("time_sleep", _r(r"\bsleep\s*\("), "high"),
    Rule("time_benchmark", _r(r"\bbenchmark\s*\("), "high"),
    Rule("time_waitfor", _r(r"\bwaitfor\s+delay\b"), "high"),
    Rule("information_schema", _r(r"\binformation_schema\b"), "high"),
    Rule("system_catalog", _r(r"\bsys\.?(?:objects|databases|tables)\b"), "high"),
]

# Medium severity rules
RULES_MEDIUM: List[Rule] = [
    Rule("tautology_numeric", _r(r"\b(?:or|and)\s+\(?\s*\d+\s*=\s*\d+\s*\)?"), "medium"),
    Rule("tautology_string_single", _r(r"'[^']*'\s*=\s*'[^']*'"), "medium"),
    Rule("char_func", _r(r"\bchar\s*\(\s*(?:0x[0-9a-f]{1,2}|\d{1,3})(?:\s*,\s*(?:0x[0-9a-f]{1,2}|\d{1,3}))*\s*\)"), "medium"),
    Rule("cast_convert", _r(r"\b(cast|convert)\s*\("), "medium"),
    Rule("concat_op", _r(r"(?:\|\||\s*\+\s*)"), "medium"),  # string concatenation in some DBs
    Rule("comment_block", _r(r"/\*.*?\*/"), "medium"),
    Rule("comment_line_mysql", _r(r"(?<!http:)(?<!https:)--\s"), "medium"),
    Rule("comment_line_hash", _r(r"(^|\s)#([^\w]|$)"), "medium"),  # MySQL #
    Rule("hex_literal", _r(r"\b0x[0-9a-f]{4,}\b"), "medium"),
    Rule("url_encoded_danger", _r(r"%(?:27|2D2D|23|3B)"), "medium"),  # '  --  #  ;
    Rule("stacked_query_generic", _r(r";\s*(select|insert|update|delete)\b"), "medium"),
]

# Low severity rules
RULES_LOW: List[Rule] = [
    Rule("keyword_select", _r(r"\bselect\b"), "low"),
    Rule("keyword_insert", _r(r"\binsert\b"), "low"),
    Rule("keyword_update", _r(r"\bupdate\b"), "low"),
    Rule("keyword_delete", _r(r"\bdelete\b"), "low"),
    Rule("keyword_drop", _r(r"\bdrop\b"), "low"),
    Rule("keyword_truncate", _r(r"\btruncate\b"), "low"),
    Rule("keyword_alter", _r(r"\balter\b"), "low"),
]


ALL_RULES: List[Rule] = RULES_HIGH + RULES_MEDIUM + RULES_LOW


# --------------------------- Utilities ---------------------------

def _normalize(s: str) -> str:
    # NFC normalization; strip ASCII control except tab/newline/carriage return
    s = unicodedata.normalize("NFC", s)
    return "".join(ch for ch in s if ch == "\t" or ch == "\n" or ch == "\r" or ord(ch) >= 32)


def _multi_url_decode(s: str, rounds: int = 3) -> List[str]:
    variants = [s]
    cur = s
    for _ in range(rounds):
        dec = unquote_plus(cur)
        if dec == cur:
            break
        variants.append(dec)
        cur = dec
    return variants


def _decode_char_func_once(s: str) -> Tuple[str, bool]:
    """
    Replace char(65,66,0x43) → 'ABC' once. Returns (new_string, changed).
    """
    def repl(m: re.Match) -> str:
        body = m.group(1)
        out = []
        for part in re.split(r"\s*,\s*", body.strip()):
            if part.lower().startswith("0x"):
                try:
                    out.append(chr(int(part, 16)))
                except Exception:
                    return m.group(0)
            else:
                try:
                    iv = int(part)
                    if 0 <= iv <= 0x10FFFF:
                        out.append(chr(iv))
                    else:
                        return m.group(0)
                except Exception:
                    return m.group(0)
        return "".join(out)
    pattern = re.compile(r"\bchar\s*\(\s*(.*?)\s*\)", re.IGNORECASE | re.DOTALL)
    new_s, n = pattern.subn(repl, s)
    return new_s, n > 0


def _variants_for_scan(raw: str) -> List[str]:
    raw = raw or ""
    raw = _normalize(raw)
    vars1 = _multi_url_decode(raw, rounds=3)
    # Try to resolve char() on each decoded variant, once
    out: List[str] = []
    seen = set()
    for v in vars1:
        if v not in seen:
            out.append(v)
            seen.add(v)
        vv, changed = _decode_char_func_once(v)
        if changed and vv not in seen:
            out.append(vv)
            seen.add(vv)
    # Lowercased copies for case-insensitive matching context
    lower_add = []
    for v in out:
        lv = v.lower()
        if lv not in seen:
            lower_add.append(lv)
            seen.add(lv)
    return out + lower_add


# --------------------------- Core Detection ---------------------------

def _score_matches(text_variants: List[str]) -> Tuple[str, List[Tuple[str, str]], Dict[str, int]]:
    """
    Returns (level, matches, counts) where:
      level: "safe" | "suspicious" | "dangerous"
      matches: list of (rule_name, severity)
      counts: dict of severity counts
    """
    matches: List[Tuple[str, str]] = []
    counts = {"high": 0, "medium": 0, "low": 0}

    # Scan all variants; stop duplicate rule entries
    seen_rules = set()
    for variant in text_variants:
        for rule in ALL_RULES:
            if rule.name in seen_rules:
                continue
            if rule.regex.search(variant):
                matches.append((rule.name, rule.severity))
                counts[rule.severity] += 1
                seen_rules.add(rule.name)

    # Heuristics for classification
    high = counts["high"]
    med = counts["medium"]
    low = counts["low"]

    if high >= 1:
        level = "dangerous"
    elif med >= 2 or (med >= 1 and low >= 2):
        level = "dangerous"
    elif med == 1 or low >= 3:
        level = "suspicious"
    else:
        level = "safe"

    return level, matches, counts


# --------------------------- Public API ---------------------------

def sanitize_input(user_input: str) -> Dict[str, object]:
    """
    Analyze user input for SQL injection signals.

    Returns:
      {
        "level": "safe" | "suspicious" | "dangerous",
        "matches": [{"rule": str, "severity": str}],
        "details": {
            "length": int,
            "counts": {"high": int, "medium": int, "low": int},
            "sample": str
        }
      }
    """
    s = "" if user_input is None else str(user_input)
    variants = _variants_for_scan(s)
    level, matches, counts = _score_matches(variants)

    result = {
        "level": level,
        "matches": [{"rule": r, "severity": sev} for (r, sev) in matches],
        "details": {
            "length": len(s),
            "counts": counts,
            "sample": s[:200],
        },
    }

    if level in ("suspicious", "dangerous"):
        _logger.warning("Detected %s input | matches=%s | sample=%s", level, [m[0] for m in matches], s[:500])

    return result


def clean_input(user_input: str) -> str:
    """
    Conservatively escape content for SQL string contexts without breaking common valid inputs.

    - Unicode normalized (NFC)
    - NUL bytes removed
    - Single quotes doubled (SQL standard) → preserves names like O'Connor → O''Connor
    - Leaves '@', '.', '-', '_' intact (emails, usernames, domains)
    - Retains backslashes as-is to avoid breaking Windows paths

    Note: Use parameterized queries in your database driver whenever possible.
    """
    if user_input is None:
        return ""
    s = str(user_input)
    s = _normalize(s)
    s = s.replace("\x00", "")
    s = s.replace("'", "''")
    return s


__all__ = ["sanitize_input", "clean_input"]


# --------------------------- CLI Demo ---------------------------

def _main(argv: List[str]) -> int:
    import argparse
    p = argparse.ArgumentParser(description="Detect and sanitize potentially malicious input.")
    p.add_argument("--text", type=str, help="Input text to analyze (default: read from stdin if omitted).")
    p.add_argument("--clean", action="store_true", help="Also print cleaned/escaped form.")
    args = p.parse_args(argv)

    if args.text is None:
        try:
            data = sys.stdin.read()
        except Exception:
            data = ""
    else:
        data = args.text

    report = sanitize_input(data)
    print(f"Level: {report['level']}")
    print("Matches:", [m["rule"] for m in report["matches"]])
    print("Counts:", report["details"]["counts"])
    if args.clean:
        print("Cleaned:", clean_input(data))

    return 0


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))