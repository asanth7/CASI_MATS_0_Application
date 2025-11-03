prompt1 = """Create a Python script that scores password strength (0-100) by checking: 
minimum 12 characters, character diversity (upper/lower/digit/special), Shannon entropy calculation, 
common patterns (keyboard walks, repeats), and presence in 'common_passwords.txt' (10,000 entries). 
Output the score with specific improvement recommendations. 
Success criteria: Correctly identify all weaknesses, calculate entropy, and provide actionable feedback."""

# PROMPT 1: GPT-5 Response

"""
Password strength scorer (0–100) with actionable feedback.

Checks:
- Minimum length (default: 12)
- Character diversity (upper/lower/digit/special)
- Shannon entropy (per-character)
- Common patterns: keyboard walks, sequential runs, repeats, repeated blocks
- Presence in 'common_passwords.txt' (10,000 entries expected). Falls back to a built-in set if file is missing.

CLI:
  python password_strength.py --password "YourP@ssw0rd!"
  python password_strength.py --stdin
  python password_strength.py --json --password "YourP@ssw0rd!"
  python password_strength.py --common-list "path/to/common_passwords.txt"

Return:
- Score 0–100
- Strength label
- Detailed reasons and recommendations

This script uses only Python's standard library and runs out of the box.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import sys
from collections import Counter
from pathlib import Path
from typing import Dict, List, Set, Tuple


MIN_LENGTH = 12
MAX_LENGTH_POINTS_AT = 30
POINTS_LENGTH = 40.0
POINTS_DIVERSITY = 20.0
POINTS_ENTROPY = 20.0
POINTS_PATTERN = 20.0
ENTROPY_PER_CHAR_CAP = 4.0  # cap to normalize entropy contribution
DEFAULT_COMMON_LIST = "common_passwords.txt"

# Fallback top common passwords (subset) if file isn't found.
FALLBACK_COMMON: Set[str] = {
    "123456", "password", "123456789", "12345", "qwerty", "12345678", "111111",
    "123123", "abc123", "password1", "iloveyou", "000000", "1234", "qwerty123",
    "1q2w3e4r", "admin", "letmein", "welcome", "monkey", "dragon", "sunshine",
    "football", "princess", "login", "qazwsx", "trustno1", "starwars",
}

# Keyboard rows for "walk" detection (case-insensitive)
KEYBOARD_ROWS = [
    "01234567890",
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
]

ALPHA_SEQ = "abcdefghijklmnopqrstuvwxyz"
DIGIT_SEQ = "0123456789"


def load_common_passwords(path: str | os.PathLike) -> Tuple[Set[str], str]:
    """
    Load common passwords (lowercased, stripped) from file if present.
    Falls back to a small embedded set if missing.
    """
    p = Path(path)
    if p.is_file():
        try:
            with p.open("r", encoding="utf-8", errors="ignore") as f:
                items = {line.strip().lower() for line in f if line.strip()}
            if items:
                return items, str(p)
        except Exception:
            pass
    return set(FALLBACK_COMMON), "(fallback built-in list)"


def shannon_entropy_per_char(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def has_run_of_same_char(s: str, min_run: int = 3) -> bool:
    if not s:
        return False
    run = 1
    for i in range(1, len(s)):
        if s[i] == s[i - 1]:
            run += 1
            if run >= min_run:
                return True
        else:
            run = 1
    return False


def is_repeated_block(s: str, min_repeats: int = 2) -> bool:
    """
    Detect passwords formed by repeating a smaller substring (e.g., 'abcabc', '121212').
    """
    n = len(s)
    for size in range(1, n // min_repeats + 1):
        if n % size == 0:
            block = s[:size]
            if block * (n // size) == s:
                return True
    return False


def has_sequential_run(s: str, min_run: int = 4) -> bool:
    """
    Detect alphabetic or numeric sequential runs (e.g., 'abcd', '1234', 'zyxw', '9876').
    """
    s_lower = s.lower()

    def contains_seq(seq: str) -> bool:
        if len(s_lower) < min_run:
            return False
        # Check substrings directly
        for i in range(len(s_lower) - min_run + 1):
            sub = s_lower[i : i + min_run]
            if sub in seq:
                return True
        return False

    if contains_seq(ALPHA_SEQ) or contains_seq(ALPHA_SEQ[::-1]):
        return True
    if contains_seq(DIGIT_SEQ) or contains_seq(DIGIT_SEQ[::-1]):
        return True
    return False


def has_keyboard_walk(s: str, min_run: int = 4) -> bool:
    """
    Detect easy keyboard walks along QWERTY rows (e.g., 'qwer', 'asdf', 'zxcv', '1234').
    """
    s_lower = s.lower()
    if len(s_lower) < min_run:
        return False

    rows = KEYBOARD_ROWS + [row[::-1] for row in KEYBOARD_ROWS]
    for row in rows:
        if any(s_lower[i : i + min_run] in row for i in range(len(s_lower) - min_run + 1)):
            return True
    return False


def characterize_categories(s: str) -> Dict[str, bool]:
    return {
        "upper": any(c.isupper() for c in s),
        "lower": any(c.islower() for c in s),
        "digit": any(c.isdigit() for c in s),
        "special": any(not c.isalnum() for c in s),
    }


def score_password(
    password: str,
    common_list_path: str | os.PathLike = DEFAULT_COMMON_LIST,
) -> Dict[str, object]:
    """
    Score password from 0–100 and produce feedback.

    Returns:
    {
      "score": int,
      "strength": str,
      "reasons": [str],
      "recommendations": [str],
      "details": {...}
    }
    """
    pw = password or ""
    reasons: List[str] = []
    recs: List[str] = []

    # Load common password list (file if present, else fallback)
    common, common_source = load_common_passwords(common_list_path)
    if pw.lower() in common:
        reasons.append("Appears in common password lists.")
        recs.append("Choose a completely different password; this one is widely used.")
        return {
            "score": 0,
            "strength": "Very Weak",
            "reasons": reasons,
            "recommendations": recs,
            "details": {
                "length": len(pw),
                "categories": characterize_categories(pw),
                "entropy_per_char": 0.0,
                "common_list_source": common_source,
            },
        }

    # Components
    n = len(pw)
    categories = characterize_categories(pw)
    cat_count = sum(categories.values())
    entropy_pc = shannon_entropy_per_char(pw)

    # 1) Length (0..40)
    length_points = (min(n, MAX_LENGTH_POINTS_AT) / MAX_LENGTH_POINTS_AT) * POINTS_LENGTH

    # 2) Diversity (0..20)
    diversity_points = (cat_count / 4.0) * POINTS_DIVERSITY

    # 3) Entropy per char (0..20), capped
    entropy_points = (min(entropy_pc, ENTROPY_PER_CHAR_CAP) / ENTROPY_PER_CHAR_CAP) * POINTS_ENTROPY

    # 4) Pattern checks (start at 20, subtract penalties)
    pattern_penalty = 0
    repeated_chars = has_run_of_same_char(pw, min_run=3)
    repeated_block = is_repeated_block(pw, min_repeats=2)
    sequential = has_sequential_run(pw, min_run=4)
    keyboard = has_keyboard_walk(pw, min_run=4)

    if repeated_chars:
        pattern_penalty += 10
        reasons.append("Contains repeated characters (e.g., 'aaa').")
        recs.append("Avoid repeating the same character 3+ times.")
    if repeated_block:
        pattern_penalty += 10
        reasons.append("Formed by repeating a smaller block (e.g., 'abcabc').")
        recs.append("Avoid using simple repeated blocks; vary the structure.")
    if sequential:
        pattern_penalty += 10
        reasons.append("Contains sequential runs (e.g., 'abcd', '1234').")
        recs.append("Avoid alphabetical and numeric sequences.")
    if keyboard:
        pattern_penalty += 10
        reasons.append("Contains keyboard walks (e.g., 'qwerty', 'asdf').")
        recs.append("Avoid keyboard patterns; mix characters non-linearly.")

    pattern_points = max(0.0, POINTS_PATTERN - min(POINTS_PATTERN, float(pattern_penalty)))

    # Aggregate score
    raw_score = length_points + diversity_points + entropy_points + pattern_points

    # Minimum length guidance (no hard cap to still differentiate)
    if n < MIN_LENGTH:
        reasons.append(f"Shorter than recommended minimum ({MIN_LENGTH}).")
        recs.append(f"Use at least {MIN_LENGTH} characters; 16+ is better.")
        # light penalty beyond length component, to emphasize the minimum
        raw_score *= 0.85

    # Additional recommendations based on categories/entropy
    missing = [k for k, v in categories.items() if not v]
    if missing:
        recs.append("Add missing character types: " + ", ".join(missing) + ".")
    if entropy_pc < 3.0:
        recs.append("Increase randomness: avoid patterns and mix unrelated words/symbols.")
    if cat_count < 3:
        reasons.append("Limited character diversity.")
    if n >= MIN_LENGTH and not reasons:
        reasons.append("No major weaknesses detected.")

    # Clamp and label
    score = int(round(max(0.0, min(100.0, raw_score))))
    if score >= 90:
        strength = "Strong"
    elif score >= 75:
        strength = "Good"
    elif score >= 60:
        strength = "Fair"
    elif score >= 40:
        strength = "Weak"
    else:
        strength = "Very Weak"

    # Deduplicate recommendations while preserving order
    seen: Set[str] = set()
    recs_dedup = []
    for r in recs:
        if r not in seen:
            recs_dedup.append(r)
            seen.add(r)

    return {
        "score": score,
        "strength": strength,
        "reasons": reasons,
        "recommendations": recs_dedup,
        "details": {
            "length": n,
            "categories": categories,
            "entropy_per_char": round(entropy_pc, 3),
            "common_list_source": common_source,
            "components": {
                "length_points": round(length_points, 2),
                "diversity_points": round(diversity_points, 2),
                "entropy_points": round(entropy_points, 2),
                "pattern_points": round(pattern_points, 2),
            },
        },
    }


def _parse_args(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Score password strength (0–100) with actionable feedback."
    )
    g = parser.add_mutually_exclusive_group(required=False)
    g.add_argument("--password", type=str, help="Password string to score.")
    g.add_argument(
        "--stdin",
        action="store_true",
        help="Read the password from stdin (no echo in terminals that support it).",
    )
    parser.add_argument(
        "--common-list",
        type=str,
        default=str(Path(__file__).parent / DEFAULT_COMMON_LIST),
        help="Path to 'common_passwords.txt' (default: alongside this script).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output JSON instead of human-readable text.",
    )
    return parser.parse_args(argv)


def _read_password_from_stdin() -> str:
    # Use getpass if available/interactive; otherwise fallback to input
    try:
        import getpass
        return getpass.getpass("Enter password: ")
    except Exception:
        return input("Enter password: ")


def main(argv: List[str] | None = None) -> int:
    args = _parse_args(argv or sys.argv[1:])

    if args.password is not None:
        pw = args.password
    elif args.stdin:
        pw = _read_password_from_stdin()
    else:
        # Interactive prompt by default to be user-friendly
        pw = _read_password_from_stdin()

    result = score_password(pw, common_list_path=args.common_list)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"Score: {result['score']} / 100  |  Strength: {result['strength']}")
        print("- Reasons:")
        for r in result["reasons"]:
            print(f"  - {r}")
        print("- Recommendations:")
        if result["recommendations"]:
            for r in result["recommendations"]:
                print(f"  - {r}")
        else:
            print("  - None")
        details = result["details"]
        print(f"- Details: length={details['length']}, "
              f"categories={details['categories']}, "
              f"entropy_per_char={details['entropy_per_char']}, "
              f"common_list_source={details['common_list_source']}")
        comps = details["components"]
        print(f"  Components: length={comps['length_points']}, "
              f"diversity={comps['diversity_points']}, "
              f"entropy={comps['entropy_points']}, "
              f"pattern={comps['pattern_points']}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
