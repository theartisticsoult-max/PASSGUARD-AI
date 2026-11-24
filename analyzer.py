"""
PASSGUARD AI - Password Analysis Engine
Provides intelligent password strength evaluation, pattern detection,
entropy calculation, vulnerability identification, and actionable security reporting.
"""

from dataclasses import dataclass, field
import math
import os
import re
from typing import Dict, List, Set, Tuple


@dataclass
class Criterion:
    """Represents an individual security rule evaluation."""
    name: str
    passed: bool
    description: str
    category: str  # 'Length', 'Complexity', 'Pattern', 'Dictionary'


@dataclass
class Vulnerability:
    """Represents an identified security flaw or pattern."""
    title: str
    severity: str  # 'Critical', 'High', 'Medium', 'Low'
    description: str
    suggestion: str


@dataclass
class AnalysisResult:
    """Comprehensive result of password security analysis."""
    password: str
    length: int
    score: int
    strength_level: str  # 'Weak', 'Fair', 'Good', 'Strong', 'Very Strong'
    strength_color: str
    entropy_bits: float
    pool_size: int
    has_lower: bool
    has_upper: bool
    has_digits: bool
    has_symbols: bool
    criteria: List[Criterion]
    vulnerabilities: List[Vulnerability]
    suggestions: List[str]
    estimated_crack_time_offline: str
    estimated_crack_time_online: str
    score_breakdown: Dict[str, int]
    is_common: bool
    detected_patterns: List[str] = field(default_factory=list)


# Cached common passwords set
_COMMON_PASSWORDS: Set[str] = set()

# Common keyboard walking patterns (forward & backward, 3+ chars)
_KEYBOARD_PATTERNS = [
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
    "1234567890",
    "0987654321",
    "qazwsxedcrfv",
    "poiuytrewq",
    "lkjhgfdsa",
    "mnbvcxz",
]

# Simple leetspeak substitution map for normalization
_LEET_MAP = {
    '@': 'a', '4': 'a',
    '8': 'b',
    '3': 'e',
    '1': 'i', '!': 'i', '|': 'i',
    '0': 'o',
    '5': 's', '$': 's',
    '7': 't', '+': 't',
}


def load_common_passwords(file_path: str = None) -> Set[str]:
    """Load common passwords from local file into memory."""
    global _COMMON_PASSWORDS
    if _COMMON_PASSWORDS:
        return _COMMON_PASSWORDS

    if file_path is None:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        file_path = os.path.join(base_dir, "common_passwords.txt")

    if os.path.exists(file_path):
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                _COMMON_PASSWORDS = {line.strip().lower() for line in f if line.strip() and not line.startswith("#")}
        except Exception:
            _COMMON_PASSWORDS = set()
    return _COMMON_PASSWORDS


def normalize_leetspeak(text: str) -> str:
    """Normalize common leetspeak substitutions to lowercase plain text."""
    lowered = text.lower()
    for char, replacement in _LEET_MAP.items():
        lowered = lowered.replace(char, replacement)
    return lowered


def detect_repeated_characters(password: str) -> List[str]:
    """Detect sequences of 3 or more identical consecutive characters."""
    findings = []
    # If the password is short or empty
    if len(password) < 3:
        return findings

    # Whole string is just one repeated character
    if len(set(password)) == 1:
        return [password[:min(len(password), 10)]]

    for match in re.finditer(r"(.)\1{2,}", password, re.IGNORECASE):
        findings.append(match.group(0))
    return findings


def detect_sequential_patterns(password: str) -> List[str]:
    """Detect alphabetical or numerical sequences of 3 or more characters."""
    findings = []
    lowered = password.lower()

    if len(lowered) < 3:
        return findings

    # Cap loop length to 500 chars to prevent lag on huge inputs
    search_len = min(len(lowered), 500)

    # Alphabetical sequence checks (forward & reverse)
    for i in range(search_len - 2):
        chunk = lowered[i:i+3]
        if chunk.isalpha() and all(ord(c) < 128 for c in chunk):
            ords = [ord(c) for c in chunk]
            if (ords[1] == ords[0] + 1 and ords[2] == ords[1] + 1) or \
               (ords[1] == ords[0] - 1 and ords[2] == ords[1] - 1):
                findings.append(chunk)

    # Numerical sequence checks (forward & reverse)
    for i in range(min(len(password), 500) - 2):
        chunk = password[i:i+3]
        if chunk.isdigit():
            ords = [ord(c) for c in chunk]
            if (ords[1] == ords[0] + 1 and ords[2] == ords[1] + 1) or \
               (ords[1] == ords[0] - 1 and ords[2] == ords[1] - 1):
                findings.append(chunk)

    return list(dict.fromkeys(findings))


def detect_keyboard_walks(password: str) -> List[str]:
    """Detect keyboard walking sequences like qwerty, asdf, etc."""
    lowered = password.lower()
    findings = []
    for pattern in _KEYBOARD_PATTERNS:
        for length in range(4, 7):
            for i in range(len(pattern) - length + 1):
                sub = pattern[i:i+length]
                if sub in lowered:
                    findings.append(sub)
    return list(dict.fromkeys(findings))


def detect_date_or_year(password: str) -> List[str]:
    """Detect common 4-digit years (1920-2035) or simple dates."""
    findings = []
    # 4-digit years
    years = re.findall(r"(?:19[2-9]\d|20[0-3]\d)", password)
    findings.extend(years)
    # MMDDYYYY or DDMMYYYY
    dates = re.findall(r"(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])(?:19|20)\d{2}", password)
    findings.extend(dates)
    return list(dict.fromkeys(findings))


def calculate_entropy(password: str) -> Tuple[float, int]:
    """
    Calculate effective information entropy in bits.
    Uses Shannon character diversity to prevent misleadingly high entropy
    on repeated or patterned characters (e.g. 'aaaaaaaaaaaaaaaa').
    Formula:
      H_effective = log2(R) + (L - 1) * (H_char / log2(L)) * log2(R)
    """
    length = len(password)
    if length == 0:
        return 0.0, 0

    pool_size = 0
    # Unicode-aware character class detection
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digits = any(c.isdigit() for c in password)
    has_symbols = any(not c.isalnum() for c in password)
    has_unicode_extended = any(ord(c) > 127 for c in password)

    if has_lower:
        pool_size += 26
    if has_upper:
        pool_size += 26
    if has_digits:
        pool_size += 10
    if has_symbols:
        pool_size += 33
    if has_unicode_extended:
        unique_unicode = len(set(c for c in password if ord(c) > 127))
        pool_size += max(15, unique_unicode * 5)

    if pool_size == 0:
        return 0.0, 0

    unique_chars = len(set(password))

    # Single character repeated (e.g. 'aaaaaaaa') has only the entropy of picking that 1 character
    if unique_chars == 1:
        single_char_entropy = math.log2(pool_size)
        return round(single_char_entropy, 1), pool_size

    # Shannon character entropy: H_char = - sum(p_i * log2(p_i))
    char_counts = {}
    for c in password:
        char_counts[c] = char_counts.get(c, 0) + 1

    shannon_char = 0.0
    for count in char_counts.values():
        p = count / length
        shannon_char -= p * math.log2(p)

    # Maximum possible Shannon character entropy for length L is log2(L)
    max_shannon = math.log2(length) if length > 1 else 1.0
    diversity_ratio = min(1.0, shannon_char / max_shannon) if max_shannon > 0 else 0.0

    # Effective entropy scales by the diversity ratio
    log2_r = math.log2(pool_size)
    effective_entropy = log2_r + (length - 1) * diversity_ratio * log2_r

    return round(effective_entropy, 1), pool_size


def format_time_duration(seconds: float) -> str:
    """Format time duration into an intuitive, readable string."""
    if seconds < 0.001:
        return "Instant (< 1 ms)"
    elif seconds < 1:
        return "Instant (< 1 sec)"
    elif seconds < 60:
        return f"{int(seconds)} seconds"
    elif seconds < 3600:
        minutes = int(seconds / 60)
        return f"{minutes} minute{'s' if minutes > 1 else ''}"
    elif seconds < 86400:
        hours = int(seconds / 3600)
        return f"{hours} hour{'s' if hours > 1 else ''}"
    elif seconds < 31536000:
        days = int(seconds / 86400)
        return f"{days} day{'s' if days > 1 else ''}"
    elif seconds < 31536000 * 100:
        years = int(seconds / 31536000)
        return f"{years} year{'s' if years > 1 else ''}"
    elif seconds < 31536000 * 1000000:
        centuries = int(seconds / (31536000 * 100))
        return f"{centuries:,} centuries"
    else:
        return "Millions of years"


def estimate_crack_times(
    entropy_bits: float,
    pool_size: int,
    length: int,
    is_compromised: bool,
    has_heavy_patterns: bool = False
) -> Tuple[str, str]:
    """
    Estimate cracking time for offline hash cracking and online attempts.
    Note: Labelled strictly as illustrative heuristics based on theoretical brute force.
    """
    if is_compromised or length == 0 or has_heavy_patterns:
        return "Instant (< 1 ms)", "Instant (< 1 sec)"

    # Cap safe entropy to 90 bits to prevent float OverflowError on long inputs (1000+ chars)
    # 2^90 combinations takes billions of years on any cluster.
    safe_entropy = min(entropy_bits, 90.0)
    combinations = 2.0 ** safe_entropy

    # Offline attacker: High-performance GPU cluster (e.g. 10 billion guesses/sec on fast hashes)
    offline_rate = 1e10
    offline_seconds = combinations / (offline_rate * 2.0)  # Average 50% search space

    # Online attacker: Rate-limited authentication endpoint (e.g. 1,000 guesses/sec)
    online_rate = 1000.0
    online_seconds = combinations / (online_rate * 2.0)

    return format_time_duration(offline_seconds), format_time_duration(online_seconds)


def analyze_password(password: str) -> AnalysisResult:
    """
    Performs full security analysis on a given password.
    Returns an AnalysisResult dataclass.
    """
    if not password:
        return AnalysisResult(
            password="",
            length=0,
            score=0,
            strength_level="Weak",
            strength_color="#ef4444",
            entropy_bits=0.0,
            pool_size=0,
            has_lower=False,
            has_upper=False,
            has_digits=False,
            has_symbols=False,
            criteria=[
                Criterion("Length >= 8", False, "At least 8 characters", "Length"),
                Criterion("Length >= 12", False, "At least 12 characters for strong security", "Length"),
                Criterion("Lowercase letter", False, "Contains lowercase characters", "Complexity"),
                Criterion("Uppercase letter", False, "Contains uppercase characters", "Complexity"),
                Criterion("Number (0-9)", False, "Contains digits", "Complexity"),
                Criterion("Special character", False, "Contains symbols or punctuation", "Complexity"),
                Criterion("No common dictionary match", True, "Not in common breached lists", "Dictionary"),
                Criterion("No sequential patterns", True, "No sequences like 123 or abc", "Pattern"),
                Criterion("No repeated characters", True, "No 3+ repeated characters", "Pattern"),
            ],
            vulnerabilities=[
                Vulnerability("No Password Provided", "Critical", "The password input is currently empty.", "Type or generate a password to begin analysis.")
            ],
            suggestions=["Enter a password with at least 12 characters combining letters, numbers, and symbols."],
            estimated_crack_time_offline="N/A",
            estimated_crack_time_online="N/A",
            score_breakdown={"Length Points": 0, "Character Variety": 0, "Entropy Bonus": 0, "Pattern Penalties": 0},
            is_common=False,
            detected_patterns=[]
        )

    common_passwords = load_common_passwords()
    length = len(password)
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digits = any(c.isdigit() for c in password)
    has_symbols = any(not c.isalnum() for c in password)

    # Pattern Detections
    normalized = normalize_leetspeak(password)
    lowered = password.lower()

    is_common = (lowered in common_passwords) or (normalized in common_passwords)
    repeated_chars = detect_repeated_characters(password)
    sequential_patterns = detect_sequential_patterns(password)
    keyboard_walks = detect_keyboard_walks(password)
    date_patterns = detect_date_or_year(password)

    detected_patterns = []
    if is_common:
        detected_patterns.append("Common Dictionary / Breached Password")
    if repeated_chars:
        detected_patterns.append(f"Repeated sequence ({', '.join(repeated_chars[:2])})")
    if sequential_patterns:
        detected_patterns.append(f"Sequential characters ({', '.join(sequential_patterns[:2])})")
    if keyboard_walks:
        detected_patterns.append(f"Keyboard pattern ({', '.join(keyboard_walks[:2])})")
    if date_patterns:
        detected_patterns.append(f"Year/Date pattern ({', '.join(date_patterns[:2])})")

    # Effective Entropy Calculation
    entropy_bits, pool_size = calculate_entropy(password)

    # Criteria evaluation
    criteria = [
        Criterion("Length >= 8", length >= 8, "Minimum acceptable baseline (8+ characters)", "Length"),
        Criterion("Length >= 12", length >= 12, "Recommended defense threshold (12+ characters)", "Length"),
        Criterion("Length >= 16", length >= 16, "Optimal resilience against high-speed brute force", "Length"),
        Criterion("Lowercase letters", has_lower, "Includes lowercase characters", "Complexity"),
        Criterion("Uppercase letters", has_upper, "Includes uppercase characters", "Complexity"),
        Criterion("Numbers", has_digits, "Includes numeric digits (0-9)", "Complexity"),
        Criterion("Special symbols", has_symbols, "Includes punctuation or symbols (!@#$%^&*)", "Complexity"),
        Criterion("No dictionary match", not is_common, "Not present in leaked password lists", "Dictionary"),
        Criterion("No sequential sequences", len(sequential_patterns) == 0, "Does not contain sequences like 'abc' or '123'", "Pattern"),
        Criterion("No repeated characters", len(repeated_chars) == 0, "Does not repeat 3+ identical consecutive characters", "Pattern"),
        Criterion("No keyboard walks", len(keyboard_walks) == 0, "Avoids spatial keyboard walks like 'qwerty'", "Pattern"),
    ]

    # Transparent Scoring Model (0 - 100)
    score_breakdown: Dict[str, int] = {
        "Length Points": 0,
        "Character Variety": 0,
        "Entropy Bonus": 0,
        "Pattern Penalties": 0,
    }

    # 1. Length scoring (up to 45 points)
    if length < 6:
        len_pts = 5
    elif length < 8:
        len_pts = 12
    elif length < 10:
        len_pts = 22
    elif length < 12:
        len_pts = 30
    elif length < 16:
        len_pts = 38
    else:
        len_pts = 45
    score_breakdown["Length Points"] = len_pts

    # 2. Character Variety (up to 35 points)
    variety_count = sum([has_lower, has_upper, has_digits, has_symbols])
    variety_pts = 0
    if has_lower:
        variety_pts += 5
    if has_upper:
        variety_pts += 7
    if has_digits:
        variety_pts += 8
    if has_symbols:
        variety_pts += 12

    # Bonus for 3 or all 4 character categories
    if variety_count >= 3:
        variety_pts += 5
    if variety_count == 4:
        variety_pts += 5
    score_breakdown["Character Variety"] = variety_pts

    # 3. Entropy & Uniqueness Bonus (up to 15 points)
    entropy_pts = 0
    if entropy_bits >= 35:
        entropy_pts += 3
    if entropy_bits >= 55:
        entropy_pts += 4
    if entropy_bits >= 75:
        entropy_pts += 4

    unique_ratio = len(set(password)) / length if length > 0 else 0
    if unique_ratio > 0.70 and length >= 10:
        entropy_pts += 4
    score_breakdown["Entropy Bonus"] = entropy_pts

    # 4. Penalties
    penalties = 0
    if repeated_chars:
        penalties -= 15
    if sequential_patterns:
        penalties -= 12
    if keyboard_walks:
        penalties -= 15
    if date_patterns:
        penalties -= 8
    if variety_count <= 1 and length > 0:
        penalties -= 25
    if len(set(password)) <= 2 and length >= 6:
        penalties -= 30
    score_breakdown["Pattern Penalties"] = penalties

    # Total Score Calculation
    total_score = len_pts + variety_pts + entropy_pts + penalties

    # Severe penalty for common passwords: cap to max 15
    if is_common:
        total_score = min(total_score, 15)

    # Severe penalty for passwords with only 1 unique character: cap to max 15
    if len(set(password)) == 1:
        total_score = min(total_score, 15)

    # Clamp between 0 and 100
    total_score = max(0, min(100, total_score))

    # Strength Level & Color Mapping
    if total_score < 35:
        strength_level = "Weak"
        strength_color = "#ef4444"  # Red
    elif total_score < 55:
        strength_level = "Fair"
        strength_color = "#f59e0b"  # Amber
    elif total_score < 75:
        strength_level = "Good"
        strength_color = "#38bdf8"  # Sky Blue
    elif total_score < 90:
        strength_level = "Strong"
        strength_color = "#818cf8"  # Indigo/Purple
    else:
        strength_level = "Very Strong"
        strength_color = "#10b981"  # Emerald

    # Vulnerability Identification
    vulnerabilities: List[Vulnerability] = []
    suggestions: List[str] = []

    if is_common:
        vulnerabilities.append(Vulnerability(
            title="Known Leaked / Dictionary Password",
            severity="Critical",
            description="This password appears in known compromised wordlists or common default credentials.",
            suggestion="Immediately choose a completely unique password that does not appear in common dictionaries."
        ))
        suggestions.append("Do not use dictionary words or common phrases known to credential-stuffing bots.")

    if len(set(password)) <= 2 and length >= 4:
        vulnerabilities.append(Vulnerability(
            title="Extremely Low Character Variety",
            severity="Critical",
            description="Password consists of only 1 or 2 distinct characters repeated, resulting in near-zero actual entropy.",
            suggestion="Use a diverse mixture of unique characters across the keyboard."
        ))

    if length < 8:
        vulnerabilities.append(Vulnerability(
            title="Critically Short Length",
            severity="Critical",
            description=f"Length ({length} chars) is below the minimum recommended 8 characters. Brute force time is negligible.",
            suggestion="Increase password length to at least 12-16 characters."
        ))
        suggestions.append("Extend the length to at least 12 characters to exponentially increase combinatorial resistance.")
    elif length < 12:
        vulnerabilities.append(Vulnerability(
            title="Suboptimal Length",
            severity="Medium",
            description=f"Length is {length} characters. While acceptable for basic accounts, 12-16+ is recommended for critical services.",
            suggestion="Expand your password to 12 or more characters."
        ))
        suggestions.append("Add 3-4 more random characters to reach the recommended 12+ threshold.")

    if variety_count == 1:
        vulnerabilities.append(Vulnerability(
            title="Monolithic Character Set",
            severity="High",
            description="Password contains only one type of character, severely shrinking the search space.",
            suggestion="Mix uppercase, lowercase, numbers, and symbols."
        ))
    else:
        if not has_upper:
            suggestions.append("Include uppercase letters to expand character pool.")
        if not has_lower:
            suggestions.append("Include lowercase letters.")
        if not has_digits:
            suggestions.append("Add numeric digits (0-9) to strengthen complexity.")
        if not has_symbols:
            vulnerabilities.append(Vulnerability(
                title="Missing Special Characters",
                severity="Medium",
                description="Special characters (!@#$%^&*) expand the character pool from 62 to 95.",
                suggestion="Add one or more special characters."
            ))
            suggestions.append("Incorporate special symbols (e.g. #, $, %, @, !) to dramatically increase entropy.")

    if repeated_chars:
        vulnerabilities.append(Vulnerability(
            title="Repeated Characters Detected",
            severity="High",
            description=f"Detected repeated sequences: {', '.join(repeated_chars[:3])}. Attack tools optimize against repeated inputs.",
            suggestion="Replace repeated sequences with non-consecutive random characters."
        ))
        suggestions.append("Avoid consecutive repeating characters like 'aaa' or '111'.")

    if sequential_patterns:
        vulnerabilities.append(Vulnerability(
            title="Sequential Sequence Detected",
            severity="Medium",
            description=f"Detected sequential pattern: {', '.join(sequential_patterns[:3])}. Sequences are prioritized in hybrid dictionary attacks.",
            suggestion="Break up sequential runs of numbers or letters."
        ))
        suggestions.append("Eliminate sequential letters or numbers like 'abc' or '123'.")

    if keyboard_walks:
        vulnerabilities.append(Vulnerability(
            title="Keyboard Pattern Detected",
            severity="High",
            description=f"Detected spatial keyboard walk: {', '.join(keyboard_walks[:3])}. Keyboard walks are among the first patterns tested by cracking algorithms.",
            suggestion="Avoid adjacent keyboard keys like 'qwerty' or 'asdf'."
        ))
        suggestions.append("Avoid consecutive keyboard walks (e.g., 'qwerty', 'zxcv').")

    if date_patterns:
        vulnerabilities.append(Vulnerability(
            title="Date or Year Pattern",
            severity="Low",
            description=f"Detected probable calendar year or date pattern ({', '.join(date_patterns[:3])}).",
            suggestion="Avoid using birth years, anniversary dates, or current years."
        ))
        suggestions.append("Remove predictable year or date stamps.")

    # Deduplicate suggestions
    suggestions = list(dict.fromkeys(suggestions))
    if not suggestions:
        suggestions.append("Excellent security posture! Ensure this password is unique and managed via a password manager.")

    # Determine if password has heavy patterns for crack time estimation
    has_heavy_patterns = (len(set(password)) <= 2 and length >= 4) or bool(keyboard_walks and length <= 16)

    # Crack time estimation
    crack_offline, crack_online = estimate_crack_times(
        entropy_bits=entropy_bits,
        pool_size=pool_size,
        length=length,
        is_compromised=is_common,
        has_heavy_patterns=has_heavy_patterns
    )

    return AnalysisResult(
        password=password,
        length=length,
        score=total_score,
        strength_level=strength_level,
        strength_color=strength_color,
        entropy_bits=entropy_bits,
        pool_size=pool_size,
        has_lower=has_lower,
        has_upper=has_upper,
        has_digits=has_digits,
        has_symbols=has_symbols,
        criteria=criteria,
        vulnerabilities=vulnerabilities,
        suggestions=suggestions,
        estimated_crack_time_offline=crack_offline,
        estimated_crack_time_online=crack_online,
        score_breakdown=score_breakdown,
        is_common=is_common,
        detected_patterns=detected_patterns
    )
