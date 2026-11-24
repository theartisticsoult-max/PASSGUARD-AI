"""
PASSGUARD AI - Cryptographically Secure Password Generator
Utilizes Python's standard `secrets` module (CSPRNG) to generate high-entropy passwords.
"""

import secrets
import string
from typing import List, Optional


# Character Sets
LOWERCASE_CHARS = string.ascii_lowercase
UPPERCASE_CHARS = string.ascii_uppercase
DIGIT_CHARS = string.digits
SYMBOL_CHARS = "!@#$%^&*()-_=+[]{}|;:,.<>?"

# Ambiguous characters that look similar across various fonts
AMBIGUOUS_CHARS = set("il1Lo0O|`'\"")

# Curated wordlist for memorable multi-word passphrases
PASSPHRASE_WORDS = [
    "nebula", "quantum", "cipher", "matrix", "shield", "beacon", "crypto",
    "vertex", "phoenix", "falcon", "aurora", "zenith", "vortex", "cobalt",
    "shadow", "glacier", "prism", "binary", "vector", "orbital", "pulsar",
    "cascade", "dynamo", "solaris", "titan", "stellar", "horizon", "bastion",
    "sentinel", "phantom", "monolith", "eclipse", "granite", "thunder", "kinetic",
    "radiant", "obsidian", "mystic", "summit", "ironclad", "canyon", "tempest",
    "valiant", "harbor", "blizzard", "odyssey", "sapphire", "trident", "astral"
]


def generate_password(
    length: int = 16,
    use_upper: bool = True,
    use_lower: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
    exclude_ambiguous: bool = False
) -> str:
    """
    Generate a cryptographically secure random password using `secrets`.
    Guarantees at least one character from each enabled set.
    """
    if length < 4:
        length = 4

    # Build active character pools
    selected_pools: List[str] = []
    guaranteed_chars: List[str] = []

    if use_lower:
        pool = LOWERCASE_CHARS
        if exclude_ambiguous:
            pool = "".join(c for c in pool if c not in AMBIGUOUS_CHARS)
        if pool:
            selected_pools.append(pool)
            guaranteed_chars.append(secrets.choice(pool))

    if use_upper:
        pool = UPPERCASE_CHARS
        if exclude_ambiguous:
            pool = "".join(c for c in pool if c not in AMBIGUOUS_CHARS)
        if pool:
            selected_pools.append(pool)
            guaranteed_chars.append(secrets.choice(pool))

    if use_digits:
        pool = DIGIT_CHARS
        if exclude_ambiguous:
            pool = "".join(c for c in pool if c not in AMBIGUOUS_CHARS)
        if pool:
            selected_pools.append(pool)
            guaranteed_chars.append(secrets.choice(pool))

    if use_symbols:
        pool = SYMBOL_CHARS
        if exclude_ambiguous:
            pool = "".join(c for c in pool if c not in AMBIGUOUS_CHARS)
        if pool:
            selected_pools.append(pool)
            guaranteed_chars.append(secrets.choice(pool))

    # Fallback to lowercase if everything was deselected
    if not selected_pools:
        selected_pools = [LOWERCASE_CHARS]
        guaranteed_chars = [secrets.choice(LOWERCASE_CHARS)]

    # Combine full character set
    full_pool = "".join(selected_pools)

    # Number of remaining characters to generate
    remaining_count = max(0, length - len(guaranteed_chars))
    random_chars = [secrets.choice(full_pool) for _ in range(remaining_count)]

    # Combine and cryptographically shuffle
    password_chars = guaranteed_chars + random_chars
    rng = secrets.SystemRandom()
    rng.shuffle(password_chars)

    return "".join(password_chars)


def generate_passphrase(
    num_words: int = 4,
    separator: str = "-",
    capitalize: bool = True,
    include_number: bool = True
) -> str:
    """
    Generate a memorable multi-word passphrase (e.g. Zenith-Cascade-Shield-42).
    """
    selected_words = [secrets.choice(PASSPHRASE_WORDS) for _ in range(num_words)]
    if capitalize:
        selected_words = [w.capitalize() for w in selected_words]

    passphrase = separator.join(selected_words)
    if include_number:
        num = secrets.randbelow(90) + 10  # 10 to 99
        passphrase = f"{passphrase}{separator}{num}"

    return passphrase
