"""
PASSGUARD AI - Validation Test Suite
Automated verification for analyzer, generator, heuristics, and security edge cases.
"""

import unittest
from analyzer import (
    analyze_password,
    calculate_entropy,
    detect_repeated_characters,
    detect_sequential_patterns,
    detect_keyboard_walks,
    detect_date_or_year,
    normalize_leetspeak,
)
from generator import generate_password, generate_passphrase


class TestPassguardAnalyzer(unittest.TestCase):
    def test_empty_password(self):
        res = analyze_password("")
        self.assertEqual(res.score, 0)
        self.assertEqual(res.strength_level, "Weak")
        self.assertEqual(res.length, 0)
        self.assertEqual(res.entropy_bits, 0.0)

    def test_common_passwords(self):
        for weak in ["password", "123456", "qwerty", "admin", "dragon", "welcome"]:
            res = analyze_password(weak)
            self.assertTrue(res.is_common, f"Failed for {weak}")
            self.assertIn(res.strength_level, ["Weak", "Fair"])
            self.assertLessEqual(res.score, 35)

    def test_leetspeak_common_passwords(self):
        res = analyze_password("p@ssw0rd")
        self.assertTrue(res.is_common or "Dictionary" in str(res.detected_patterns))
        self.assertLessEqual(res.score, 35)

    def test_strong_password(self):
        strong_pw = "Tr@9!vL2#mK$8qZ&"
        res = analyze_password(strong_pw)
        self.assertGreaterEqual(res.score, 80)
        self.assertIn(res.strength_level, ["Strong", "Very Strong"])
        self.assertTrue(res.has_lower)
        self.assertTrue(res.has_upper)
        self.assertTrue(res.has_digits)
        self.assertTrue(res.has_symbols)
        self.assertFalse(res.is_common)

    def test_repeated_characters(self):
        self.assertTrue(len(detect_repeated_characters("aaa123")) > 0)
        self.assertTrue(len(detect_repeated_characters("passs123")) > 0)
        self.assertEqual(len(detect_repeated_characters("abcdef")), 0)

    def test_sequential_patterns(self):
        self.assertTrue(len(detect_sequential_patterns("abcxyz")) > 0)
        self.assertTrue(len(detect_sequential_patterns("test123test")) > 0)
        self.assertEqual(len(detect_sequential_patterns("t9X#m2!v")), 0)

    def test_keyboard_walks(self):
        self.assertTrue(len(detect_keyboard_walks("myqwerty12")) > 0)
        self.assertTrue(len(detect_keyboard_walks("testasdfgh")) > 0)
        self.assertEqual(len(detect_keyboard_walks("z9K#pL3!")) , 0)

    def test_date_patterns(self):
        self.assertTrue(len(detect_date_or_year("john1995")) > 0)
        self.assertTrue(len(detect_date_or_year("pass2024")) > 0)

    def test_entropy_calculation(self):
        # 8 distinct lowercase chars
        ent, pool = calculate_entropy("abcdefgh")
        self.assertEqual(pool, 26)
        self.assertGreaterEqual(ent, 30.0)

        # 16 distinct chars: lowercase, uppercase, digits, symbols
        ent_full, pool_full = calculate_entropy("aA1!bB2@cC3#dD4$")
        self.assertEqual(pool_full, 95)
        self.assertGreater(ent_full, 90.0)

    def test_repeated_characters_entropy_not_inflated(self):
        # 16 'a's must NOT have 70+ bits of entropy or centuries of crack time
        res = analyze_password("aaaaaaaaaaaaaaaa")
        self.assertEqual(res.score, 0)
        self.assertEqual(res.strength_level, "Weak")
        self.assertLess(res.entropy_bits, 10.0)
        self.assertIn("Instant", res.estimated_crack_time_offline)

    def test_long_password_no_overflow(self):
        # Test 1000 character inputs for overflow prevention
        long_weak = "a" * 1000
        res_weak = analyze_password(long_weak)
        self.assertEqual(res_weak.score, 0)
        self.assertIn("Instant", res_weak.estimated_crack_time_offline)

        long_strong = "K9#xV!7m" * 125
        res_strong = analyze_password(long_strong)
        self.assertGreaterEqual(res_strong.score, 90)
        self.assertIn("Millions", res_strong.estimated_crack_time_offline)

    def test_unicode_passwords(self):
        # Test emojis and non-ascii accented and Cyrillic characters
        res_emoji = analyze_password("🔒🔑Pass123!Safe")
        self.assertTrue(res_emoji.has_symbols)
        self.assertGreaterEqual(res_emoji.score, 75)

        res_cyrillic = analyze_password("ПарольЗащита123!")
        self.assertTrue(res_cyrillic.has_upper)
        self.assertTrue(res_cyrillic.has_lower)
        self.assertGreaterEqual(res_cyrillic.score, 75)

    def test_keyboard_walk_crack_time(self):
        # Long keyboard walk should be recognized as weak with instant crack time
        res = analyze_password("qwertyuiopasdfgh")
        self.assertEqual(res.strength_level, "Weak")
        self.assertIn("Instant", res.estimated_crack_time_offline)


class TestPassguardGenerator(unittest.TestCase):
    def test_password_generation_length(self):
        for length in [8, 12, 16, 24, 32]:
            pw = generate_password(length=length)
            self.assertEqual(len(pw), length)

    def test_character_sets_guarantee(self):
        for _ in range(20):
            pw = generate_password(length=16, use_upper=True, use_lower=True, use_digits=True, use_symbols=True)
            self.assertTrue(any(c.islower() for c in pw), "Missing lowercase")
            self.assertTrue(any(c.isupper() for c in pw), "Missing uppercase")
            self.assertTrue(any(c.isdigit() for c in pw), "Missing digit")
            self.assertTrue(any(not c.isalnum() for c in pw), "Missing symbol")

    def test_exclude_ambiguous(self):
        ambiguous = set("il1Lo0O|`'\"")
        for _ in range(20):
            pw = generate_password(length=30, exclude_ambiguous=True)
            for c in pw:
                self.assertNotIn(c, ambiguous, f"Found ambiguous char {c} in {pw}")

    def test_passphrase_generation(self):
        passphrase = generate_passphrase(num_words=4, separator="-")
        parts = passphrase.split("-")
        # 4 words + 1 appended number = 5 parts
        self.assertEqual(len(parts), 5)


if __name__ == "__main__":
    unittest.main()
