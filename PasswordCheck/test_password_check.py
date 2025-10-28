import unittest

from PasswordCheck import estimate_entropy, score_password


class TestPasswordCheck(unittest.TestCase):
    def test_empty_password(self):
        self.assertEqual(estimate_entropy(""), 0.0)

    def test_repeated_chars_lower_entropy(self):
        e1 = estimate_entropy("aaaaaaaa")
        e2 = estimate_entropy("abcd1234")
        # repeated single-character password should have less entropy than varied
        self.assertLess(e1, e2)

    def test_mixed_characters_increases_entropy(self):
        low = estimate_entropy("password")
        high = estimate_entropy("P@ssw0rd!2025")
        self.assertGreater(high, low)

    def test_score_categories(self):
        weak = score_password("1234")
        strong = score_password("G7#xT9!mQ2@")
        self.assertIn(weak["category"], {"Very Weak", "Weak", "Reasonable"})
        self.assertIn(strong["category"], {"Strong", "Very Strong"})


if __name__ == "__main__":
    unittest.main()
