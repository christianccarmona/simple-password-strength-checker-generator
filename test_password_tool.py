"""Small automated checks for the password tool."""

import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from password_tool import (
    check_password,
    estimate_strength,
    generate_password,
    has_repeated_characters,
    is_common_password,
    SYMBOLS,
)


class PasswordToolTests(unittest.TestCase):
    def test_generated_password_has_requested_length(self):
        password = generate_password(20)
        self.assertEqual(len(password), 20)
        self.assertFalse(password.endswith("-"))
        self.assertTrue(all(3 <= len(group) <= 4 for group in password.split("-")))

    def test_generated_password_contains_all_four_character_types(self):
        password = generate_password(16)
        characters = password.replace("-", "")
        self.assertTrue(any(character.islower() for character in characters))
        self.assertTrue(any(character.isupper() for character in characters))
        self.assertTrue(any(character.isdigit() for character in characters))
        self.assertTrue(any(character in SYMBOLS for character in characters))

    def test_generated_password_has_exact_requested_total_at_every_allowed_length(self):
        for length in range(12, 65):
            with self.subTest(length=length):
                password = generate_password(length)
                self.assertEqual(len(password), length)
                self.assertFalse(password.endswith("-"))
                self.assertNotIn("--", password)
                self.assertTrue(all(3 <= len(group) <= 4 for group in password.split("-")))

    def test_generator_rejects_length_outside_allowed_range(self):
        with self.assertRaises(ValueError):
            generate_password(11)
        with self.assertRaises(ValueError):
            generate_password(65)

    def test_listed_password_gets_weak_rating(self):
        with TemporaryDirectory() as temporary_directory:
            wordlist_path = Path(temporary_directory) / "common_passwords.txt"
            wordlist_path.write_text("password123\n", encoding="utf-8")
            rating, score, suggestions = estimate_strength("password123", wordlist_path)

        self.assertEqual(rating, "Weak")
        self.assertLessEqual(score, 4)
        self.assertTrue(any("common password" in suggestion for suggestion in suggestions))

    def test_wordlist_finds_common_password_substrings_case_insensitively(self):
        with TemporaryDirectory() as temporary_directory:
            wordlist_path = Path(temporary_directory) / "common_passwords.txt"
            wordlist_path.write_text(
                "password123\niloveyou\nqwerty123\n987654321\n",
                encoding="utf-8",
            )

            self.assertTrue(is_common_password("xpassword123!", wordlist_path))
            self.assertTrue(is_common_password("xxILOVEYOUxx", wordlist_path))
            self.assertTrue(is_common_password("prefixQWERTY123suffix", wordlist_path))
            self.assertTrue(is_common_password("987654321", wordlist_path))
            self.assertFalse(is_common_password("password", wordlist_path))
            self.assertFalse(is_common_password("something-unlisted", wordlist_path))

    def test_common_substring_check_ignores_short_entries_and_generator_hyphens(self):
        with TemporaryDirectory() as temporary_directory:
            wordlist_path = Path(temporary_directory) / "common_passwords.txt"
            wordlist_path.write_text("a\n123\npass\n", encoding="utf-8")

            self.assertTrue(is_common_password("Abcd-pass-5678", wordlist_path))
            self.assertFalse(is_common_password("abc-123", wordlist_path))

    def test_three_repeated_characters_in_a_row_are_detected(self):
        self.assertTrue(has_repeated_characters("abccc123"))
        self.assertTrue(has_repeated_characters("aa-aa-123"))
        self.assertFalse(has_repeated_characters("aabbcc123"))

    def test_missing_wordlist_has_a_helpful_error(self):
        with TemporaryDirectory() as temporary_directory:
            missing_path = Path(temporary_directory) / "missing.txt"
            with self.assertRaisesRegex(FileNotFoundError, "missing.txt"):
                estimate_strength("Example123!", missing_path)

    def test_long_mixed_password_gets_strong_rating(self):
        with TemporaryDirectory() as temporary_directory:
            wordlist_path = Path(temporary_directory) / "common_passwords.txt"
            wordlist_path.write_text("password123\n", encoding="utf-8")
            rating, score, suggestions = estimate_strength("Abcd1234!@#$wXYZ", wordlist_path)

        self.assertEqual(rating, "Strong")
        self.assertEqual(score, 10)

    def test_score_below_seven_offers_password_generation(self):
        with patch("password_tool.getpass.getpass", return_value="practice-only"):
            with patch("password_tool.estimate_strength", return_value=("Moderate", 6, [])):
                with patch("builtins.input", return_value="y"):
                    with patch("password_tool.make_password_from_menu") as generate_menu:
                        with redirect_stdout(StringIO()):
                            check_password()

        generate_menu.assert_called_once()

    def test_score_of_seven_does_not_offer_password_generation(self):
        with patch("password_tool.getpass.getpass", return_value="practice-only"):
            with patch("password_tool.estimate_strength", return_value=("Moderate", 7, [])):
                with patch("builtins.input") as prompt:
                    with patch("password_tool.make_password_from_menu") as generate_menu:
                        with redirect_stdout(StringIO()):
                            check_password()

        prompt.assert_not_called()
        generate_menu.assert_not_called()


if __name__ == "__main__":
    unittest.main()
