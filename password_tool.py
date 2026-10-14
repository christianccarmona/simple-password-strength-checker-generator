"""Simple password generator and strength estimator."""

import getpass
import secrets
import string
from pathlib import Path


SYMBOLS = "!@#$%^&*_=+,.?"
PASSWORD_LIST_FILE = Path(__file__).with_name("Pwdb_top-10000000.txt")
MIN_COMMON_SUBSTRING_LENGTH = 4


def format_password(password, group_size=4, group_count=None):
    """Group characters evenly, using groups no longer than group_size."""
    if not password:
        return ""

    if group_size < 1:
        raise ValueError("Group size must be at least 1.")
    if group_count is None:
        group_count = (len(password) + group_size - 1) // group_size

    short_group_size, larger_group_count = divmod(len(password), group_count)
    groups = []
    start = 0

    for index in range(group_count):
        current_size = short_group_size + (1 if index < larger_group_count else 0)
        groups.append(password[start:start + current_size])
        start += current_size

    return "-".join(groups)

def generate_password(length=16):
    """Return a grouped random password with all four character types."""
    if length < 12 or length > 64:
        raise ValueError("Choose a total password length from 12 to 64 characters.")

    character_groups = [
        string.ascii_lowercase,
        string.ascii_uppercase,
        string.digits,
        SYMBOLS,
    ]

    # Pick one from each group first so all four types are guaranteed.
    password_characters = [secrets.choice(group) for group in character_groups]
    all_characters = "".join(character_groups)

    # Count hyphens as part of the requested total length. With groups of up
    # to four, this chooses a number of character groups that fits that total.
    group_count = (length + 5) // 5
    character_count = length - group_count + 1
    while len(password_characters) < character_count:
        password_characters.append(secrets.choice(all_characters))

    # Shuffle so the required character types aren't in fixed positions.
    secrets.SystemRandom().shuffle(password_characters)
    generated_characters = "".join(password_characters)
    return format_password(generated_characters, group_count=group_count)


def is_common_password(password, password_list_file=PASSWORD_LIST_FILE):
    """Return whether a list entry of 4+ characters occurs in the password.

    Matching ignores letter case and generator hyphens. The list is streamed
    one line at a time to avoid loading all ten million entries into memory.
    """
    password_list_file = Path(password_list_file)
    searchable_password = password.replace("-", "").casefold()

    with password_list_file.open("r", encoding="utf-8", errors="replace") as wordlist:
        for line in wordlist:
            listed_password = line.rstrip("\r\n").casefold()
            if (
                len(listed_password) >= MIN_COMMON_SUBSTRING_LENGTH
                and listed_password in searchable_password
            ):
                return True

    return False


def has_repeated_characters(password):
    """Return True for a run of three or more of the same character."""
    password = password.replace("-", "")
    run_length = 1
    for index in range(1, len(password)):
        if password[index] == password[index - 1]:
            run_length += 1
            if run_length >= 3:
                return True
        else:
            run_length = 1
    return False


def estimate_strength(password, password_list_file=PASSWORD_LIST_FILE):
    """Return a simple rating, score out of 10, and suggestions."""
    try:
        has_common_substring = is_common_password(password, password_list_file)
    except FileNotFoundError as error:
        raise FileNotFoundError(
            f"Could not find {Path(password_list_file).name}. Put it in the same folder as password_tool.py."
        ) from error

    score = 0
    suggestions = []

    # Length can earn up to three points.
    if len(password) >= 8:
        score += 1
    if len(password) >= 12:
        score += 1
    if len(password) >= 16:
        score += 1

    if len(password) < 8:
        suggestions.append("Use at least 8 characters.")
    elif len(password) < 12:
        suggestions.append("Aim for at least 12 characters.")
    elif len(password) < 16:
        suggestions.append("Aim for 16 or more characters for a stronger passphrase.")

    has_lowercase = any(character.islower() for character in password)
    has_uppercase = any(character.isupper() for character in password)
    has_digit = any(character.isdigit() for character in password)
    has_symbol = any(character in SYMBOLS for character in password)

    if has_lowercase and has_uppercase:
        score += 2
    else:
        suggestions.append("Use both lowercase and uppercase letters.")

    if has_digit:
        score += 1
    else:
        suggestions.append("Add a number.")

    if has_symbol:
        score += 1
    else:
        suggestions.append("Add a symbol, such as ! or #.")

    if has_repeated_characters(password):
        suggestions.append("Avoid using the same character three or more times in a row.")
    else:
        score += 1

    if has_common_substring:
        # A listed password inside the input is a serious weakness. Cap the
        # score so even a long, mixed password cannot receive a high rating.
        score = min(score, 4)
        suggestions.append(
            "A common password of at least 4 characters appears within this password (case-insensitive). Try a different word or sequence."
        )
    else:
        score += 2

    if score <= 4:
        rating = "Weak"
    elif score <= 7:
        rating = "Moderate"
    else:
        rating = "Strong"

    if not suggestions:
        suggestions.append("Good mix. Avoid reusing this password on other accounts.")

    return rating, score, suggestions


def check_password():
    """Ask for a password without displaying it, then show the score."""
    password = getpass.getpass("Enter a password (your typing is hidden): ")
    try:
        rating, score, suggestions = estimate_strength(password)
    except FileNotFoundError as error:
        print(f"\n{error}")
        print("The password list is large, so it is kept as a separate local file.")
        return

    print(f"\nEstimated strength: {rating} ({score}/10)")
    print("Suggestions:")
    for suggestion in suggestions:
        print(f"- {suggestion}")

    if score < 7:
        answer = input("\nWould you like to generate a password instead? (y/n): ").strip().lower()
        if answer in ("y", "yes"):
            make_password_from_menu()

    print("\nThis is a simple estimate, not a guarantee or a check against leaked passwords.")


def make_password_from_menu():
    """Ask for a length and display a generated password."""
    length_text = input("Password length, 12-64 (press Enter for 16): ").strip()

    if length_text == "":
        length = 16
    else:
        try:
            length = int(length_text)
        except ValueError:
            print("Please enter a whole number.\n")
            return

    try:
        password = generate_password(length)
    except ValueError as error:
        print(f"{error}\n")
        return

    print(f"\nGenerated password: {password}")
    print("Copy it somewhere safe. This program does not save it.\n")


def main():
    """Show the menu until the user chooses to quit."""
    while True:
        print("=== Password Strength Checker and Generator ===")
        print("1. Check a password")
        print("2. Generate a password")
        print("3. Quit")

        choice = input("Choose 1, 2, or 3: ").strip()

        if choice == "1":
            check_password()
            print()
        elif choice == "2":
            make_password_from_menu()
        elif choice == "3":
            print("Goodbye!")
            break
        else:
            print("Please choose 1, 2, or 3.\n")


if __name__ == "__main__":
    main()
