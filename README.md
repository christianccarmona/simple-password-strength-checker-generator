# Password Strength Checker and Generator

A beginner-friendly command-line project written in Python. It gives a simple password-strength estimate, checks for common-password substrings in a local wordlist, and generates random passwords.

## Features

- Generates passwords with lowercase letters, uppercase letters, digits, and symbols.
- Counts hyphens as part of the requested total length and avoids a trailing hyphen. To keep every requested length possible, it groups generated characters into chunks of three or four.
- Scores passwords from 0 to 10 using visible rules and gives suggestions for improvement.
- Checks for common-password entries of four or more characters inside the password. Matching ignores case and grouping hyphens.
- Flags a run of three or more identical characters.
- Offers to generate a password when the score is below 7/10.
- Hides typed passwords with Python's `getpass` module. Passwords are not saved or sent over the network.
- Uses only Python's standard library; there are no packages to install.

## Requirements

- Python 3.6 or newer
- The external `Pwdb_top-10000000.txt` wordlist for password checks

## Setup

1. Download `Pwdb_top-10000000.txt` from [SecLists](https://github.com/danielmiessler/SecLists/blob/master/Passwords/Common-Credentials/Pwdb_top-10000000.txt).
2. Put the downloaded file in the same folder as `password_tool.py`.
3. Open the project folder in VS Code and choose **Terminal → New Terminal**.

The wordlist is about 90 MB and is intentionally not included in this repository. The program reads it one line at a time instead of loading the full file into memory. A no-match check must scan the full list, so time depends on your computer and storage drive.

## Run the program

In the VS Code terminal, run:

```text
python password_tool.py
```

Choose `1` to check a password, `2` to generate one, or `3` to quit. Generated password length includes the hyphens. The groups contain three or four random characters, so the requested total length is exact and the password never ends with a hyphen.

## Run the tests

The tests use Python's built-in `unittest` module and a small temporary wordlist, so the large SecLists file is not needed to run them.

```text
python -m unittest -v
```

## How the score works

The program awards up to 10 points:

| Check | Points |
|---|---:|
| Length milestones (8, 12, and 16 characters) | 3 |
| Both lowercase and uppercase letters | 2 |
| At least one digit | 1 |
| At least one symbol | 1 |
| No run of three identical characters | 1 |
| No common-password substring | 2 |

If a common-password substring is found, the score is capped at 4/10. Scores of 0–4 are **Weak**, 5–7 are **Moderate**, and 8–10 are **Strong**. This is a simple learning-project estimate; it does not calculate cracking time or query a live breach database, and a “Strong” result is not a security guarantee.

The checker ignores list entries shorter than four characters to avoid flagging trivial fragments. It does not replace letters with lookalike symbols (for example, it does not treat `@` as `a`). Do not enter a password you currently use for an important account into a practice project.

## Project files

- `password_tool.py` — the command-line program
- `test_password_tool.py` — automated tests
- `README.md` — setup, usage, and project details
- `BUILD_GUIDE.md` — optional guide for learning and modifying the project
- `.gitignore` — excludes the large wordlist and Python-generated files
- `LICENSE` — license for this project's code

## Data source and licenses

The common-password list comes from [SecLists](https://github.com/danielmiessler/SecLists), maintained by Daniel Miessler and contributors. The list is not redistributed in this repository; download it from the source above and consult the [SecLists license](https://github.com/danielmiessler/SecLists/blob/master/LICENSE) for its terms and notices.

The Python code in this repository is offered under the MIT License; see [`LICENSE`](LICENSE). The SecLists wordlist is a separate third-party data file and is not included in this project's code license.
