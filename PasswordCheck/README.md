# PasswordCheck

Simple local password strength checker with entropy scoring.

Features
- Estimate entropy in bits for a password using character pool heuristics.
- Simple penalties for repeated characters, sequences, and common words.
- Categorizes passwords (Very Weak -> Very Strong) and provides recommendations.

Usage

- Run interactively (it will prompt for a password without echoing):

```powershell
python PasswordCheck.py
```

Visible typing

By default the interactive mode hides input (uses getpass). Use the `-s` or
`--show` flag to show typed passwords in the interactive prompt (useful for
demos or when you're the only user on the machine):

```powershell
python PasswordCheck.py -s
# Enter password to evaluate (visible) (or 'quit' to exit): MyPass123
# (output printed)
```

Single evaluation

- Or pass a password as an argument (note: passing passwords on the command line may be visible to other users/processes):

```powershell
python PasswordCheck.py "P@ssw0rd!2025"
```

API

Import and call from Python:

```python
from PasswordCheck import estimate_entropy, score_password

print(estimate_entropy("P@ssw0rd!2025"))
print(score_password("P@ssw0rd!2025"))
```

Notes
- This is a local estimator for guidance only. For production use, consider stronger heuristics (e.g., zxcvbn) and server-side breach checks if appropriate.
- Avoid passing secrets on CLI arguments in shared environments.

Example interactive session (visible)

```
$ python PasswordCheck.py -s
Password checker interactive mode. Type 'quit' or 'exit' to leave.
Enter password to evaluate (visible) (or 'quit' to exit): MyPass123
Password: MyPass123
Estimated entropy: 38.2 bits
Category: Reasonable
Recommendations:
 - Add symbols (e.g., !@#$%).
 - Use a passphrase (multiple unrelated words) or a password manager to generate/store long, random passwords.
Enter password to evaluate (visible) (or 'quit' to exit): quit
Exiting.
```

Interactive commands and help

In interactive mode you can toggle visible typing without restarting the program:

- Type `:show` or `show` — enable visible typing (same as `-s`).
- Type `:hide` or `hide` — switch back to hidden input (uses getpass when available).
- Type `quit` or `exit` — leave the program.

Run `-h` or `--help` to print a short usage summary:

```powershell
python PasswordCheck.py -h
```
