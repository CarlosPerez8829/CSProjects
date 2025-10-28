"""
Password strength checker with entropy scoring.

Provides:
- estimate_entropy(password) -> float (bits)
- score_password(password) -> dict with bits, category, suggestions
- CLI to evaluate a password interactively or from args

This is a lightweight estimator — it intentionally avoids online checks and
password breach databases. It's intended for local guidance and demonstrations."""
from __future__ import annotations

import math
import re
import string
import sys
from typing import Dict, List

# Small built-in list of common words to detect weak dictionary-based passwords.
# This is intentionally tiny to avoid shipping large files; for production, use
# a larger wordlist or an algorithm like zxcvbn.
COMMON_WORDS = {
	"password",
	"123456",
	"qwerty",
	"letmein",
	"admin",
	"welcome",
	"iloveyou",
}


def _char_pool_size(password: str) -> int:
	"""Estimate the character pool size used by the password.

	This is a simple heuristic: if the password contains any lowercase letters,
	we add 26, uppercase add 26, digits add 10, symbols add len(string.punctuation)."""
	pool = 0
	if re.search(r"[a-z]", password):
		pool += 26
	if re.search(r"[A-Z]", password):
		pool += 26
	if re.search(r"[0-9]", password):
		pool += 10
	if re.search(rf"[{re.escape(string.punctuation)}]", password):
		pool += len(string.punctuation)
	# If nothing matched (strange), assume ASCII printable
	if pool == 0 and password:
		pool = 95  # printable ASCII range guess
	return pool


def _count_repeated_char_runs(password: str) -> int:
	"""Return number of repeated-character runs (e.g., 'aaa' counts as run of length 3).

	Helps penalize passwords that are mostly repeated characters."""
	if not password:
		return 0
	runs = 1
	prev = password[0]
	for ch in password[1:]:
		if ch != prev:
			runs += 1
			prev = ch
	return runs


def _has_sequence(password: str, min_len: int = 3) -> bool:
	"""Detect simple ascending or descending sequences like 'abcd' or '4321'.

	This is not exhaustive but catches common patterns."""
	pw = password
	# Normalize: consider letters and digits in lower-case only
	pw_norm = pw.lower()
	# Check for alphabetical or numeric sequences
	for i in range(len(pw_norm) - (min_len - 1)):
		seg = pw_norm[i : i + min_len]
		if seg.isalpha() or seg.isdigit():
			# Build ascending and descending sequences from first char
			asc = ''.join(chr(ord(seg[0]) + j) for j in range(len(seg)))
			desc = ''.join(chr(ord(seg[0]) - j) for j in range(len(seg)))
			if seg == asc or seg == desc:
				return True
	return False


def _contains_common_word(password: str) -> List[str]:
	found: List[str] = []
	low = password.lower()
	for word in COMMON_WORDS:
		if len(word) >= 3 and word in low:
			found.append(word)
	return found


def estimate_entropy(password: str) -> float:
	"""Estimate entropy in bits for a given password.

	Method:
	- Start with entropy = length * log2(pool_size)
	- Apply simple deductions for repeated runs, sequences, and common words.

	This is an estimator, not a perfect predictor. Use as guidance."""
	if not password:
		return 0.0

	length = len(password)
	pool = _char_pool_size(password)
	base_entropy = length * math.log2(pool) if pool > 1 else 0.0

	# Penalize long repeated runs: if many repeated chars, reduce effective entropy
	runs = _count_repeated_char_runs(password)
	repeat_penalty = 0.0
	if runs < length:  # there are repeats
		# fewer runs means more repeats -> larger penalty
		repeat_ratio = runs / length
		# scale penalty up to 25% of the base entropy
		repeat_penalty = (1.0 - repeat_ratio) * 0.25 * base_entropy

	# Penalize sequences
	seq_penalty = 0.0
	if _has_sequence(password, min_len=3):
		seq_penalty = min(0.20 * base_entropy, 10.0)

	# Penalize presence of common words
	common_found = _contains_common_word(password)
	common_penalty = 0.0
	if common_found:
		# subtract roughly 10 bits per common word occurrence (heuristic)
		common_penalty = 10.0 * len(common_found)

	entropy = base_entropy - (repeat_penalty + seq_penalty + common_penalty)
	# clamp
	entropy = max(0.0, entropy)
	return entropy


def score_password(password: str) -> Dict[str, object]:
	"""Return a scoring summary for the password.

	Output keys:
	- entropy: estimated bits (float)
	- category: string label
	- recommendations: List[str]"""
	bits = estimate_entropy(password)

	# Categorize according to entropy thresholds (bits)
	if bits < 28:
		category = "Very Weak"
	elif bits < 36:
		category = "Weak"
	elif bits < 60:
		category = "Reasonable"
	elif bits < 128:
		category = "Strong"
	else:
		category = "Very Strong"

	recs: List[str] = []
	if len(password) < 8:
		recs.append("Use at least 8 characters; 12+ is better for most accounts.")
	if not re.search(r"[a-z]", password):
		recs.append("Add lowercase letters.")
	if not re.search(r"[A-Z]", password):
		recs.append("Add uppercase letters.")
	if not re.search(r"[0-9]", password):
		recs.append("Add digits.")
	if not re.search(rf"[{re.escape(string.punctuation)}]", password):
		recs.append("Add symbols (e.g., !@#$%).")

	if _has_sequence(password, min_len=4):
		recs.append("Avoid sequential characters (e.g., 'abcd' or '1234').")

	common_found = _contains_common_word(password)
	if common_found:
		recs.append(f"Avoid common words like: {', '.join(common_found)}.")

	# Final helpful suggestion
	if not recs:
		recs.append("Use a passphrase (multiple unrelated words) or a password manager to generate/store long, random passwords.")

	return {"entropy": bits, "category": category, "recommendations": recs}


def _print_report(password: str) -> None:
	result = score_password(password)
	bits = result["entropy"]
	category = result["category"]
	recs = result["recommendations"]

	print(f"Password: {password}")
	print(f"Estimated entropy: {bits:.1f} bits")
	print(f"Category: {category}")
	print("Recommendations:")
	for r in recs:
		print(f" - {r}")


def main(argv: List[str] | None = None) -> int:
	"""CLI: if a password is passed as an argument, evaluate it once.

	Otherwise enter an interactive loop where the user can type passwords to
	evaluate repeatedly. Type 'quit' or 'exit' to end the session."""
	if argv is None:
		argv = sys.argv[1:]

	# Support flags: -s/--show to show typed passwords, -h/--help for usage.
	show = False
	if "-s" in argv:
		show = True
		argv = [a for a in argv if a != "-s"]
	if "--show" in argv:
		show = True
		argv = [a for a in argv if a != "--show"]
	if "-h" in argv or "--help" in argv:
		print("Usage: PasswordCheck.py [password] [-s|--show] [-h|--help]")
		print()
		print("If [password] is provided, the program evaluates it once and exits.")
		print("Without arguments it enters interactive mode. In interactive mode:")
		print("  - Type a password to evaluate it.")
		print("  - Type 'quit' or 'exit' to leave.")
		print("  - Type ':show' or 'show' to enable visible typing; ':hide' or 'hide' to hide input.")
		return 0

	# If password provided as first argument, evaluate once and exit
	if len(argv) >= 1:
		pwd = argv[0]
		_print_report(pwd)
		return 0

	# Interactive mode: loop until the user exits
	try:
		import getpass
	except Exception:
		getpass = None

	print("Password checker interactive mode. Type 'quit' or 'exit' to leave.")
	print("  Type ':show' or 'show' to enable visible typing; ':hide' or 'hide' to hide input.")
	while True:
		try:
			# If user asked to show typed passwords, use input(); otherwise try getpass
			if show:
				pwd = input("Enter password to evaluate (visible) (or 'quit' to exit): ")
			else:
				if getpass:
					pwd = getpass.getpass("Enter password to evaluate (hidden) (or 'quit' to exit): ")
				else:
					pwd = input("Enter password to evaluate (or 'quit' to exit): ")
		except (KeyboardInterrupt, EOFError):
			print("\nExiting.")
			break

		if not pwd:
			# empty: show prompt guidance and continue
			print("No password entered. Type 'quit' to exit or enter a password to evaluate.")
			continue

		low = pwd.lower()
		# interactive commands to toggle visibility
		if low in (":show", "show"):
			show = True
			print("Visible typing enabled.")
			continue
		if low in (":hide", "hide"):
			show = False
			print("Hidden typing enabled.")
			continue

		if low in ("quit", "exit"):
			print("Exiting.")
			break

		_print_report(pwd)

	return 0


if __name__ == "__main__":
	raise SystemExit(main())

