#!/usr/bin/env python3
"""
Password Crack-Time Estimator (PBKDF2 -> AES-256)
100% local, no network calls, no logging of the password.

This tool estimates how long a brute-force attack would theoretically
take against a password, assuming the password is the weak link in a
PBKDF2-based key derivation scheme (e.g. PBKDF2-HMAC-SHA256 feeding an
AES-256 key). It does NOT attack anything, store anything, or send
anything anywhere -- it just does arithmetic based on:

    1. The password's character-set entropy (how big the guessing space is)
    2. An assumed attacker guessing speed (guesses/second), which for
       PBKDF2 is dominated by the KDF's iteration count, not raw AES speed.

IMPORTANT CAVEATS (read these -- they matter more than the numbers):
  - This estimates a THEORETICAL, UNIFORM brute-force search over the
    character space implied by which character classes you used. It does
    NOT model dictionary attacks, leaked-password lists, pattern-based
    guessing (e.g. "P@ssw0rd123"), or personal-info-based guessing -- all
    of which are dramatically faster in practice than raw brute force.
  - Real attacker speed depends entirely on the PBKDF2 iteration count
    (and hardware). This script lets you enter that iteration count, or
    pick a preset, but any number you choose is an assumption, not a fact
    about your actual system.
  - Treat the output as a rough order-of-magnitude sanity check, not a
    guarantee.
"""

import math
import getpass
import string
import sys

# ---------------------------------------------------------------------------
# Character set detection
# ---------------------------------------------------------------------------

# Assumed pool size for characters outside printable ASCII (accented letters,
# non-Latin scripts, emoji, ...). The real pool is unknowable from one
# password, so this is a deliberately conservative guess: understating the
# guessing space errs on the side of telling you a password is weaker.
NON_ASCII_POOL = 100


def charset_size(password: str) -> int:
    """Estimate the size of the character space the password draws from,
    based on which character classes are present."""
    has_lower = any(c in string.ascii_lowercase for c in password)
    has_upper = any(c in string.ascii_uppercase for c in password)
    has_digit = any(c in string.digits for c in password)
    has_symbol = any(c in string.punctuation for c in password)
    has_space = " " in password
    has_other = any(not (c.isascii() and c.isprintable()) for c in password)

    size = 0
    if has_lower:
        size += 26
    if has_upper:
        size += 26
    if has_digit:
        size += 10
    if has_symbol:
        size += 32   # printable ASCII symbols
    if has_space:
        size += 1
    if has_other:
        size += NON_ASCII_POOL

    return max(size, 1)


def entropy_bits(password: str) -> float:
    """Upper-bound entropy estimate: log2(charset_size ^ length), i.e. the
    entropy the password would have if every character were chosen at
    random from the detected character space."""
    size = charset_size(password)
    if len(password) == 0:
        return 0.0
    return len(password) * math.log2(size)


# ---------------------------------------------------------------------------
# Attacker speed presets (guesses per second)
#
# These are illustrative orders of magnitude for OFFLINE attacks against a
# PBKDF2-HMAC-SHA256-derived key, where the attacker must run the full KDF
# for every guess. GPU figures are scaled from a public hashcat benchmark of
# an RTX 4090 (~16M guesses/s at 500 iterations, i.e. ~8 billion PBKDF2
# iterations/s). Real numbers vary hugely with hardware, iteration count,
# and the specific PBKDF2 pseudorandom function used. Adjust freely.
# ---------------------------------------------------------------------------

PRESETS = {
    "1": ("Single CPU core, PBKDF2 @ 600,000 iterations (modern default)", 10),
    "2": ("High-end consumer GPU (RTX 4090-class), PBKDF2 @ 600,000 iterations", 13_000),
    "3": ("Large GPU cluster (~100 high-end GPUs), PBKDF2 @ 600,000 iterations", 1_300_000),
    "4": ("High-end consumer GPU (RTX 4090-class), PBKDF2 @ 100,000 iterations (older default)", 80_000),
    "5": ("Large GPU cluster (~100 high-end GPUs), PBKDF2 @ 100,000 iterations", 8_000_000),
    "6": ("Custom: enter your own guesses/second", None),
}


def choose_guess_rate() -> float:
    print("\nAssumed attacker capability (this is a guess -- pick what's realistic for your threat model):")
    for key, (label, _) in PRESETS.items():
        print(f"  {key}. {label}")
    choice = input("Choose [1-6], default 3: ").strip() or "3"

    if choice not in PRESETS:
        print("Unrecognized choice, defaulting to option 3.")
        choice = "3"

    label, rate = PRESETS[choice]
    if rate is None:
        while True:
            try:
                rate = float(input("Enter guesses per second: ").strip())
                if rate > 0 and math.isfinite(rate):
                    break
                print("Must be a positive, finite number.")
            except ValueError:
                print("Please enter a numeric value.")
    return rate


# ---------------------------------------------------------------------------
# Formatting
#
# Keyspaces for long passwords exceed the float range (~1e308), so large
# quantities are carried around as base-10 logarithms.
# ---------------------------------------------------------------------------

SECONDS_PER_YEAR = 365.25 * 24 * 3600


def format_scientific(log10_value: float) -> str:
    """Format 10**log10_value like '1.23e+45' without overflowing a float."""
    exponent = math.floor(log10_value)
    mantissa = 10 ** (log10_value - exponent)
    if round(mantissa, 2) >= 10:
        mantissa /= 10
        exponent += 1
    return f"{mantissa:.2f}e{exponent:+03d}"


def format_duration(log10_seconds: float) -> str:
    if log10_seconds < 0:
        return "less than a second"

    units = [
        ("centuries", 100 * SECONDS_PER_YEAR),
        ("years", SECONDS_PER_YEAR),
        ("days", 24 * 3600),
        ("hours", 3600),
        ("minutes", 60),
        ("seconds", 1),
    ]

    # For astronomically large numbers, just report order of magnitude in years
    log10_years = log10_seconds - math.log10(SECONDS_PER_YEAR)
    if log10_years > 6:
        return f"~{format_scientific(log10_years)} years (effectively uncrackable by brute force)"

    seconds = 10 ** log10_seconds
    for name, unit_seconds in units:
        if seconds >= unit_seconds:
            value = seconds / unit_seconds
            return f"~{value:,.2f} {name}"
    return "less than a second"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print(__doc__)
    print("-" * 70)

    try:
        password = getpass.getpass("Enter password to evaluate (input hidden, nothing is stored): ")
    except Exception:
        # Fallback if terminal doesn't support hidden input
        password = input("Enter password to evaluate (input will be visible): ")

    if not password:
        print("No password entered. Exiting.")
        sys.exit(0)

    length = len(password)
    size = charset_size(password)
    bits = entropy_bits(password)
    log10_total = length * math.log10(size)

    print("\n--- Password characteristics ---")
    print(f"Length: {length} characters")
    print(f"Estimated character-set size: {size}")
    print(f"Estimated entropy (upper bound): {bits:.2f} bits")
    print(f"Full keyspace size: ~{format_scientific(log10_total)} possible combinations")
    if any(not (c.isascii() and c.isprintable()) for c in password):
        print(f"Note: non-ASCII characters detected; assumed a pool of {NON_ASCII_POOL} "
              "extra characters (a rough guess).")

    rate = choose_guess_rate()

    log10_rate = math.log10(rate)
    avg_log10_seconds = log10_total - math.log10(2) - log10_rate   # average case: half the keyspace
    worst_log10_seconds = log10_total - log10_rate                 # worst case: entire keyspace

    print("\n--- Theoretical brute-force crack time ---")
    print(f"Assumed attacker speed: {rate:,.0f} guesses/second")
    print(f"Average case (50% of keyspace searched): {format_duration(avg_log10_seconds)}")
    print(f"Worst case (100% of keyspace searched):  {format_duration(worst_log10_seconds)}")

    print("\nReminder: this assumes a truly random password with no patterns,")
    print("dictionary words, or reused/leaked components. Real-world attacks")
    print("are usually much faster than pure brute force because passwords")
    print("are rarely truly random.")

    # Password is never written to disk, logged, or transmitted.
    del password


if __name__ == "__main__":
    main()
