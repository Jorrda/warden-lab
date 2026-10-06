"""Rotate the portal access key.

Usage: rotate_keys.py OLD_KEY_ID, for example AKIAIOSFODNN7EXAMPLE, the id every AWS document uses.
"""
import sys


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__)
        return 2
    print(f"would rotate {argv[1]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
