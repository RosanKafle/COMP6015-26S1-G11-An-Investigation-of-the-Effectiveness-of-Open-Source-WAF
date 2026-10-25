"""Refactored continuation of the previous semester's automate_modsecurity_sqli.py.
Retains the same laboratory task; shared modules replace duplicated unsafe plumbing.
"""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent / "scripts"))
from run_test_set import parser_for, run

def main():
    parser = parser_for(__doc__)
    parser.set_defaults(category="sqli", exclude_normal=False)
    args = parser.parse_args()
    try:
        run(args)
    except ValueError as exc:
        parser.exit(2, f"Configuration or validation error: {exc}\n")
    except Exception as exc:
        parser.exit(2, f"Run failed ({type(exc).__name__}); inspect configuration and private lab logs.\n")
if __name__ == "__main__":
    main()
