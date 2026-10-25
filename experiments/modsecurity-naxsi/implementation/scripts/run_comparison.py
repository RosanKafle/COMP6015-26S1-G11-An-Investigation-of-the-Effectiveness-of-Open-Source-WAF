"""Run the same selected corpus under a named WAF condition."""
import logging
from config_loader import load_config
from run_test_set import parser_for, run

def main() -> None:
    parser = parser_for(__doc__)
    parser.add_argument("--waf", required=True, choices=("modsecurity", "naxsi"))
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    try:
        config = load_config(args.config, args.env_file)
        if config.waf_name != args.waf:
            raise ValueError("--waf disagrees with the effective configuration.")
        run(args)
    except (ValueError, OSError, TypeError) as exc:
        parser.exit(2, f"Comparison run failed: {exc}\n")

if __name__ == "__main__":
    main()
