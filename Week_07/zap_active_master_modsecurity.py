"""Continuation of the inherited ZAP spider and active-scanner pipeline."""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent / "scripts"))
from zap_active_pipeline import main
if __name__ == "__main__":
    main()
