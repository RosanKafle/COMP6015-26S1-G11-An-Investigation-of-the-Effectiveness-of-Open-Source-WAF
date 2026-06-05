# Framework Source

This package contains the executable Python framework.

- `experiment_runner.py` is the main entry point for experiment runs.
- `attack_modules.py` defines generated malicious request traffic.
- `traffic_generator.py` defines benign traffic generation.
- `data_logger.py` writes raw request-level evidence.
- `summary_writer.py` creates per-run summaries.
- `output_manager.py` manages structured output folders.
- `zap_controller.py` integrates with OWASP ZAP.
- `config.py` stores environment and target configuration.

Run from the repository root with `python3 -m framework.experiment_runner`.
