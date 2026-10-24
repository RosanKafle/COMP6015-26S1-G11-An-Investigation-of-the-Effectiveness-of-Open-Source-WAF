"""Check all independent snapshots without contacting configured lab targets."""
from __future__ import annotations
import ast
import csv
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def command(*args: str, expected: int = 0) -> str:
    """Run a non-experimental validation command in a clean environment."""
    env = dict(os.environ)
    for key in ('TARGET_URL', 'MODSECURITY_URL', 'NAXSI_URL', 'LAB_COOKIE',
                'WAF_NAME', 'TIMEOUT', 'DELAY_BETWEEN_REQUESTS', 'ZAP_URL', 'ZAP_API_KEY', 'DVWA_USERNAME', 'DVWA_PASSWORD'):
        env.pop(key, None)
    process = subprocess.run([sys.executable, *args], cwd=ROOT, env=env,
                             capture_output=True, text=True, timeout=30)
    if process.returncode != expected:
        raise AssertionError(f'{args}: expected exit {expected}, got {process.returncode}\n'
                             f'{process.stdout}\n{process.stderr}')
    return process.stdout + process.stderr


def main() -> None:
    syntax_count = 0
    cli_count = 0
    for number in range(1, 8):
        week = ROOT / f'Week_{number:02}'
        for path in week.rglob('*.py'):
            source = path.read_text(encoding='utf-8')
            ast.parse(source, filename=str(path))
            compile(source, str(path), 'exec')
            syntax_count += 1
            if 'if __name__ == "__main__":' in source:
                command(str(path), '--help')
                cli_count += 1
        for path in week.rglob('*.json'):
            json.loads(path.read_text(encoding='utf-8'))
        if number >= 2:
            command(str(week / 'scripts/config_loader.py'))
        if number >= 3:
            command(str(week / 'scripts/test_loader.py'))
            with (week / 'outputs/test_inventory.csv').open(newline='', encoding='utf-8') as handle:
                assert sum(int(r['count']) for r in csv.DictReader(handle)) == 600
        if number >= 4:
            command(str(week / 'scripts/run_test_set.py'), '--category', 'all')
        if number >= 5:
            for waf in ('modsecurity', 'naxsi'):
                command(str(week / 'scripts/run_comparison.py'), '--waf', waf,
                        '--config', str(week / f'config/{waf}.example.json'), '--category', 'all')
        if number >= 6:
            variants = week / 'test_cases/variants/generated_variants.csv'
            if not variants.exists():
                command(str(week / 'scripts/generate_variants.py'))
            command(str(week / 'scripts/test_loader.py'), '--include-variants',
                    '--output', str(week / 'outputs/variant_inventory.csv'))
        if number == 7:
            with tempfile.TemporaryDirectory(prefix='waf_validation_ONLY_') as directory:
                report = Path(directory) / 'must_not_exist.md'
                text = command(str(week / 'analysis/generate_analysis_report.py'),
                               '--output', str(report), expected=2)
                assert 'No real experiment result file was supplied. Analysis cannot be generated.' in text
                assert not report.exists()
        print(f'Week_{number:02}: syntax, available CLIs, configuration and non-executing stages PASS')
    for number in range(2, 8):
        before = ROOT / f'Week_{number-1:02}'
        after = ROOT / f'Week_{number:02}'
        files = [p for p in before.rglob('*') if p.is_file() and '__pycache__' not in p.parts]
        for path in files:
            assert (after / path.relative_to(before)).is_file(), f'Lost inherited file: {path}'
    print(f'PASS: {syntax_count} snapshot Python files; {cli_count} CLI help/import checks; all inherited files retained.')
    print('No configured WAF/DVWA target was contacted. Inventory/variant outputs are input artifacts only.')


if __name__ == '__main__':
    main()
