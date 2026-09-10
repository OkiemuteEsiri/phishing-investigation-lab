from __future__ import annotations

import argparse
from pathlib import Path

from .analyzer import analyze
from .io import load_messages
from .reporting import render_markdown


def main() -> int:
    parser = argparse.ArgumentParser(description="Assess synthetic phishing-investigation evidence")
    parser.add_argument("input", help="Path to synthetic message JSON")
    parser.add_argument("--output", default="reports/generated-report.md", help="Markdown report path")
    args = parser.parse_args()

    messages = load_messages(args.input)
    findings = [analyze(message) for message in messages]
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(render_markdown(findings), encoding="utf-8")
    print(f"Assessed {len(findings)} messages; report written to {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
