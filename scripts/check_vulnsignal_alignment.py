#!/usr/bin/env python3
"""Fail current VulnSignal docs/assets that drift into vague ML detector framing."""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

CHECK_PATHS = [
    ROOT / "README.md",
    ROOT / "DOCUMENT_INDEX.md",
    ROOT / "docs" / "PROPOSAL.md",
    ROOT / "docs" / "slides",
    ROOT / "docs" / "project" / "VULNSIGNAL_ARCHITECTURE.md",
    ROOT / "docs" / "project" / "VULNSIGNAL_DATASET_STRATEGY.md",
    ROOT / "docs" / "project" / "VULNSIGNAL_MODEL_STRATEGY.md",
    ROOT / "docs" / "project" / "VULNSIGNAL_VISION.md",
    ROOT / "diagrams",
]

SKIP_PARTS = {
    ".git",
    "venv",
    ".venv",
    "__pycache__",
    "rejected",
}

REQUIRED_README_PHRASES = [
    "tool-grounded vulnerability candidate-ranking framework",
    "(task_instance, candidate_location)",
    "It does not claim final vulnerability truth from model output alone.",
]

FORBIDDEN_TEXT = [
    (re.compile(r"\bSPDL\b|Security Protocol Delta Learning", re.I), "stale SPDL/delta project naming"),
    (re.compile(r"\bSML\b|\bSLM\b", re.I), "ambiguous SML/SLM model framing"),
    (
        re.compile(r"\bgeneric vulnerable\s*/\s*non-vulnerable classifier\b", re.I),
        "use the approved negative wording: no generic vulnerable/non-vulnerable classifier",
    ),
    (
        re.compile(r"\bvulnerability detection project\b", re.I),
        "vague vulnerability-detection-project framing",
    ),
    (
        re.compile(r"\bsmall model\s*/\s*SLM\b", re.I),
        "small-model/SLM framing",
    ),
    (
        re.compile(r"\bFinal Finding Object\b", re.I),
        "model-to-final-finding framing",
    ),
]

ALLOWED_NEGATIVE_PHRASES = [
    "No generic vulnerable / non-vulnerable classifier",
    "Do not frame the model as a generic vulnerable / non-vulnerable classifier",
    "not vulnerable/non-vulnerable classification",
    "Rejected shape: single code segment -> vulnerable/non-vulnerable.",
    "No collapse into generic vulnerable/non-vulnerable labels",
    "Never merge strong, conditional, weak, and UNKNOWN into one vague vulnerable label.",
]


def iter_files(paths: list[Path]) -> list[Path]:
    files: list[Path] = []
    for path in paths:
        if not path.exists():
            continue
        if path.is_file():
            files.append(path)
            continue
        for child in path.rglob("*"):
            if child.is_file() and not (set(child.relative_to(ROOT).parts) & SKIP_PARTS):
                files.append(child)
    return sorted(files)


def is_text(path: Path) -> bool:
    return path.suffix.lower() in {".md", ".html", ".mmd", ".txt"}


def allowed_negative_line(line: str) -> bool:
    lower_line = line.lower()
    return any(phrase.lower() in lower_line for phrase in ALLOWED_NEGATIVE_PHRASES)


def main() -> int:
    failures: list[str] = []

    readme = ROOT / "README.md"
    readme_text = readme.read_text(encoding="utf-8")
    for phrase in REQUIRED_README_PHRASES:
        if phrase not in readme_text:
            failures.append(f"README.md missing required VulnSignal phrase: {phrase}")

    for path in iter_files(CHECK_PATHS):
        rel = path.relative_to(ROOT)
        if path.name.startswith("Data Structure & Algorithms I - Source Code Representation ML"):
            failures.append(f"{rel}: stale ML diagram filename; use VulnSignal contract naming")
        if not is_text(path):
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for lineno, line in enumerate(text.splitlines(), start=1):
            for pattern, reason in FORBIDDEN_TEXT:
                if pattern.search(line) and not allowed_negative_line(line):
                    failures.append(f"{rel}:{lineno}: {reason}: {line.strip()}")

    if failures:
        print("VulnSignal alignment gate failed:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1

    print("VulnSignal alignment gate passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
