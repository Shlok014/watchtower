#!/usr/bin/env python3
"""Fail the build if fabricated values, or retired overclaiming names, come back.

The project's whole premise is that it does not invent numbers. Randomness is
legitimate when producing explicitly labelled synthetic *input data*: the
demo source, threat-feed sampling for demo addresses, and seeded evaluation
scenario generators. It must never perturb measured detector scores or
reported outcomes.

This is a script rather than a shell one-liner in the CI file because both
halves of the original one-liner were wrong in ways only a real run would show:

1. ``grep -rn ... .`` prefixes paths with ``./`` under GNU grep and not under
   BSD grep, so an anchored ``grep -v "^./app.py"`` allowlist silently stops
   matching depending on which runner executes it.

2. Far more seriously, a plain substring search for the retired names flags the
   sentences that *retire* them. "There is no proof-of-work, and it is not
   Hyperledger" and "it used to be ``random.uniform(-0.04, 0.04)``" are the
   honesty story, not violations of it. Run as written, that check failed on
   six lines of the repository's own explanation.

So the two rules are scoped to what they actually protect:

  random.*        code only, comments and docstrings stripped by ``tokenize``.
  retired names   anything the *running program* can emit — code and string
                  literals in Python and JSX — plus, in prose, only mentions
                  shaped like a claim ("built on X", "powered by X"). Prose is
                  free to name what was removed; it is not free to re-adopt it.

    python scripts/check_no_fabrication.py [--root .]
"""

from __future__ import annotations

import argparse
import io
import re
import sys
import tokenize
from pathlib import Path

# Files permitted to call random.* for input generation, and why.
RANDOM_ALLOWED = {
    "backend/watchtower/sources/synthetic.py": "the synthetic generator — it produces input data",
    "backend/watchtower/threatintel/pool.py": "samples the real cached feed for demo addresses",
    "backend/eval/live.py": "seeded, labelled synthetic feature scenarios only",
    "backend/eval/live_pipeline.py": "seeded, labelled synthetic raw-event scenarios only",
}

RANDOM_CALL = re.compile(r"\brandom\s*\.\s*[A-Za-z_]+\s*\(")

# Names the project has committed to not using.
RETIRED = r"hyperledger|loglm|iris[-_ ]?soc"
RETIRED_NAMES = re.compile(RETIRED, re.IGNORECASE)

# In prose, only a claim counts. A negation or a historical note is the point of
# the honesty table and must stay legal.
CLAIM_SHAPED = re.compile(
    r"(?:built (?:on|with|using)|powered by|backed by|running on|runs on|uses?|using|"
    r"based on|implemented (?:in|with|using)|integrat\w+ with)\s+[^.\n]{0,24}?(" + RETIRED + r")",
    re.IGNORECASE,
)

# This script and the CI file that calls it are the two places whose job is to
# say the words. Skipping them is not a loophole.
SELF = {"scripts/check_no_fabrication.py", ".github/workflows/ci.yml"}

SKIP_DIRS = {
    ".git",
    ".venv",
    "node_modules",
    "dist",
    "data",
    "__pycache__",
    ".ruff_cache",
    ".pytest_cache",
    "coverage",
}

CODE_SUFFIXES = {".py", ".jsx", ".js"}
PROSE_SUFFIXES = {".md", ".yml", ".yaml", ".html", ".sql", ".txt"}

JS_COMMENT = re.compile(r"//[^\n]*|/\*.*?\*/", re.DOTALL)


def strip_python_comments(source: str) -> str:
    """Blank comments and bare string-expression docstrings, preserving line numbers."""
    lines = source.splitlines()
    blanked = list(lines)
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(source).readline))
    except (tokenize.TokenError, IndentationError, SyntaxError):
        # Unparseable: fall back to the raw text rather than passing it silently.
        return source

    prev = tokenize.INDENT
    for tok in tokens:
        is_docstring = tok.type == tokenize.STRING and prev in (
            tokenize.NEWLINE,
            tokenize.NL,
            tokenize.INDENT,
            tokenize.DEDENT,
        )
        if tok.type == tokenize.COMMENT or is_docstring:
            (srow, scol), (erow, ecol) = tok.start, tok.end
            for row in range(srow, erow + 1):
                i = row - 1
                if i >= len(blanked):
                    continue
                start = scol if row == srow else 0
                end = ecol if row == erow else len(blanked[i])
                blanked[i] = blanked[i][:start] + " " * (end - start) + blanked[i][end:]
        if tok.type != tokenize.COMMENT:
            prev = tok.type
    return "\n".join(blanked)


def strip_js_comments(source: str) -> str:
    """Blank // and /* */ comments, preserving line count."""

    def blank(m: re.Match) -> str:
        return re.sub(r"[^\n]", " ", m.group(0))

    return JS_COMMENT.sub(blank, source)


def iter_files(root: Path):
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if path.suffix not in CODE_SUFFIXES | PROSE_SUFFIXES:
            continue
        if any(part in SKIP_DIRS for part in path.relative_to(root).parts):
            continue
        yield path


def check(root: Path) -> list[str]:
    findings: list[str] = []
    for path in iter_files(root):
        rel = path.relative_to(root).as_posix()
        if rel in SELF:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:  # pragma: no cover - unreadable file
            findings.append(f"{rel}: could not read ({exc})")
            continue

        is_test = "/tests/" in f"/{rel}"

        if path.suffix == ".py":
            code = strip_python_comments(text)
            if rel not in RANDOM_ALLOWED and not is_test:
                for n, line in enumerate(code.splitlines(), 1):
                    if RANDOM_CALL.search(line):
                        findings.append(
                            f"{rel}:{n}: random.* called outside an approved synthetic input generator "
                            f"— {line.strip()}"
                        )
        elif path.suffix in CODE_SUFFIXES:
            code = strip_js_comments(text)
        else:
            code = None

        if code is not None and not is_test:
            for n, line in enumerate(code.splitlines(), 1):
                m = RETIRED_NAMES.search(line)
                if m:
                    findings.append(
                        f"{rel}:{n}: retired name {m.group(0)!r} in code — {line.strip()[:100]}"
                    )
        else:
            for n, line in enumerate(text.splitlines(), 1):
                m = CLAIM_SHAPED.search(line)
                if m:
                    findings.append(
                        f"{rel}:{n}: prose claims {m.group(1)!r} — {line.strip()[:100]}"
                    )
    return findings


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Honesty gate for the Watchtower repository.")
    ap.add_argument("--root", default=".", help="repository root to scan")
    args = ap.parse_args(argv)

    findings = check(Path(args.root).resolve())
    if findings:
        print(f"❌ {len(findings)} finding(s):\n", file=sys.stderr)
        for f in findings:
            print(f"  {f}", file=sys.stderr)
        print(
            "\nRandomness is allowed only in:\n"
            + "\n".join(f"  {k} — {v}" for k, v in RANDOM_ALLOWED.items()),
            file=sys.stderr,
        )
        return 1
    print("✅ no fabricated values, no retired names in code, no retired claims in prose.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
