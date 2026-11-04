"""Cross-check docs/ACCEPTANCE_MATRIX.md against the test suite.

Every row must be ``pass``, and every test named in the Test column must exist in pytest's
collection. With ``--run``, the named tests are also executed (slow ones included), so the
matrix can't claim a pass the suite doesn't deliver.

Usage: ``uv run python scripts/check_matrix.py [--run]`` - exits non-zero on any mismatch.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MATRIX = ROOT / "docs" / "ACCEPTANCE_MATRIX.md"
TEST_NAME = re.compile(r"`(test_\w+)")


def matrix_rows() -> list[tuple[int, list[str], str]]:
    """(line number, test names in the Test column, status) for every table body row."""
    rows = []
    for lineno, line in enumerate(MATRIX.read_text(encoding="utf-8").splitlines(), 1):
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if not line.startswith("|") or len(cells) < 3 or cells[0] in ("Criterion", "---"):
            continue
        rows.append((lineno, TEST_NAME.findall(cells[1]), cells[-1].lower()))
    return rows


def collected() -> dict[str, list[str]]:
    """Test function name -> node ids (parametrized cases share one name)."""
    out = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", "-m", ""],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    ).stdout
    nodes: dict[str, list[str]] = {}
    for line in out.splitlines():
        if "::" in line:
            name = line.split("::")[-1].split("[")[0]
            nodes.setdefault(name, []).append(line.strip())
    return nodes


def main() -> int:
    rows = matrix_rows()
    nodes = collected()
    problems: list[str] = []
    named: set[str] = set()
    for lineno, tests, status in rows:
        if status != "pass":
            problems.append(f"line {lineno}: status is {status!r}")
        if not tests:
            problems.append(f"line {lineno}: no test named")
        for test in tests:
            named.add(test)
            if test not in nodes:
                problems.append(f"line {lineno}: {test} is not collected by pytest")
    print(
        f"{len(rows)} rows, {len(named)} distinct tests named, "
        f"{len(nodes)} test functions collected"
    )

    if not problems and "--run" in sys.argv:
        ids = [node for test in sorted(named) for node in nodes[test]]
        result = subprocess.run(  # noqa: S603 - node ids come from our own pytest collection
            [sys.executable, "-m", "pytest", "-q", "-m", "", *ids],
            cwd=ROOT,
            check=False,
        )
        if result.returncode != 0:
            problems.append("some matrix tests failed (see pytest output above)")

    for problem in problems:
        print("MISMATCH:", problem)
    if not problems:
        print("matrix OK")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
