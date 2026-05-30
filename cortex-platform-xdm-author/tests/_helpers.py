# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Shared loaders for the bundle integrity test suite.

Locates the bundle root by walking upward from this file looking for
``SKILL.md``. Lets the test suite run from any working directory and
from any install path the bundle is copied to.
"""

from __future__ import annotations

import json
from pathlib import Path


def bundle_root() -> Path:
    """Walk upward from this file to find the bundle root (the dir
    containing ``SKILL.md``). Raises FileNotFoundError if the bundle is
    malformed."""
    here = Path(__file__).resolve().parent
    for candidate in (here, *here.parents):
        if (candidate / "SKILL.md").is_file():
            return candidate
    raise FileNotFoundError(
        f"Could not locate bundle root (no SKILL.md in {here} or ancestors)"
    )


def read_text(rel_path: str) -> str:
    """Read a UTF-8 text file relative to the bundle root."""
    return (bundle_root() / rel_path).read_text(encoding="utf-8")


def read_json(rel_path: str):
    """Parse a JSON file relative to the bundle root."""
    return json.loads(read_text(rel_path))


def iter_reference_md_files():
    """Yield every Path under ``references/`` ending in ``.md`` (recursive)."""
    refs = bundle_root() / "references"
    if not refs.is_dir():
        return
    for p in sorted(refs.rglob("*.md")):
        yield p


def iter_source_files():
    """Yield every ``.md`` / ``.py`` / ``.xql`` Path in the bundle.
    Excludes ``LICENSE`` and anything inside ``tests/`` itself (the
    tests can carry their own SPDX hygiene check separately if
    needed)."""
    root = bundle_root()
    skip_dirs = {root / "tests"}
    for ext in ("*.md", "*.py", "*.xql"):
        for p in sorted(root.rglob(ext)):
            if any(str(p).startswith(str(d)) for d in skip_dirs):
                continue
            yield p
