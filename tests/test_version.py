from __future__ import annotations

import tomllib
from pathlib import Path

from palsy import __version__
from palsy.api import app


def test_versions_match_project_metadata():
    project = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))["project"]

    assert project["version"] == __version__
    assert app.version == __version__
