from __future__ import annotations

import json
from collections.abc import Iterable

from packaging.requirements import InvalidRequirement, Requirement

from .models import ArtifactCoordinate, Ecosystem, LockfileAssessmentRequest
from .utils import normalize_pypi_name

GLOBAL_REQUIREMENTS_OPTIONS = (
    "--extra-index-url",
    "--find-links",
    "--index-url",
    "--no-binary",
    "--no-index",
    "--only-binary",
    "--prefer-binary",
    "--require-hashes",
    "--trusted-host",
)


def parse_lockfile(request: LockfileAssessmentRequest) -> list[ArtifactCoordinate]:
    name = request.lockfile_name.rsplit("/", 1)[-1].lower()
    if name == "package-lock.json":
        coordinates = _parse_package_lock_json(request.content)
    elif _is_requirements_file(name):
        coordinates = _parse_requirements_txt(request.content)
    else:
        raise ValueError(
            "unsupported lockfile type; supported files are requirements*.txt and package-lock.json"
        )
    if not coordinates:
        raise ValueError("lockfile contains no supported pinned dependencies")
    return _dedupe(coordinates)


def _is_requirements_file(name: str) -> bool:
    return name == "requirements.txt" or (name.startswith("requirements") and name.endswith(".txt"))


def _parse_requirements_txt(content: str) -> list[ArtifactCoordinate]:
    coordinates: list[ArtifactCoordinate] = []
    for line_number, raw_line in enumerate(content.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(("-r ", "-r\t", "--requirement", "-c ", "-c\t", "--constraint")):
            raise ValueError(
                f"requirements.txt line {line_number} references another file; submit a fully pinned lockfile"
            )
        if line.startswith(GLOBAL_REQUIREMENTS_OPTIONS):
            continue
        if line.startswith("-"):
            raise ValueError(f"requirements.txt line {line_number} uses an unsupported pip option")

        requirement_text = _strip_requirement_options(_strip_inline_comment(line))
        if not requirement_text:
            continue
        try:
            requirement = Requirement(requirement_text)
        except InvalidRequirement as exc:
            raise ValueError(f"requirements.txt line {line_number} is not a supported requirement") from exc

        exact_versions = [
            spec.version
            for spec in requirement.specifier
            if spec.operator == "==" and not spec.version.endswith(".*")
        ]
        if len(exact_versions) != 1:
            raise ValueError(f"requirements.txt line {line_number} must pin exactly one version with ==")
        coordinates.append(
            ArtifactCoordinate(
                ecosystem=Ecosystem.pypi,
                name=normalize_pypi_name(requirement.name),
                version=exact_versions[0],
            )
        )
    return coordinates


def _strip_inline_comment(line: str) -> str:
    if " #" in line:
        return line.split(" #", 1)[0].strip()
    return line


def _strip_requirement_options(line: str) -> str:
    for token in (" --hash=",):
        if token in line:
            return line.split(token, 1)[0].strip()
    return line


def _parse_package_lock_json(content: str) -> list[ArtifactCoordinate]:
    try:
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ValueError("package-lock.json is not valid JSON") from exc
    if not isinstance(data, dict):
        raise ValueError("package-lock.json root must be an object")

    coordinates: list[ArtifactCoordinate] = []
    packages = data.get("packages")
    if isinstance(packages, dict):
        for path, metadata in packages.items():
            if not isinstance(path, str) or not path:
                continue
            if not isinstance(metadata, dict):
                continue
            if metadata.get("link") is True:
                continue
            if "node_modules/" not in path:
                continue
            package_name = path.rsplit("node_modules/", 1)[-1]
            _append_npm_coordinate(coordinates, package_name, metadata.get("version"))

    dependencies = data.get("dependencies")
    if isinstance(dependencies, dict):
        for package_name, metadata in _walk_package_lock_dependencies(dependencies):
            _append_npm_coordinate(coordinates, package_name, metadata.get("version"))

    return coordinates


def _walk_package_lock_dependencies(dependencies: dict) -> Iterable[tuple[str, dict]]:
    for package_name, metadata in dependencies.items():
        if not isinstance(package_name, str) or not isinstance(metadata, dict):
            continue
        yield package_name, metadata
        children = metadata.get("dependencies")
        if isinstance(children, dict):
            yield from _walk_package_lock_dependencies(children)


def _append_npm_coordinate(coordinates: list[ArtifactCoordinate], name: str, version: object) -> None:
    if not isinstance(version, str) or not version:
        return
    if version.startswith(("file:", "git+", "http://", "https://", "link:")):
        raise ValueError(f"package-lock.json contains unsupported non-registry dependency {name}@{version}")
    coordinates.append(ArtifactCoordinate(ecosystem=Ecosystem.npm, name=name.lower(), version=version))


def _dedupe(coordinates: list[ArtifactCoordinate]) -> list[ArtifactCoordinate]:
    seen: set[tuple[str, str, str]] = set()
    unique: list[ArtifactCoordinate] = []
    for coordinate in coordinates:
        key = (
            coordinate.ecosystem.value,
            (coordinate.name or coordinate.project or "").lower(),
            coordinate.version or "",
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(coordinate)
    return unique
