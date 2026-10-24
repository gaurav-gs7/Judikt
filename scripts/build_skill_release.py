from __future__ import annotations

import argparse
import json
import re
import tomllib
import zipfile
from pathlib import Path, PurePosixPath


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SKILL_ROOT = PROJECT_ROOT / "skills" / "judikt-mcp-security"
DEFAULT_PYPROJECT = PROJECT_ROOT / "pyproject.toml"
ALLOWED_TOP_LEVEL = {"SKILL.md", "agents", "assets", "references", "scripts"}
VERSION_TOKEN = "__JUDIKT_VERSION__"
LINK_PATTERN = re.compile(r"\[[^]]*]\(([^)]+)\)")
SKILL_NAME_PATTERN = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


class SkillReleaseError(ValueError):
    pass


def project_version(pyproject: Path) -> str:
    document = tomllib.loads(pyproject.read_text())
    version = document.get("project", {}).get("version")
    if not isinstance(version, str) or not version.strip():
        raise SkillReleaseError("pyproject.toml is missing project.version")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]*", version):
        raise SkillReleaseError(f"project.version is not safe for an artifact name: {version}")
    return version


def validate_skill(skill_root: Path) -> tuple[str, list[Path]]:
    skill_file = skill_root / "SKILL.md"
    if not skill_file.is_file():
        raise SkillReleaseError(f"skill is missing SKILL.md: {skill_root}")
    metadata = _frontmatter(skill_file.read_text())
    name = metadata.get("name", "")
    description = metadata.get("description", "")
    if not SKILL_NAME_PATTERN.fullmatch(name) or len(name) > 64:
        raise SkillReleaseError("skill name must be lowercase hyphen-case and at most 64 characters")
    if skill_root.name != name:
        raise SkillReleaseError(
            f"skill folder {skill_root.name!r} does not match metadata name {name!r}"
        )
    if not description:
        raise SkillReleaseError("skill metadata requires a non-empty description")

    files: list[Path] = []
    for path in sorted(skill_root.rglob("*")):
        if path.is_symlink():
            raise SkillReleaseError(f"skill packages cannot contain symlinks: {path}")
        if not path.is_file():
            continue
        relative = path.relative_to(skill_root)
        if relative.parts[0] not in ALLOWED_TOP_LEVEL:
            raise SkillReleaseError(f"unexpected top-level skill content: {relative}")
        if any(part == "__pycache__" or part.startswith(".") for part in relative.parts):
            raise SkillReleaseError(f"generated or hidden skill content is not allowed: {relative}")
        if path.suffix in {".pyc", ".pyo"}:
            raise SkillReleaseError(f"compiled Python is not allowed in the skill: {relative}")
        files.append(path)

    for markdown in (path for path in files if path.suffix.lower() == ".md"):
        for target in LINK_PATTERN.findall(markdown.read_text()):
            if target.startswith(("http://", "https://", "#")):
                continue
            link = target.split("#", 1)[0]
            resolved = (markdown.parent / link).resolve()
            try:
                resolved.relative_to(skill_root.resolve())
            except ValueError as exc:
                raise SkillReleaseError(
                    f"reference escapes the skill directory: {markdown}: {target}"
                ) from exc
            if not resolved.exists():
                raise SkillReleaseError(f"broken skill reference: {markdown}: {target}")
    return name, files


def build_skill_release(
    *,
    skill_root: Path = DEFAULT_SKILL_ROOT,
    pyproject: Path = DEFAULT_PYPROJECT,
    output_dir: Path,
    release_tag: str = "",
) -> Path:
    version = project_version(pyproject)
    expected_tag = f"v{version}"
    if release_tag and release_tag != expected_tag:
        raise SkillReleaseError(
            f"release tag {release_tag!r} does not match runtime version {expected_tag!r}"
        )
    name, files = validate_skill(skill_root)
    output_dir.mkdir(parents=True, exist_ok=True)
    artifact = output_dir / f"{name}-v{version}.zip"
    with zipfile.ZipFile(artifact, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for source in files:
            relative = source.relative_to(skill_root)
            archived = PurePosixPath(name, *relative.parts).as_posix()
            info = zipfile.ZipInfo(archived, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (0o755 if source.stat().st_mode & 0o111 else 0o644) << 16
            archive.writestr(info, stamp_version(source, version))
    return artifact


def stamp_version(source: Path, version: str) -> bytes:
    """Return a skill file's bytes with the runtime version filled in.

    Markdown references carry the VERSION_TOKEN placeholder so a released skill
    tells agents to install exactly the runtime it was built and tested with.
    """
    data = source.read_bytes()
    if source.suffix == ".md":
        data = data.replace(VERSION_TOKEN.encode(), version.encode())
    return data


def _frontmatter(text: str) -> dict[str, str]:
    if not text.startswith("---\n"):
        raise SkillReleaseError("SKILL.md must begin with YAML frontmatter")
    try:
        raw, _body = text[4:].split("\n---\n", 1)
    except ValueError as exc:
        raise SkillReleaseError("SKILL.md frontmatter is not terminated") from exc
    metadata: dict[str, str] = {}
    for line in raw.splitlines():
        key, separator, value = line.partition(":")
        if not separator or not key.strip() or not value.strip():
            raise SkillReleaseError(f"unsupported SKILL.md metadata line: {line!r}")
        key = key.strip()
        if key in metadata:
            raise SkillReleaseError(f"duplicate SKILL.md metadata key: {key}")
        metadata[key] = value.strip()
    if set(metadata) != {"name", "description"}:
        raise SkillReleaseError("SKILL.md metadata must contain only name and description")
    return metadata


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Validate and build the Judikt skill ZIP at the runtime version."
    )
    parser.add_argument("--skill-root", type=Path, default=DEFAULT_SKILL_ROOT)
    parser.add_argument("--pyproject", type=Path, default=DEFAULT_PYPROJECT)
    parser.add_argument("--output-dir", type=Path, default=PROJECT_ROOT / "dist")
    parser.add_argument("--release-tag", default="")
    args = parser.parse_args()
    try:
        artifact = build_skill_release(
            skill_root=args.skill_root,
            pyproject=args.pyproject,
            output_dir=args.output_dir,
            release_tag=args.release_tag,
        )
    except (OSError, SkillReleaseError, tomllib.TOMLDecodeError) as exc:
        raise SystemExit(f"skill release validation failed: {exc}") from exc
    print(
        json.dumps(
            {
                "artifact": str(artifact),
                "runtime_version": project_version(args.pyproject),
                "skill": args.skill_root.name,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
