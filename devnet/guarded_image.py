"""Guarded-image builder — applies a guard.diff patch to a client source tree
and builds a Docker image for the negative-control (E) variant.

This bridges the gap between the harness ``negative_control`` spec (which
references a source diff) and the Kurtosis backend (which needs a prebuilt
Docker image tag). The builder:

1. clones the client repository at a known commit (or HEAD),
2. applies the guard diff,
3. builds the Docker image with the client's own Dockerfile,
4. tags it, and
5. returns the tag for use as ``variant_images[Variant.GUARDED][client]``.

The builder is client-agnostic: it looks up the clone URL and Dockerfile path
per client. Currently supports grandine (the track-a target); adding another
client is a one-entry addition to ``CLIENT_REPOS``.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ClientRepo:
    """Where to clone a client and how to build its image."""

    git_url: str
    dockerfile: str = "Dockerfile"      # relative to repo root
    build_context: str = "."            # relative to repo root


CLIENT_REPOS: dict[str, ClientRepo] = {
    "grandine": ClientRepo(
        git_url="https://github.com/grandinetech/grandine.git",
        dockerfile="Dockerfile",
        build_context=".",
    ),
}


class GuardedImageBuildError(RuntimeError):
    """Raised when the guarded image build fails."""


def build_guarded_image(
    client: str,
    guard_diff: str | Path,
    *,
    tag: str | None = None,
    workdir: str | Path | None = None,
    commit: str = "HEAD",
    no_cache: bool = False,
) -> str:
    """Build a Docker image with ``guard_diff`` applied to the client source.

    Args:
        client:      client name (e.g. ``"grandine"``).
        guard_diff:  path to the ``guard.diff`` file.
        tag:         Docker image tag; defaults to ``{client}:guarded``.
        workdir:     scratch directory for the clone; defaults to a temp dir.
        commit:      git ref to check out before applying the patch.
        no_cache:    pass ``--no-cache`` to ``docker build``.

    Returns:
        The Docker image tag (e.g. ``"grandine:guarded"``).
    """
    repo_info = CLIENT_REPOS.get(client)
    if repo_info is None:
        raise GuardedImageBuildError(
            f"no repo config for client {client!r}; known: {sorted(CLIENT_REPOS)}"
        )

    guard_path = Path(guard_diff)
    if not guard_path.exists():
        raise GuardedImageBuildError(f"guard diff not found: {guard_path}")

    if tag is None:
        tag = f"{client}:guarded"

    if workdir is None:
        workdir = tempfile.mkdtemp(prefix=f"guarded-{client}-")
    work = Path(workdir)
    clone_dir = work / client

    _run(["git", "clone", "--depth=1", repo_info.git_url, str(clone_dir)])
    if commit != "HEAD":
        _run(["git", "fetch", "--depth=1", "origin", commit], cwd=clone_dir)
        _run(["git", "checkout", commit], cwd=clone_dir)

    # Apply the guard patch.
    _run(["git", "apply", str(guard_path.resolve())], cwd=clone_dir)

    # Build the Docker image.
    dockerfile = clone_dir / repo_info.dockerfile
    context = clone_dir / repo_info.build_context
    cmd = [
        "docker", "build",
        "-t", tag,
        "-f", str(dockerfile),
    ]
    if no_cache:
        cmd.append("--no-cache")
    cmd.append(str(context))
    _run(cmd)

    return tag


def _run(cmd: list[str], *, cwd: Path | None = None, check: bool = True) -> subprocess.CompletedProcess:
    proc = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd)
    if check and proc.returncode != 0:
        raise GuardedImageBuildError(
            f"{' '.join(cmd)} failed: {proc.stderr.strip()[:500] or proc.stdout.strip()[:500]}"
        )
    return proc