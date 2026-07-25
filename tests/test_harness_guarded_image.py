"""Guarded-image builder tests — offline, mocks docker + git.

Verifies that build_guarded_image:
- clones the repo, applies the patch, and builds the image
- passes the correct tag
- raises on unknown client
- raises on missing guard diff
"""
from __future__ import annotations

import pytest

from harness.devnet import guarded_image


def test_build_guarded_image_unknown_client():
    with pytest.raises(guarded_image.GuardedImageBuildError, match="no repo config"):
        guarded_image.build_guarded_image("unknownclient", "/dev/null")


def test_build_guarded_image_missing_diff(tmp_path):
    with pytest.raises(guarded_image.GuardedImageBuildError, match="guard diff not found"):
        guarded_image.build_guarded_image("grandine", tmp_path / "nonexistent.diff")


def test_build_guarded_image_builds_and_tags(monkeypatch, tmp_path):
    calls = []

    def fake_run(cmd, *, cwd=None, check=True, **kwargs):
        calls.append((cmd, cwd))

        class Done:
            returncode = 0
            stdout = ""
            stderr = ""

        return Done()

    monkeypatch.setattr(guarded_image.subprocess, "run", fake_run)
    monkeypatch.setattr(guarded_image.tempfile, "mkdtemp", lambda **kw: str(tmp_path))

    guard = tmp_path / "guard.diff"
    guard.write_text("--- a\n+++ b\n", encoding="utf-8")

    tag = guarded_image.build_guarded_image("grandine", guard, tag="grandine:test")

    assert tag == "grandine:test"
    # Should have: git clone, git apply, docker build
    cmd_strs = [" ".join(c[0]) for c in calls]
    assert any("git clone" in s for s in cmd_strs)
    assert any("git apply" in s for s in cmd_strs)
    assert any("docker build" in s for s in cmd_strs)
    # The docker build should include our tag
    build_call = [c for c in calls if c[0][0] == "docker" and c[0][1] == "build"]
    assert build_call
    assert "grandine:test" in build_call[0][0]


def test_build_guarded_image_default_tag(monkeypatch, tmp_path):
    calls = []

    def fake_run(cmd, *, cwd=None, check=True, **kwargs):
        calls.append(cmd)

        class Done:
            returncode = 0
            stdout = ""
            stderr = ""

        return Done()

    monkeypatch.setattr(guarded_image.subprocess, "run", fake_run)
    monkeypatch.setattr(guarded_image.tempfile, "mkdtemp", lambda **kw: str(tmp_path))

    guard = tmp_path / "guard.diff"
    guard.write_text("--- a\n+++ b\n", encoding="utf-8")

    tag = guarded_image.build_guarded_image("grandine", guard)

    assert tag == "grandine:guarded"
    build_call = [c for c in calls if c[0] == "docker" and c[1] == "build"]
    assert "grandine:guarded" in build_call[0]