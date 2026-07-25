from __future__ import annotations

from pathlib import Path

from harness.probes import prysm_forkchoice_dos as probe

_SAMPLE_OUTPUT = """\
=== RUN   TestCHKAS03_ForkchoiceUnboundedTreeQuadratic
    prysm_forkchoice_dos_test.go:94: STALLED  (no prune): visits 501500->2003000 on 2x chain  ratio=3.99x  (O(n^2) => ~4x)
    prysm_forkchoice_dos_test.go:96: STALLED  final tree NodeCount=2001 (== chain length; unbounded)
    prysm_forkchoice_dos_test.go:97: STALLED  cumulative Head() wall: 409ms vs 94ms
    prysm_forkchoice_dos_test.go:109: HEALTHY  (prune):  final NodeCount=81 (bounded), cumulative visits 157880 (7.9% of stalled)
--- PASS: TestCHKAS03_ForkchoiceUnboundedTreeQuadratic (16.54s)
PASS
ok  \tgithub.com/OffchainLabs/prysm/v7/beacon-chain/forkchoice/doubly-linked-tree\t16.5s
"""


def test_regexes_parse_the_ab_result():
    ms = probe.STALLED_RE.search(_SAMPLE_OUTPUT)
    assert ms and float(ms.group(3)) == 3.99
    mn = probe.STALLED_NODES_RE.search(_SAMPLE_OUTPUT)
    assert mn and int(mn.group(1)) == 2001
    mh = probe.HEALTHY_RE.search(_SAMPLE_OUTPUT)
    assert mh and int(mh.group(1)) == 81 and float(mh.group(3)) == 7.9


def test_module_path_rewrite_matches_checkout(tmp_path):
    (tmp_path / "go.mod").write_text("module github.com/OffchainLabs/prysm/v9\n\ngo 1.26\n")
    assert probe._module_path(tmp_path) == "github.com/OffchainLabs/prysm/v9"


def test_ensure_test_installed_rewrites_module_version(tmp_path):
    pkg = tmp_path / probe.PKG_REL
    pkg.mkdir(parents=True)
    (tmp_path / "go.mod").write_text("module github.com/OffchainLabs/prysm/v9\n")
    dst = probe.ensure_test_installed(tmp_path)
    assert dst.exists()
    body = dst.read_text()
    assert "prysm/v9" in body
    assert "prysm/v7" not in body


def test_the_go_test_file_ships_with_the_probe():
    assert (Path(probe.__file__).with_name(probe.TEST_FILE)).exists()


def test_ensure_test_installed_rejects_non_prysm_dir(tmp_path):
    import pytest
    with pytest.raises(FileNotFoundError):
        probe.ensure_test_installed(tmp_path)
