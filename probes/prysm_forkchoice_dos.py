"""Deterministic, in-process reproduction of CHK-AS-03 (prysm).

The finding: prysm's doubly-linked-tree fork choice runs six recursive tree
walks with no depth/size cap (only ctx.Err()); ForkChoice.Head() traverses the
whole tree twice per slot (applyWeightChangesConsensusNode +
updateBestDescendantConsensusNode from treeRootNode). When finality stalls the
tree is never pruned, so per-slot cost grows with the tree — O(n) per Head,
O(n^2) cumulative — a CPU-DoS an attacker with >=1/3 of validators can drive.

Like the grandine gap-index probe, this needs no live devnet: it installs a Go
test into prysm's own fork-choice package and drives the *real* recursion. The
work metric is exact and deterministic — the number of nodes each Head() visits
is precisely f.NodeCount() — so the O(n^2) result is not a timing artifact.

Obligations proven by ``prysm_forkchoice_dos_test.go``:
- (3) baseline symptom: with finality stalled (no prune), doubling the chain
  ~quadruples cumulative recursion work (ratio -> ~4x) and the tree is unbounded.
- (2) causation: prysm's own prune() (finality advancing) re-roots and bounds the
  tree, collapsing cumulative work to a linear fraction — the guard removes
  exactly the blowup. guard.diff adds an explicit MAX_NODES cap as in-code
  defense-in-depth for the stalled case.

Usage:
    python -m harness.probes.prysm_forkchoice_dos --prysm-dir /path/to/prysm

Requirements: a prysm checkout (module github.com/OffchainLabs/prysm/vN) and the
Go toolchain. The fork-choice package builds standalone with `go test`.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

TEST_FILE = "prysm_forkchoice_dos_test.go"
TEST_NAME = "TestCHKAS03_ForkchoiceUnboundedTreeQuadratic"
PKG_REL = "beacon-chain/forkchoice/doubly-linked-tree"

STALLED_RE = re.compile(r"STALLED.*visits (\d+)->(\d+) on 2x chain\s+ratio=([\d.]+)x")
STALLED_NODES_RE = re.compile(r"STALLED\s+final tree NodeCount=(\d+)")
HEALTHY_RE = re.compile(r"HEALTHY.*final NodeCount=(\d+) \(bounded\), cumulative visits (\d+) \(([\d.]+)% of stalled\)")


@dataclass
class ForkchoiceDosResult:
    reproduced: bool
    test: str
    stalled_ratio: float | None            # cumulative work growth on a 2x chain (~4 == O(n^2))
    stalled_final_nodecount: int | None    # unbounded tree size (== chain length + genesis)
    healthy_final_nodecount: int | None    # bounded tree size after prune()
    healthy_work_pct_of_stalled: float | None
    stdout_tail: str
    note: str

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)


def ensure_test_installed(prysm_dir: Path) -> Path:
    """Copy the reproduction test into prysm's fork-choice package."""
    pkg = prysm_dir / PKG_REL
    if not pkg.is_dir():
        raise FileNotFoundError(f"not a prysm checkout (missing {PKG_REL}): {prysm_dir}")
    dst = pkg / TEST_FILE
    src = Path(__file__).with_name(TEST_FILE)
    # Rewrite the module path (v6/v7/...) to match this checkout's go.mod.
    text = src.read_text(encoding="utf-8")
    mod = _module_path(prysm_dir)
    if mod:
        text = re.sub(r"github\.com/OffchainLabs/prysm/v\d+", mod, text)
    dst.write_text(text, encoding="utf-8")
    return dst


def _module_path(prysm_dir: Path) -> str | None:
    gomod = prysm_dir / "go.mod"
    if not gomod.exists():
        return None
    m = re.search(r"^module\s+(\S+)", gomod.read_text(encoding="utf-8"), re.MULTILINE)
    return m.group(1) if m else None


def run_forkchoice_dos_repro(prysm_dir: str | Path = "prysm", *, keep_test: bool = False) -> ForkchoiceDosResult:
    prysm_path = Path(prysm_dir).resolve()
    if shutil.which("go") is None:
        raise RuntimeError("go toolchain not found on PATH")
    dst = ensure_test_installed(prysm_path)
    cmd = ["go", "test", f"./{PKG_REL}/", "-run", TEST_NAME, "-v", "-count=1"]
    try:
        proc = subprocess.run(cmd, cwd=prysm_path, capture_output=True, text=True, timeout=1200)
    finally:
        if not keep_test:
            dst.unlink(missing_ok=True)

    combined = proc.stdout + "\n" + proc.stderr
    passed = f"--- PASS: {TEST_NAME}" in combined or (
        "PASS" in combined and f"FAIL: {TEST_NAME}" not in combined and proc.returncode == 0
    )
    ms = STALLED_RE.search(combined)
    mn = STALLED_NODES_RE.search(combined)
    mh = HEALTHY_RE.search(combined)

    ratio = float(ms.group(3)) if ms else None
    stalled_nodes = int(mn.group(1)) if mn else None
    healthy_nodes = int(mh.group(1)) if mh else None
    healthy_pct = float(mh.group(3)) if mh else None

    # ③ symptom = quadratic growth; ② control = prune() bounds the tree.
    reproduced = bool(passed and ratio is not None and ratio > 3.0
                      and healthy_nodes is not None and stalled_nodes is not None
                      and healthy_nodes < stalled_nodes // 2)
    note = (
        f"CONFIRMED: fork-choice recursion is O(n^2) under finality stall "
        f"(cumulative work x{ratio:.2f} on a 2x chain, tree unbounded at "
        f"{stalled_nodes} nodes); prune() bounds it to {healthy_nodes} nodes "
        f"({healthy_pct}% of the work)."
        if reproduced
        else "NOT reproduced — see stdout_tail (guard applied, or prysm "
             "revision/build differs)."
    )
    tail = "\n".join(combined.strip().splitlines()[-30:])
    return ForkchoiceDosResult(
        reproduced=reproduced,
        test=TEST_NAME,
        stalled_ratio=ratio,
        stalled_final_nodecount=stalled_nodes,
        healthy_final_nodecount=healthy_nodes,
        healthy_work_pct_of_stalled=healthy_pct,
        stdout_tail=tail,
        note=note,
    )


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="CHK-AS-03 in-process fork-choice O(n^2) repro (prysm)")
    ap.add_argument("--prysm-dir", default="prysm", help="path to a prysm checkout")
    ap.add_argument("--keep-test", action="store_true", help="leave the test file in the checkout")
    ap.add_argument("--json", action="store_true", help="emit JSON only")
    args = ap.parse_args(argv)

    res = run_forkchoice_dos_repro(args.prysm_dir, keep_test=args.keep_test)
    if args.json:
        print(res.to_json())
    else:
        print(f"[CHK-AS-03] reproduced={res.reproduced}")
        print(f"  stalled: work x{res.stalled_ratio} on 2x chain, tree unbounded @ {res.stalled_final_nodecount} nodes")
        print(f"  healthy: prune() bounds tree @ {res.healthy_final_nodecount} nodes "
              f"({res.healthy_work_pct_of_stalled}% of stalled work)")
        print(f"  {res.note}")
    return 0 if res.reproduced else 1


if __name__ == "__main__":
    sys.exit(main())
