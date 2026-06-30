# KurtosisHarness

**Reproduce it on a real client, or it doesn't count as a finding.**

[![CI](https://github.com/NyxFoundation/kurtosis-harness/actions/workflows/test.yml/badge.svg)](https://github.com/NyxFoundation/kurtosis-harness/actions/workflows/test.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)

A finding-driven, client-agnostic reproduction harness for Ethereum-client audit
findings. You describe an attack in a small `finding.json`; the harness drives it
against a real client on a local [Kurtosis](https://docs.kurtosis.com/) devnet,
applies a guarded negative control, and returns an evidence-based verdict instead
of a code-reading opinion.

It was built to gate an LLM-assisted audit of the eleven Ethereum clients: the
static pipeline produced many "CONFIRMED" findings, and most did not survive
contact with a running node. The harness is the part that tells a real defect
from a plausible-looking one.

```console
$ python -m harness finding.json
PROP-val-eth-003 [grandine/p2p-gossip] backend=dryrun
  verdict: CONFIRMED
    - ③ baseline symptom observed
    - ② guarded build clears the symptom (causation established)
    - ④ survives default mitigations
```

## Why

A candidate becomes a finding only when **four obligations** all hold:

| | Obligation | Meaning |
|---|---|---|
| ① | **reachable** | the attack input actually reaches the entry point |
| ③ | **baseline symptom** | the unguarded build exhibits the symptom |
| ② | **guard clears it** | applying the missing guard removes the symptom — cause, not coincidence |
| ④ | **survives mitigations** | the symptom still fires with the client's default defenses on |

Anything short produces a *named* verdict — `NOT_REACHABLE`, `NOT_REPRODUCED`,
`FALSE_POSITIVE_RISK`, `MITIGATED_IN_PRACTICE` — so a false positive is never
emitted by accident. The engine carries no per-finding logic; one harness serves
all eleven clients.

## Install

```bash
pip install -e .            # exposes the `harness` package
# requires Python 3.10+; deps: pydantic, cryptography, pycryptodome, coincurve, cramjam
```

The live backend additionally needs the [`kurtosis`](https://docs.kurtosis.com/install)
CLI and Docker on your PATH. The offline model and the test suite need neither.

## Quickstart

```bash
python -m pytest tests/ -q                      # offline engine + contract tests
python -m harness tests/fixtures/sample_finding.json   # offline DryRun verdict
```

Then point it at your own bundle, or run a live A/B once a devnet is reachable:

```bash
python -m harness path/to/finding.json --devnet            # boots a devnet, runs baseline vs guard
python -m harness path/to/finding.json --devnet --guarded-image local/client:guard
```

## Write a finding

Everything client- and finding-specific lives outside the engine in a bundle:

```
your-bundle/
├── finding.json   the machine spec the harness consumes (validated by harness/schema.py)
├── guard.diff     the negative control referenced by finding.json
├── poc.py         your runnable reproduction entrypoint (optional; imports harness.*)
└── runs/<ts>/     captured metrics.json + samples.csv + verdict
```

A `finding.json` (see [`tests/fixtures/sample_finding.json`](tests/fixtures/sample_finding.json)):

```jsonc
{
  "vuln_id": "PROP-val-eth-003",
  "client": "grandine",
  "attack_surface": "p2p-gossip",          // p2p-rlpx | devp2p-wire | p2p-gossip | txpool | engine-api | block-import
  "entry_point": "fork_choice_store/src/store.rs:1158",
  "attacker_input": {
    "driver": "p2p-gossip",
    "generator": "far_future_slot_beacon_block_flood",
    "params": { "count": 500000, "slot_offset": 1000000, "unique_graffiti": true, "per_item_bytes": 1024 }
  },
  "resource_signal": "rss",                 // rss | cpu | restart | reexec-count
  "threshold": { "metric": "rss_delta_mb", "op": ">", "value": 300 },
  "keep_mitigations_on": ["gossipsub_peer_scoring"],
  "negative_control": { "type": "patch", "ref": "guard.diff", "description": "enforce the missing spec bound" },
  "spec_ref": "ethereum/consensus-specs p2p-interface.md#beacon_block"
}
```

## Architecture

```
harness/                 (this package, at the repo root)
├── schema.py     FindingSpec — validates a finding.json (pydantic)
├── observer.py   L2: resource sampling + analytic memory model
├── verdict.py    L3: the A/B decision over the four obligations
├── runner.py     orchestration: DryRunHarness (offline) + Harness protocol
├── drivers/      L1: one attack driver per surface
│   └── rlpx/     from-scratch RLPx stack (ECIES + AES-CTR/keccak MAC + snappy + eth Status)
├── probes/       reusable live probes (reth devp2p/engine, grandine libp2p/gossip)
└── devnet/       L0: Docker + Kurtosis ethereum-package backends
```

L0 boots a real client, L1 delivers the attack on one surface, L2 samples RSS/CPU
via `docker stats`, L3 turns baseline-vs-guard metrics into a verdict. The RLPx
stack interoperates with real reth — it completes the handshake and reth's own
handlers accept the crafted messages — so a negative result reflects impact, not
an inability to land the attack.

| Backend | Use | Needs |
|---|---|---|
| `DryRun` | analytic model, CI, fast feedback | nothing |
| `Docker` | container-level checks | Docker |
| `Kurtosis` | real devnet A/B with `docker stats` sampling | Docker + `kurtosis` |

## Use as a submodule

The package lives at the repo root, so it mounts directly as the `harness`
package when vendored at path `harness/`:

```bash
git submodule add https://github.com/NyxFoundation/kurtosis-harness.git harness
git submodule update --init
# `import harness`, `python -m harness`, and each bundle's poc.py now resolve
```

## Project status

Pre-1.0. The offline engine, the schema/verdict contract, and the RLPx
interop are covered by the test suite (`python -m pytest`, runs without a
devnet). The live Kurtosis backend has been used to produce real reproductions
(e.g. a grandine gossip-buffer OOM with a guarded control); treat the
`finding.json` schema as not-yet-stable across versions.

## Roadmap

- Versioned, documented `finding.json` schema.
- A plugin entrypoint so the [SPECA](https://github.com/NyxFoundation/speca)
  pipeline can call the harness as its Phase-E verification step.
- More surface drivers and per-client devnet templates.

## Contributing

Issues and PRs welcome. Please keep the engine client-agnostic (no per-finding
logic in `harness/`; that belongs in a bundle) and add an offline test for new
engine behavior. Run `python -m pytest tests/ -q` before opening a PR.

## Security & responsible use

This is offensive tooling for **authorized** testing only. Run reproducers
against local devnets exclusively (Anvil / Kurtosis / ethpandaops) — never
against mainnet, public testnets, or third-party infrastructure. Coordinate
disclosure with the affected client team before publishing a reproduction.

## License

[MIT](LICENSE).
