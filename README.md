# KurtosisHarness

*Reproduce it on a real client, or it doesn't count as a finding.*

A finding-driven, client-agnostic reproduction harness for Ethereum-client audit
findings. You bring a `finding.json` (what the attack is) and a small runner; the
harness drives the attack against a real client on a local
[Kurtosis](https://docs.kurtosis.com/) devnet, applies a guarded negative
control, and returns an evidence-based verdict.

A candidate is promoted to a finding only when four obligations all hold:

1. the attack input reaches the entry point;
2. the unguarded build shows the symptom;
3. applying the missing guard makes the symptom vanish — cause, not coincidence;
4. the symptom still fires with the client's default defenses on.

Anything short gets a *named* verdict instead (`NOT_REACHABLE`, `NOT_REPRODUCED`,
`FALSE_POSITIVE_RISK`, `MITIGATED_IN_PRACTICE`), so a false positive is never
emitted by accident. The engine holds no per-finding data — one harness serves
all 11 clients.

## Architecture

```
harness/  (this package, at the repo root)
├── schema.py     FindingSpec — validates a finding.json (pydantic)
├── observer.py   L2: resource observation + analytic memory model
├── verdict.py    L3: the A/B decision over the four obligations
├── runner.py     orchestration: DryRunHarness (offline) + Harness protocol
├── drivers/      L1: one attack driver per surface (rlpx/wire/gossip/txpool/engine/block)
│   └── rlpx/     from-scratch RLPx stack (ECIES + AES-CTR/keccak MAC + snappy + eth Status)
├── probes/       reusable live probes (reth devp2p/engine, grandine libp2p/gossip)
└── devnet/       L0: Docker + Kurtosis ethereum-package backends
```

L0 boots a real client on a devnet, L1 delivers the attack on one surface, L2
samples RSS/CPU via `docker stats`, and L3 turns the baseline-vs-guard metrics
into a verdict. Three backends sit behind one interface: `DryRunHarness` (an
offline analytic model, fully unit-tested), `Docker`, and `Kurtosis`.

The devp2p path is a from-scratch RLPx stack (ECIES handshake, AES-CTR with a
keccak running-MAC, snappy, the eth `Status` exchange) that interoperates with
real reth — it completes the handshake and reth's own handlers accept the crafted
messages, so a negative result reflects impact, not an inability to land the
attack.

## Bring your own finding (the contract)

Everything client- and finding-specific lives outside the engine, in a bundle:

```
<your-bundle>/
├── finding.json   machine spec the harness consumes (validated by harness/schema.py)
├── guard.diff     the negative control referenced by finding.json
├── poc.py         your runnable PoC (the reproduction entrypoint)
└── runs/<ts>/     captured metrics.json + samples.csv + verdict
```

`finding.json` key fields: `attack_surface` (`p2p-rlpx`, `devp2p-wire`,
`p2p-gossip`, `txpool`, `engine-api`, `block-import`), `resource_signal` (`rss`,
`cpu`, `restart`, `reexec-count`), the attacker input parameters, and the
`threshold` that defines the symptom. A minimal example ships in
[`tests/fixtures/sample_finding.json`](tests/fixtures/sample_finding.json).

## Install

```bash
pip install -e .                 # exposes the `harness` package
# or use it as a git submodule (see "As a submodule" below) — no install needed
```

## Run

```bash
python -m pytest tests/ -q                       # offline engine + contract tests
python -m harness <finding.json>                 # offline DryRun verdict
python -m harness <finding.json> --devnet        # live A/B (needs Docker + kurtosis)

# reusable probes (discover per-boot devnet ports via harness/probes/discover.py):
python -m harness.probes.discover
python -m harness.probes.reth_devp2p             # reth devp2p surfaces
python -m harness.probes.grandine_libp2p_attack  # grandine gossip over real libp2p
```

The offline run prints the four-obligation verdict from the analytic model.
`--devnet` runs the real A/B; until a finding's L0/L1 network paths are
implemented it reports the substrate as unavailable rather than inventing metrics.

## As a submodule

The harness is designed to be vendored into an audit repo at path `harness/`
(this package is at the repo root, so the submodule mounts directly as the
`harness` package):

```bash
git submodule add https://github.com/NyxFoundation/kurtosis-harness.git harness
git submodule update --init
# now `import harness`, `python -m harness`, and per-finding poc.py all resolve
```

Each finding bundle's `poc.py` imports `harness.*` and drives one reproduction;
running the poc reproduces the finding against the devnet.

## Roadmap

- Stable `finding.json` schema versioning.
- A thin plugin entrypoint so the [SPECA](https://github.com/NyxFoundation/speca)
  pipeline can call the harness directly as a Phase-E verification step.

## License

MIT — see [LICENSE](LICENSE).

> Reproducers run on local devnets only (Anvil / Kurtosis / ethpandaops), never
> against mainnet, public testnets, or third-party nodes.
