# harness/probes — the live reproduction scripts behind the verdicts

These are the reusable probe helpers behind the `live_probe` verdicts in
`reports/findings_index.json`. The canonical report-specific runners now live
under `reports/<client>/poc/<vuln-id>/` so the generic harness and the
per-finding reproduction assets stay separate. Each helper discovers the
running devnet (ports change per boot) via `discover.py`, so no hardcoded
endpoints.

## Boot the devnet first

```bash
export PATH="$HOME/.local/bin:$PATH"   # kurtosis
cat > /tmp/eth_reth.yaml <<'YAML'
participants:
  - el_type: reth
    cl_type: lighthouse
additional_services: []
YAML
kurtosis run github.com/ethpandaops/ethereum-package --args-file /tmp/eth_reth.yaml --enclave repro-reth
```

## Run the probes

```bash
uv run python -m harness.probes.discover                 # show discovered endpoints
uv run python -m harness.probes.reth_devp2p              # AUDIT-001 / WIRE-003 / RLPX-002 / RLPX-003
uv run python -m harness.probes.reth_engine              # RETH-ENG-004 / RETH-BCT-002
uv run python -m harness.probes.grandine_gossip_api      # grandine PROP-val-eth-003 (Beacon-API path)
uv run python -m harness.probes.grandine_libp2p_attack   # grandine PROP-val-eth-003 (real libp2p path)
```

(Individual: `... reth_devp2p audit001`, `... reth_engine bct002`, etc.)

## grandine native verification (gitignored tree)

The grandine source tree lives under `/grandine/` and is `.gitignore`d because
it is a full client checkout plus build output. It is used for native source
reads and for the libp2p E2E test harness.

```bash
git clone --filter=blob:none --no-checkout https://github.com/grandinetech/grandine.git grandine
git -C grandine checkout 06247e6877c64ed56e4a3e76c1458eea3454b281
git -C grandine submodule update --init --recursive
# build (NixOS): rust 1.95.0 is auto-selected by rust-toolchain.toml
export LIBCLANG_PATH=$(dirname $(find /nix/store -name 'libclang.so' | head -1))
cd grandine && cargo test -p fork_choice_store --features bls/blst,kzg_utils/blst --no-run
```

The exact functions/lines read per finding are recorded in
`reports/findings_index.json` (`code_review`) — e.g. PROP-val-eth-003:
`fork_choice_store/src/store.rs:1158,1194` + `fork_choice_control/src/mutator.rs:2895`.

## Reproduction map (finding -> script / source)

| Finding | How to reproduce |
|---|---|
| RETH-RLPX-002 | `python -m harness.probes.reth_devp2p rlpx002` |
| RETH-WIRE-003 | `python -m harness.probes.reth_devp2p wire003` |
| RETH-RLPX-003 | `python -m harness.probes.reth_devp2p rlpx003` |
| AUDIT-001 | `python reports/reth/poc/AUDIT-001/poc.py` |
| RETH-ENG-004 | `python -m harness.probes.reth_engine eng004` |
| RETH-BCT-002 | `python -m harness.probes.reth_engine bct002` |
| RETH-BCT-001 | engine flow drivable via `reth_engine`; verdict is premise analysis |
| grandine PROP-val-eth-003 (API path, negative) | `python -m harness.probes.grandine_gossip_api` |
| grandine PROP-val-eth-003 (libp2p path) | `python reports/grandine/poc/PROP-val-eth-003/poc.py` — live reproduced with guarded control |
| grandine (all CONFIRMED clusters) | native source read at SHA 06247e68 — file:line in `reports/findings_index.json` `code_review`; build per the section above |

Every finding's `repro` field in `reports/findings_index.json` carries this
same pointer, so the chain is: **live-verification-summary.md → findings_index
(verdict + `repro` + `code_review`) → probe script or source line**.

## grandine libp2p live attack

`grandine_libp2p_attack.py` is the E2E runner for the real libp2p reproduction
of PROP-val-eth-003. It discovers the grandine CL in the Kurtosis enclave,
extracts the devnet `config.yaml` plus `genesis_validators_root`, resolves the
target `/ip4/127.0.0.1/tcp/<port>/p2p/<peer>` multiaddr from the Beacon API,
installs `grandine_libp2p_attack.rs` into `grandine/eth2_libp2p/tests/`, and
runs the ignored Rust test with the right `GR_*` environment.

```bash
cat > /tmp/eth_grandine.yaml <<'YAML'
participants:
  - el_type: geth
    cl_type: grandine
additional_services: []
YAML
kurtosis run github.com/ethpandaops/ethereum-package --args-file /tmp/eth_grandine.yaml --enclave repro-grandine
uv run python -m harness.probes.grandine_libp2p_attack
```

The Rust test reuses grandine's own `eth2_libp2p` stack, not a Python
approximation. It builds a same-fork attacker node, completes Status, joins the
`beacon_block` mesh, captures a live block from the victim, then publishes
far-future Fulu blocks with unique slots and graffiti.

Confirmed run:

```bash
uv run python -m harness.probes.grandine_libp2p_attack \
  --enclave repro-grandine \
  --count 100000 --warmup 30 --batch 100 --batch-sleep-ms 10
```

The baseline evidence is `reports/grandine/poc/PROP-val-eth-003/runs/20260629T035027Z`:
100,000 beacon blocks received over gossip, RSS +334.90 MiB, peak 798.90 MiB.

Guarded negative control:

```bash
# Build grandine locally with reports/grandine/poc/PROP-val-eth-003/guard.diff applied.
cd grandine
cargo build --profile compact --bin grandine --features default-networks \
  --workspace --exclude zkvm_host --exclude zkvm_guest_risc0 \
  --exclude c_grandine --exclude csharp_grandine
cd ..

# If built on NixOS, patch the Docker copy's ELF interpreter before image build.
cp grandine/target/compact/grandine grandine/target/compact/grandine.docker
patchelf --set-interpreter /lib64/ld-linux-x86-64.so.2 grandine/target/compact/grandine.docker
docker build -t local/grandine:prop-val-eth-003-guard \
  -f reports/grandine/poc/PROP-val-eth-003/Dockerfile.guarded grandine

kurtosis run github.com/ethpandaops/ethereum-package \
  --args-file reports/grandine/poc/PROP-val-eth-003/kurtosis-guarded.yaml \
  --enclave repro-grandine-guard
uv run python -m harness.probes.grandine_libp2p_attack \
  --enclave repro-grandine-guard \
  --count 100000 --warmup 30 --batch 100 --batch-sleep-ms 10
```

The guarded evidence is `reports/grandine/poc/PROP-val-eth-003/runs/20260629T041822Z`:
the same 100,000 beacon blocks are received, but RSS grows only 52.95 MiB
(peak 120.20 MiB). That confirms the root-cause guard suppresses the symptom
without relying on network-layer non-delivery.
