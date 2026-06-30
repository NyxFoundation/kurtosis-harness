"""Finding-spec schema — the contract between an audit report and the harness.

A ``finding.json`` is the machine-readable form of a single confirmed/potential
finding. The harness consumes it to drive a reproduction (A) and a negative
control (E). Everything client-specific lives here as data; the harness layers
(observer, verdict, drivers) stay client-agnostic.

Grounded on the real PoC at reports/grandine/poc/PROP-val-eth-003/.
Uses pydantic (already a project dependency) rather than jsonschema.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field, model_validator


class AttackSurface(str, Enum):
    """Untrusted entry surface. One driver per surface, reused across clients."""

    P2P_RLPX = "p2p-rlpx"          # RLPx / ECIES handshake bytes
    DEVP2P_WIRE = "devp2p-wire"    # eth/68 wire messages
    P2P_GOSSIP = "p2p-gossip"      # libp2p gossipsub topics (CL)
    TXPOOL = "txpool"              # transaction gossip / pool
    ENGINE_API = "engine-api"      # Engine API (malicious/compromised CL)
    BLOCK_IMPORT = "block-import"  # crafted blocks/headers via sync


class ResourceSignal(str, Enum):
    """The observable that a resource-exhaustion finding drives."""

    RSS = "rss"                    # resident memory growth -> OOM
    CPU = "cpu"                    # CPU saturation
    RESTART = "restart"            # process crash/restart count
    REEXEC_COUNT = "reexec-count"  # re-execution storm (log-derived)


class ThresholdOp(str, Enum):
    GT = ">"
    GE = ">="
    LT = "<"
    LE = "<="


# Metrics the observer knows how to compute from a sample series.
KNOWN_METRICS = {
    "rss_delta_mb",   # peak RSS - baseline RSS
    "peak_rss_mb",    # absolute peak RSS
    "cpu_pct",        # sustained CPU %
    "restart_count",  # number of process restarts during the run
    "reexec_count",   # re-executions counted from logs
}


class Threshold(BaseModel):
    """Symptom predicate evaluated against an observed sample series."""

    metric: str
    op: ThresholdOp
    value: float

    @model_validator(mode="after")
    def _check_metric(self) -> "Threshold":
        if self.metric not in KNOWN_METRICS:
            raise ValueError(
                f"unknown metric {self.metric!r}; known: {sorted(KNOWN_METRICS)}"
            )
        return self


class AttackerInput(BaseModel):
    """Which driver generates the malicious input, and with what parameters."""

    driver: AttackSurface
    generator: str                 # named generator within the driver
    params: dict = Field(default_factory=dict)


class NegativeControlType(str, Enum):
    PATCH = "patch"    # apply a source diff that adds the missing guard
    CONFIG = "config"  # flip an existing-but-disabled limit via config


class NegativeControl(BaseModel):
    """The E half: how to build the 'guarded' variant for the A/B."""

    type: NegativeControlType
    ref: str                       # patch path or config key
    description: str = ""


class FindingSpec(BaseModel):
    """One finding, expressed as something the harness can run."""

    vuln_id: str
    client: str
    attack_surface: AttackSurface
    entry_point: str               # file:line of the vulnerable site
    attacker_input: AttackerInput
    resource_signal: ResourceSignal
    threshold: Threshold
    # The ④ obligation: mitigations to leave enabled during the run.
    keep_mitigations_on: list[str] = Field(default_factory=list)
    negative_control: NegativeControl
    spec_ref: str = ""

    @model_validator(mode="after")
    def _driver_matches_surface(self) -> "FindingSpec":
        if self.attacker_input.driver != self.attack_surface:
            raise ValueError(
                f"attacker_input.driver ({self.attacker_input.driver}) must match "
                f"attack_surface ({self.attack_surface})"
            )
        return self


def load_finding_spec(path) -> FindingSpec:
    """Load and validate a finding.json from disk."""
    import json
    from pathlib import Path

    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return FindingSpec.model_validate(data)
