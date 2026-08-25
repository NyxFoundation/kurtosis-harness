"""Minimal two-service Reth Amsterdam staged-import target."""

GENESIS = """
{
  "config": {
    "chainId": 3151908,
    "homesteadBlock": 0,
    "eip150Block": 0,
    "eip155Block": 0,
    "eip158Block": 0,
    "byzantiumBlock": 0,
    "constantinopleBlock": 0,
    "petersburgBlock": 0,
    "istanbulBlock": 0,
    "berlinBlock": 0,
    "londonBlock": 0,
    "mergeNetsplitBlock": 0,
    "terminalTotalDifficulty": 0,
    "terminalTotalDifficultyPassed": true,
    "shanghaiTime": 0,
    "cancunTime": 0,
    "pragueTime": 0,
    "osakaTime": 0,
    "amsterdamTime": 0,
    "blobSchedule": {
      "cancun": {"target": 3, "max": 6, "baseFeeUpdateFraction": 3338477},
      "prague": {"target": 6, "max": 9, "baseFeeUpdateFraction": 5007716},
      "bpo1": {"target": 10, "max": 15, "baseFeeUpdateFraction": 8346193},
      "bpo2": {"target": 14, "max": 21, "baseFeeUpdateFraction": 11684671}
    }
  },
  "coinbase": "0x0000000000000000000000000000000000000000",
  "difficulty": "0x0",
  "extraData": "",
  "gasLimit": "0x3938700",
  "nonce": "0x1234",
  "mixHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
  "parentHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
  "timestamp": "1787631283",
  "alloc": {}
}
"""


def run(plan, args={}):
    image = args.get("image", "ethpandaops/reth:main")
    genesis = plan.render_templates(
        {"genesis.json": struct(template=GENESIS, data={})},
        "reth-staged-bal-genesis",
    )
    plan.add_service(
        name="el-source-reth",
        config=ServiceConfig(
            image=image,
            ports={"rpc": PortSpec(number=8545, transport_protocol="TCP")},
            cmd=[
                "node", "--chain", "/genesis/genesis.json", "--datadir", "/data",
                "--dev", "--dev.block-time", "2s", "--http", "--http.addr", "0.0.0.0",
                "--http.port", "8545", "--http.api", "eth,web3,net,debug",
            ],
            files={"/genesis": genesis},
        ),
    )
    plan.add_service(
        name="el-target-reth",
        config=ServiceConfig(
            image=image,
            entrypoint=["/bin/sh"],
            cmd=[
                "-c",
                "reth init --chain /genesis/genesis.json --datadir /data && sleep 3600",
            ],
            files={"/genesis": genesis},
        ),
    )
    return struct()
