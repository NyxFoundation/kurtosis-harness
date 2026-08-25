"""Besu lifecycle target with a real block-import execution path.

The current Besu release no longer produces Clique blocks.  The target is
therefore kept alive as a clean custom-genesis node and the driver invokes
Besu's own ``blocks import --format=JSON`` path with signed transactions.  The
transactions are executed by Besu's production block importer under the
Amsterdam account-lifecycle rules.
"""

GENESIS = """
{
  "config": {
    "chainId": 3151909,
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
    "amsterdamTime": 0,
    "depositContractAddress": "0x00000000219ab540356cbb839cbe05303d7705fa",
    "withdrawalRequestContractAddress": "0x00000961ef480eb55e80d19ad83579a64c007002",
    "consolidationRequestContractAddress": "0x0000bbddc7ce488642fb579f8b00f3a590007251"
  },
  "coinbase": "0x0000000000000000000000000000000000000000",
  "difficulty": "0x0",
  "extraData": "0x",
  "gasLimit": "0x3938700",
  "mixHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
  "nonce": "0x0",
  "timestamp": "0x68aaf000",
  "terminalTotalDifficulty": "0x0",
  "terminalTotalDifficultyPassed": true,
  "alloc": {
    "8943545177806ed17b9f23f0a21ee5948ecaa776": {"balance": "0x3635c9adc5dea0000000"},
    "000f3df6d732807ef1319fb7b8bb8522d0beac02": {"code": "0x00"},
    "0000f90827f1c53a10cb7a02335b175320002935": {"code": "0x00"}
  }
}
"""


def run(plan, args={}):
    image = args.get("image", "hyperledger/besu:latest")
    genesis = plan.render_templates(
        {"genesis.json": struct(template=GENESIS, data={})},
        "besu-legacy-genesis",
    )
    plan.add_service(
        name="el-1-besu-import",
        config=ServiceConfig(
            image=image,
            ports={"rpc": PortSpec(number=8545, transport_protocol="TCP")},
            entrypoint=["/bin/sh"],
            cmd=[
                "-c",
                "touch /tmp/pid; besu --genesis-file=/genesis/genesis.json --data-path=/opt/besu/live --rpc-http-enabled --rpc-http-host=0.0.0.0 --rpc-http-port=8545 --rpc-http-api=ETH,NET,WEB3,DEBUG,TXPOOL,ADMIN --host-allowlist=* --p2p-enabled=false & echo $! >/tmp/besu.pid; while true; do sleep 3600; done",
            ],
            files={"/genesis": genesis},
        ),
    )
    return struct()
