"""Erigon v2.41.0 pre-Shanghai dev chain.

The image is built locally from the v2.41.0 source tag.  Its `chain=dev`
genesis uses the legacy Clique developer chain without Shanghai/EIP-6780,
and its built-in miner includes pending transactions into blocks.
"""


def run(plan, args={}):
    image = args.get("image", "ethtotal/erigon:v2.41.0")
    signer = plan.render_templates(
        {"signer.key": struct(
            template="26e86e45f6fc45ec6e2ecd128cec80fa1d1505e5507dcd2ae58c3130a7a97b48",
            data={},
        )},
        "erigon-precancun-signer",
    )
    plan.add_service(
        name="el-1-erigon",
        config=ServiceConfig(
            image=image,
            ports={
                "rpc": PortSpec(number=8545, transport_protocol="TCP"),
            },
            cmd=[
                "--chain=dev",
                "--datadir=/home/erigon/.local/share/erigon",
                "--dev.period=5",
                "--mine",
                "--miner.etherbase=0x67b1d87101671b127f5f8714789C7192f7ad340e",
                "--miner.sigfile=/key/signer.key",
                "--http",
                "--http.addr=0.0.0.0",
                "--http.port=8545",
                "--http.api=eth,erigon,web3,net,debug,trace,txpool,admin",
                "--http.vhosts=*",
                "--nodiscover",
            ],
            files={"/key": signer},
        ),
    )
    return struct()
