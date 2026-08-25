"""Single-service Erigon dev-chain package for lifecycle probes.

This package intentionally uses Erigon's embedded Caplin dev mode.  It is a
real block-producing Erigon service, but it is not a pre-EIP-6780 network:
the current dev-chain genesis enables the modern fork schedule.  Callers must
inspect the chain configuration before treating it as a historical-fork
attack environment.
"""


def run(plan, args={}):
    image = args.get("image", "erigontech/erigon:latest")
    jwt = plan.render_templates(
        {"jwtsecret": struct(template="11" * 32, data={})},
        "erigon-dev-jwt",
    )
    plan.add_service(
        name="el-1-erigon",
        config=ServiceConfig(
            image=image,
            ports={
                "rpc": PortSpec(number=8545, transport_protocol="TCP"),
                "engine": PortSpec(number=8551, transport_protocol="TCP"),
            },
            cmd=[
                "--chain=dev",
                "--datadir=/home/erigon/.local/share/erigon",
                "--dev-validator-count=1",
                "--dev.slot-time=2",
                "--beacon.api=beacon,validator,node,config",
                "--beacon.api.addr=0.0.0.0",
                "--beacon.api.port=5555",
                "--http",
                "--http.addr=0.0.0.0",
                "--http.port=8545",
                "--http.api=eth,erigon,engine,web3,net,debug,trace,txpool,admin",
                "--http.vhosts=*",
                "--authrpc.addr=0.0.0.0",
                "--authrpc.port=8551",
                "--authrpc.vhosts=*",
                "--authrpc.jwtsecret=/jwt/jwtsecret",
                "--prune.mode=archive",
            ],
            # Kurtosis mounts a files artifact as a directory; the rendered
            # `jwtsecret` file therefore appears at /jwt/jwtsecret.
            files={"/jwt": jwt},
        ),
    )
    return struct()
