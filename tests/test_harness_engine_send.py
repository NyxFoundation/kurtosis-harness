"""Engine driver send test — JWT-authenticated JSON-RPC flood vs a stub server.

Offline: a stub Engine endpoint verifies the HS256 JWT against the shared
secret and records the JSON-RPC method/params; the driver points at it. The
live reth target swaps in for the stub.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from harness.drivers.base import DriverTarget, get_driver, make_engine_jwt
from harness.schema import (
    AttackerInput,
    AttackSurface,
    FindingSpec,
    NegativeControl,
    NegativeControlType,
    ResourceSignal,
    Threshold,
    ThresholdOp,
)

SECRET_HEX = "fd" * 32  # 32-byte jwtsecret


def _jwt_valid(token: str, secret: bytes) -> bool:
    try:
        h, p, s = token.split(".")
        signing = f"{h}.{p}".encode()
        expect = base64.urlsafe_b64encode(
            hmac.new(secret, signing, hashlib.sha256).digest()
        ).rstrip(b"=").decode()
        return hmac.compare_digest(s, expect)
    except Exception:
        return False


def _engine_spec() -> FindingSpec:
    return FindingSpec(
        vuln_id="RETH-ENG-004",
        client="reth",
        attack_surface=AttackSurface.ENGINE_API,
        entry_point="crates/rpc/rpc-engine-api/src/engine_api.rs:627",
        attacker_input=AttackerInput(
            driver=AttackSurface.ENGINE_API,
            generator="blocking_task_flood",
            params={"count": 6, "rpc_params": ["0x1", "0xffffffffffffffff"]},
        ),
        resource_signal=ResourceSignal.CPU,
        threshold=Threshold(metric="cpu_pct", op=ThresholdOp.GT, value=70),
        negative_control=NegativeControl(type=NegativeControlType.CONFIG, ref="cap-range"),
    )


class _EngineHandler(BaseHTTPRequestHandler):
    calls: list[dict] = []
    secret: bytes = bytes.fromhex(SECRET_HEX)

    def do_POST(self):
        auth = self.headers.get("Authorization", "")
        token = auth.removeprefix("Bearer ").strip()
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
        type(self).calls.append({"jwt_ok": _jwt_valid(token, self.secret), "method": body.get("method")})
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'{"jsonrpc":"2.0","id":1,"result":[]}')

    def log_message(self, *a):
        pass


@pytest.fixture()
def stub_engine():
    _EngineHandler.calls = []
    server = HTTPServer(("127.0.0.1", 0), _EngineHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    host, port = server.server_address
    try:
        yield f"http://{host}:{port}", _EngineHandler
    finally:
        server.shutdown()


def test_jwt_is_valid_hs256():
    secret = bytes.fromhex(SECRET_HEX)
    assert _jwt_valid(make_engine_jwt(secret), secret)


def test_engine_driver_floods_with_valid_jwt(stub_engine):
    url, handler = stub_engine
    driver = get_driver(AttackSurface.ENGINE_API)
    sent = driver.emit(_engine_spec(), DriverTarget(engine_url=url, jwt_secret=SECRET_HEX))
    assert sent == 6
    assert len(handler.calls) == 6
    assert all(c["jwt_ok"] for c in handler.calls)  # every request authenticated
    assert all(c["method"] == "engine_getPayloadBodiesByRangeV1" for c in handler.calls)


def test_engine_driver_requires_url_and_secret():
    from harness.drivers.base import DriverNotImplemented

    driver = get_driver(AttackSurface.ENGINE_API)
    with pytest.raises(DriverNotImplemented):
        driver.emit(_engine_spec(), DriverTarget())  # no engine_url / jwt
