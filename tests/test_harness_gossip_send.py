"""Gossip driver send test — real HTTP POSTs, verified against a stub server.

Offline: stands up a tiny HTTP server that counts POSTs to
/eth/v1/beacon/blocks, points the driver at it, and asserts the flood is
actually delivered. No devnet needed; the real grandine target just swaps in
for the stub.
"""
from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from harness.drivers.base import DriverTarget, get_driver
from harness.schema import load_finding_spec

GRANDINE = "tests/fixtures/sample_finding.json"


class _CountingHandler(BaseHTTPRequestHandler):
    posts: list[int] = []

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        type(self).posts.append(len(body))
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, *a):  # silence
        pass


@pytest.fixture()
def stub_beacon_api():
    _CountingHandler.posts = []
    server = HTTPServer(("127.0.0.1", 0), _CountingHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    host, port = server.server_address
    try:
        yield f"http://{host}:{port}", _CountingHandler
    finally:
        server.shutdown()


def test_gossip_driver_floods_beacon_api(stub_beacon_api):
    url, handler = stub_beacon_api
    spec = load_finding_spec(GRANDINE)
    spec.attacker_input.params["count"] = 8  # small, for the test

    driver = get_driver(spec.attack_surface)
    sent = driver.emit(spec, DriverTarget(rpc_url=url))

    assert sent == 8
    assert len(handler.posts) == 8
    assert all(n > 100 for n in handler.posts)  # real SSZ blocks, not empty


def test_gossip_driver_requires_target_url():
    from harness.drivers.base import DriverNotImplemented

    spec = load_finding_spec(GRANDINE)
    driver = get_driver(spec.attack_surface)
    with pytest.raises(DriverNotImplemented):
        driver.emit(spec, DriverTarget())  # no rpc_url
