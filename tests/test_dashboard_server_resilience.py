from __future__ import annotations

from rootkeepers.dashboard.server import Handler


class _AbortedWriter:
    def write(self, _body: bytes) -> None:
        raise ConnectionAbortedError("client changed views")


def test_json_response_treats_client_disconnect_as_normal() -> None:
    handler = object.__new__(Handler)
    handler.wfile = _AbortedWriter()
    handler.close_connection = False
    handler.send_response = lambda _status: None
    handler.send_header = lambda _name, _value: None
    handler.end_headers = lambda: None

    handler._send_json(200, {"ok": True})

    assert handler.close_connection is True
