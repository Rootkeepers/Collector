from __future__ import annotations

import io

import pytest

from rootkeepers.dashboard.server import Handler, MAX_JSON_BODY_BYTES


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


def _body_reader(body: bytes, declared_length: int | str | None = None) -> Handler:
    handler = object.__new__(Handler)
    length = len(body) if declared_length is None else declared_length
    handler.headers = {"Content-Length": str(length)}
    handler.rfile = io.BytesIO(body)
    return handler


def test_json_body_must_be_an_object() -> None:
    with pytest.raises(ValueError, match="객체"):
        _body_reader(b"[]")._read_json_body()


@pytest.mark.parametrize("length", ["invalid", -1, MAX_JSON_BODY_BYTES + 1])
def test_invalid_or_oversized_content_length_is_rejected(length) -> None:
    with pytest.raises(ValueError):
        _body_reader(b"", length)._read_json_body()


def test_truncated_json_body_is_rejected() -> None:
    with pytest.raises(ValueError, match="짧습니다"):
        _body_reader(b'{}', 10)._read_json_body()
