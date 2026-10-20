"""Offline test defaults and an outbound socket tripwire with loopback support."""

from __future__ import annotations

import ipaddress
import os
import socket
from collections.abc import Callable

import pytest


class OutboundNetworkDenied(RuntimeError):
    pass


_METADATA_ADDRESSES = {
    ipaddress.ip_address("169.254.169.254"),
    ipaddress.ip_address("169.254.170.2"),
    ipaddress.ip_address("fd00:ec2::254"),
}


def _address_is_loopback(address: object) -> bool:
    if isinstance(address, str):
        host = address
    elif isinstance(address, tuple) and address:
        host = address[0]
    else:
        return False
    try:
        parsed = ipaddress.ip_address(host)
    except ValueError:
        return False
    return parsed.is_loopback and parsed not in _METADATA_ADDRESSES


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "acceptance(*ids): acceptance requirement IDs")
    config.addinivalue_line("markers", "case_id(value): formal golden or review case ID")
    config.addinivalue_line("markers", "variant(value): positive/negative/boundary/failure")
    config.addinivalue_line("markers", "fixture_sha256(value): independent fixture digest")
    if os.environ.get("SOC_MODE", "fixture") != "fixture":
        raise pytest.UsageError("offline test runs require SOC_MODE=fixture")


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    del config
    for item in items:
        requirements = item.get_closest_marker("acceptance")
        case_id = item.get_closest_marker("case_id")
        variant = item.get_closest_marker("variant")
        fixture_hash = item.get_closest_marker("fixture_sha256")
        if requirements is not None:
            item.user_properties.append(
                ("acceptance_ids", ",".join(str(value) for value in requirements.args))
            )
        if case_id is not None and case_id.args:
            item.user_properties.append(("case_id", str(case_id.args[0])))
        if variant is not None and variant.args:
            item.user_properties.append(("variant", str(variant.args[0])))
        if fixture_hash is not None and fixture_hash.args:
            item.user_properties.append(("fixture_sha256", str(fixture_hash.args[0])))


@pytest.fixture(autouse=True)
def deny_external_sockets(monkeypatch: pytest.MonkeyPatch) -> None:
    original_connect: Callable[..., object] = socket.socket.connect
    original_connect_ex: Callable[..., int] = socket.socket.connect_ex
    original_create_connection = socket.create_connection

    def guarded_connect(sock: socket.socket, address: object) -> object:
        if _address_is_loopback(address):
            return original_connect(sock, address)
        raise OutboundNetworkDenied("external network access is disabled in offline tests")

    def guarded_connect_ex(sock: socket.socket, address: object) -> int:
        if _address_is_loopback(address):
            return original_connect_ex(sock, address)
        raise OutboundNetworkDenied("external network access is disabled in offline tests")

    def guarded_create_connection(
        address: object, *args: object, **kwargs: object
    ) -> socket.socket:
        if _address_is_loopback(address):
            return original_create_connection(address, *args, **kwargs)
        raise OutboundNetworkDenied("external network access is disabled in offline tests")

    monkeypatch.setattr(socket.socket, "connect", guarded_connect)
    monkeypatch.setattr(socket.socket, "connect_ex", guarded_connect_ex)
    monkeypatch.setattr(socket, "create_connection", guarded_create_connection)
