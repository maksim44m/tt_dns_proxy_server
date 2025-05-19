from typing import AsyncGenerator
import pytest
import asyncio
import socket
import struct

import pytest_asyncio

from dns_proxy import DNSProxy
from config_process import Config


def make_query(qname: str, id: int = 0x1234) -> bytes:
    # Построение простого DNS-запроса (ID, флаги, QDCOUNT=1)
    flags = 0x0100
    header = struct.pack("!HHHHHH", id, flags, 1, 0, 0, 0)
    question = b"".join(
        struct.pack("!B", len(label)) + label.encode()
        for label in qname.split(".")
    ) + b"\x00" + struct.pack("!HH", 1, 1)
    return header + question


class DummyUpstream(asyncio.DatagramProtocol):
    def __init__(self):
        self.transport = None

    def connection_made(
        self, transport: asyncio.DatagramTransport
    ) -> None:
        self.transport = transport

    def datagram_received(
        self, data: bytes, addr: tuple[str, int]
    ) -> None:
        # Эхо-ответ: просто ставим QR и возвращаем тот же вопрос
        id, flags, qdcount, _, _, _ = struct.unpack("!HHHHHH", data[:12])
        resp_flags = flags | 0x8000  # установить бит QR
        header = struct.pack("!HHHHHH", id, resp_flags, qdcount, 0, 0, 0)
        resp = header + data[12:]
        self.transport.sendto(resp, addr)


@pytest_asyncio.fixture
async def proxy_and_upstream() -> AsyncGenerator[tuple[int, DNSProxy], None]:
    # 1) Запуск upstream на локальном порту
    upstream_port = 15353
    upstream = DummyUpstream()
    loop = asyncio.get_running_loop()
    up_trans, _ = await loop.create_datagram_endpoint(
        lambda: upstream,
        local_addr=('127.0.0.1', upstream_port)
    )

    # 2) Конфигурация прокси
    cfg = Config()
    cfg.upstream = ('127.0.0.1', upstream_port)
    cfg.blacklist = ['block.domain']
    cfg.blacklist_rcode = 3
    cfg.redirect_ip = '127.0.0.1'

    # 3) Запуск прокси на другом порту
    proxy_port = 15354
    proxy = DNSProxy(cfg)
    px_trans, _ = await loop.create_datagram_endpoint(
        lambda: proxy,
        local_addr=('127.0.0.1', proxy_port)
    )

    yield proxy_port, proxy

    # Завершение обоих транспортов
    px_trans.close()
    up_trans.close()


@pytest.mark.asyncio
async def test_forward(proxy_and_upstream: tuple[int, DNSProxy]) -> None:
    proxy_port, _ = proxy_and_upstream
    query = make_query('example.com', id=0x1234)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)

    loop = asyncio.get_running_loop()
    await loop.sock_sendto(sock, query, ('127.0.0.1', proxy_port))
    resp, _ = await loop.sock_recvfrom(sock, 512)

    assert (resp[2] & 0x80) != 0  # QR
    assert resp[:2] == b'\x12\x34'  # ID
    sock.close()


@pytest.mark.asyncio
async def test_block_nxdomain(proxy_and_upstream: tuple[int, DNSProxy]) -> None:
    proxy_port, _ = proxy_and_upstream
    query = make_query('block.domain', id=0x5678)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)

    loop = asyncio.get_running_loop()
    await loop.sock_sendto(sock, query, ('127.0.0.1', proxy_port))
    resp, _ = await loop.sock_recvfrom(sock, 512)

    rcode = resp[3] & 0x0F
    assert rcode == 3  # NXDOMAIN
    sock.close()


@pytest.mark.asyncio
async def test_redirect(proxy_and_upstream: tuple[int, DNSProxy]) -> None:
    proxy_port, proxy = proxy_and_upstream
    query = make_query('block.domain', id=0x9ABC)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)

    proxy.config.blacklist_rcode = 0

    loop = asyncio.get_running_loop()
    await loop.sock_sendto(sock, query, ('127.0.0.1', proxy_port))
    resp, _ = await loop.sock_recvfrom(sock, 512)

    # Проверка заголовка
    assert resp[:2] == b'\x9A\xBC'   # ID
    assert (resp[2] & 0x80) != 0     # QR бит
    assert resp[6:8] == b'\x00\x01'  # ANCOUNT = 1

    # Проверка ответа
    # header + qname + qtype/qclass
    answer_start = proxy._question_end(query)
    assert resp[answer_start:answer_start+2] == b'\xC0\x0C'  # pointer
    assert resp[answer_start+2:answer_start+4] == b'\x00\x01'  # A record
    assert resp[answer_start+6:answer_start+10] == b'\x00\x00\x00\x3c'  # TTL
    assert resp[answer_start+10:answer_start+12] == b'\x00\x04'  # RDLENGTH
    assert resp[answer_start+12:answer_start + 16] \
        == socket.inet_aton('127.0.0.1')  # IP

    sock.close()


@pytest.mark.asyncio
async def test_error_handling(proxy_and_upstream: tuple[int, DNSProxy]) -> None:
    proxy_port, _ = proxy_and_upstream
    # Некорректный DNS-запрос
    invalid_query = b'\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00'
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)

    loop = asyncio.get_running_loop()
    await loop.sock_sendto(sock, invalid_query, ('127.0.0.1', proxy_port))
    # Проверяем, что сервер не падает
    await asyncio.sleep(0.1)
    sock.close()
