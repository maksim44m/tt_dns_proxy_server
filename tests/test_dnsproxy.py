import pytest
import struct
import socket

from dns_proxy import DNSProxy
from config_process import Config


class DummyTransport:
    def __init__(self):
        self.sent = []  # список (data, addr)

    def sendto(self, data, addr):
        self.sent.append((data, addr))


def make_query(qname: str, id: int = 0x1234) -> bytes:
    # Заголовок: ID, QR=0,RD=1, QDCOUNT=1
    flags = 0x0100
    header = struct.pack("!HHHHHH", id, flags, 1, 0, 0, 0)
    query = b"".join(
        struct.pack("!B", len(label)) + label.encode()
        for label in qname.split(".")
    ) + b"\x00" + struct.pack("!HH", 1, 1)
    return header + query


@pytest.fixture
def config():
    # дефолтный конфиг
    return Config(
        upstream=("10.0.0.1", 5353),
        blacklist=["block.domain"],
        blacklist_rcode=0x0003,
        redirect_ip="127.0.0.1",
        _reload_interval=10,
    )


@pytest.fixture
def proxy(config):
    p = DNSProxy(config)
    p.transport = DummyTransport()
    return p


def test_parse_and_question_end(proxy):
    data = make_query("a.b")
    assert proxy._parse_question(data) == "a.b"
    end = proxy._question_end(data)
    # в end +1 - нулевой байт, +4 - QTYPE+QCLASS
    assert end == len(data)


def test_get_flags_nxdomain(proxy):
    orig = struct.pack("!H", 0x0100)  # только RD=1
    flags = proxy._get_flags(orig)
    val = struct.unpack("!H", flags)[0]
    # QR|RD|RA|RCODE(3) = 0x8000+0x0100+0x0080+0x0003 = 0x8183
    assert val == 0x8183


def test_build_error_response(proxy):
    # NXDOMAIN
    data = make_query("block.domain", id=0x1111)
    resp = proxy._build_error(data)
    # id
    assert resp[:2] == b'\x11\x11'
    # флаги _build_error
    assert resp[2:4] == b'\x81\x83'
    # QDCOUNT осталось 1
    assert resp[4:6] == b'\x00\x01'
    # ANCOUNT, NSCOUNT, ARCOUNT = 0
    assert resp[6:12] == b'\x00\x00\x00\x00\x00\x00'
    # тело вопроса (всё после первых 12 байт)
    assert resp[12:] == data[12:]


def test_build_redirect_response(proxy):
    #  REDIRECT
    proxy.config.blacklist_rcode = 0x0000
    data = make_query("block.domain", id=0x2222)
    resp = proxy._build_redirect(data)
    # id
    assert resp[:2] == b'\x22\x22'
    # флаги _build_redirect
    flags = struct.unpack("!H", resp[2:4])[0]
    assert flags & 0x000F == 0  # RCODE=0
    # ANCOUNT=1
    assert resp[6:8] == b'\x00\x01'
    # A-запись с redirect_ip в конце
    assert resp[-4:] == socket.inet_aton(proxy.config.redirect_ip)


def test_datagram_received_forward(proxy):
    data = make_query("ok.domain", id=0x3333)
    client = ("1.2.3.4", 9999)
    proxy.datagram_received(data, client)
    # должно уйти на upstream
    assert proxy.transport.sent == [(data, proxy.config.upstream)]


def test_datagram_received_upstream_reply(proxy):
    # сначала клиент→прокси
    data = make_query("ok.domain", id=0x4444)
    client = ("2.3.4.5", 1234)
    proxy.datagram_received(data, client)
    # затем «ответ» от upstream
    proxy.datagram_received(data, proxy.config.upstream)
    # прокси вернёт клиенту тот же пакет
    assert proxy.transport.sent[-1] == (data, client)


def test_datagram_received_block(proxy):
    data = make_query("block.domain", id=0x5555)
    client = ("5.6.7.8", 2222)
    proxy.datagram_received(data, client)
    sent_data, sent_addr = proxy.transport.sent[-1]
    assert sent_addr == client
    # проверяем RCODE == конфигный
    flags = struct.unpack("!H", sent_data[2:4])[0]
    assert flags & 0x000F == proxy.config.blacklist_rcode
