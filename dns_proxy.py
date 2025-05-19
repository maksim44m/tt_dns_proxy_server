from asyncio import DatagramTransport, DatagramProtocol
import socket
import struct

import config_process
import log_conf


logger = log_conf.logging.getLogger(__name__)


class DNSProxy(DatagramProtocol):
    def __init__(self, config: config_process.Config):
        self.transport = None
        self._addrs_in_work = {}
        self.config = config

    def connection_made(self, transport: DatagramTransport) -> None:
        self.transport = transport
        logger.info("✅ DNS-прокси слушает UDP/5353")

    def datagram_received(self, data: bytes, addr_from: tuple) -> None:
        if not addr_from or not data:
            logger.error("❌ Неизвестный ответ от upstream %s", addr_from)
            return

        id = struct.unpack_from("!H", data, 0)[0]

        if addr_from == self.config.upstream:
            client_addr = self._addrs_in_work.pop(id, None)
            if client_addr:
                self.transport.sendto(data, client_addr)
                logger.info("◀️ Ответ отправлен клиенту %s",
                            client_addr)
            return

        qname = self._parse_question(data)
        if self.config.is_blacklisted(qname):
            self._send_block(data, addr_from)
            logger.info("🚫 Заблокирован домен: %s", qname)
        else:
            self._addrs_in_work[id] = addr_from
            self.transport.sendto(data, self.config.upstream)
            logger.info("▶️ Запрос отправлен на upstream %s",
                        self.config.upstream)
        return

    def error_received(self, exc) -> None:
        logger.error("🔴 Ошибка UDP: %s", exc)

    def connection_lost(self, exc) -> None:
        logger.error("🔴 UDP сокет закрыт")

    def _send_block(self, data: bytes, addr: tuple) -> None:
        if self.config.blacklist_rcode == 0x0000:
            block_data = self._build_redirect(data)
        else:
            block_data = self._build_error(data)
        self.transport.sendto(block_data, addr)
        logger.info("◀️ Ответ блокировки отправлен клиенту %s",
                    addr)
        return

    def _build_error(self, data: bytes) -> bytes:
        id = data[:2]
        flags = self._get_flags(data[2:4])
        qdcount = data[4:6]
        other_header = b'\x00\x00\x00\x00\x00\x00'  # ancount, nscount, arcount
        question = data[12:self._question_end(data)]
        return id + flags + qdcount + other_header + question

    def _build_redirect(self, data: bytes) -> bytes:
        id = data[:2]
        flags = self._get_flags(data[2:4])
        qdcount = data[4:6]
        ancount = b'\x00\x01'
        other_header = b'\x00\x00\x00\x00'  # nscount, arcount

        header = id + flags + qdcount + ancount + other_header
        question = data[12:self._question_end(data)]
        answer = self._build_redirect_answer()

        return header + question + answer

    def _build_redirect_answer(self) -> bytes:
        pointer = b'\xC0\x0C'       # offset=12
        qtype = b'\x00\x01'         # A-запрос
        qclass = b'\x00\x01'        # IN
        ttl = b'\x00\x00\x00\x3c'   # 60 секунд
        rdlength = b'\x00\x04'      # 4 байта
        rdata = socket.inet_aton(self.config.redirect_ip)
        return pointer + qtype + qclass + ttl + rdlength + rdata

    def _get_flags(self, flags: bytes) -> bytes:
        flags = struct.unpack_from("!H", flags, 0)[0]
        qr = 0x8000                          # 1000 0000 0000 0000
        rd = flags & 0x0100                  # 0000 0001 0000 0000
        ra = 0x0080                          # 0000 0000 1000 0000
        rcode = self.config.blacklist_rcode  # 0000 0000 0000 0011 - NXDOMAIN
        new_flags = qr | rd | ra | rcode     # 1000 0001 1000 0011
        return struct.pack("!H", new_flags)

    def _parse_question(self, data: bytes) -> str:
        qname = []
        offset = 12
        while data[offset] != 0:
            label_len = data[offset]
            if label_len == 0:
                break
            offset += 1
            end = offset + label_len
            qname.append(data[offset:end].decode('ascii'))
            offset = end
        return '.'.join(qname)

    def _question_end(self, data: bytes) -> int:
        offset = 12
        while data[offset] != 0:
            offset += 1 + data[offset]
        return offset + 1 + 4   # +1 - нулевой байт, +4 - QTYPE+QCLASS
