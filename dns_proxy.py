#!/usr/bin/env python3
import asyncio
import struct
import pprint

UPSTREAM = ("8.8.8.8", 53)

class DNSProxy(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport
        print("✅ DNS-прокси слушает UDP/5353")

    def datagram_received(self, data, addr):
        # Логи получения
        print(f"▶️ Запрос {len(data)} байт от {addr}")
        pprint.pprint(self._parse_header(data))

        if addr == UPSTREAM:
            # пришёл ответ от Google DNS
            self.transport.sendto(data, self._last_client)
            print("◀️ Ответ отправлен клиенту", self._last_client)
            return

        # Отправляем на upstream
        self.transport.sendto(data, UPSTREAM)
        print("▶️ Запрос отправлен на upstream", UPSTREAM)

        # Ждём ответ от upstream в том же протоколе
        # Он придёт в тот же метод datagram_received,
        # но addr уже будет ("8.8.8.8", 53)
        # поэтому поймаем его там и пошлём назад клиенту.
        # Для простоты различаем по addr:
        #   если addr == UPSTREAM — это ответ, шлём клиенту
        self._last_client = addr

    def _parse_header(self, data: bytes) -> dict:
        # Только пара полей для примера
        qid = struct.unpack("!H", data[0:2])[0]
        flags = struct.unpack("!H", data[2:4])[0]
        qr = (flags >> 15) & 0x1
        tc = (flags >> 9) & 0x1
        return {"id": qid, "qr": qr, "tc": tc}

    def error_received(self, exc):
        print("‼️ Ошибка UDP:", exc)

    def connection_lost(self, exc):
        print("🔴 UDP сокет закрыт")

async def main():
    loop = asyncio.get_event_loop()
    # Привязываемся к 0.0.0.0:5353
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: DNSProxy(),
        local_addr=("0.0.0.0", 5353)
    )
    # Блокируемся навсегда
    await asyncio.Future()

if __name__ == "__main__":
    asyncio.run(main())
