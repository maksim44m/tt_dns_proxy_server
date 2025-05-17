import asyncio
import struct
import pprint


class DNSProxy(asyncio.DatagramProtocol):

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        self.transport = transport
        print("✅ DNS-прокси слушает UDP/5300")

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        print(f"Получен UDP-пакет {len(data)} байт от {addr}")
        self.transport.sendto(data, addr)
        pprint(self.parse_dns_request(data))
        print()
        pprint(addr)

    def parse_dns_request(self, data: bytes) -> dict:
        return {
            "id": struct.unpack("!H", data[0:2])[0],
            "qr": struct.unpack("!B", data[2:3])[0],
            "opcode": struct.unpack("!B", data[3:4])[0],
            "aa": struct.unpack("!B", data[4:5])[0],
            "tc": struct.unpack("!B", data[5:6])[0],
        }

async def main():
    loop = asyncio.get_event_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: DNSProxy(),
        local_addr=("127.0.0.1", 5300)
    )
    await asyncio.Future()

asyncio.run(main())
