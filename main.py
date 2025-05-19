import asyncio

import config_process
from dns_proxy import DNSProxy


async def main():
    config = config_process.Config()
    await config.load_config()
    asyncio.create_task(config.load_loop())

    loop = asyncio.get_event_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: DNSProxy(config),
        local_addr=("0.0.0.0", 5353)
    )
    await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(main())
