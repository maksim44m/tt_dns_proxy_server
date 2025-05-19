from dataclasses import dataclass, field
import asyncio
import re

import yaml
import aiofiles


@dataclass
class Config:
    upstream: tuple[str, int] = ("8.8.8.8", 53)
    blacklist: list[str] = field(default_factory=list)
    blacklist_patterns: list[re.Pattern] = field(default_factory=list)
    blacklist_rcode: int = 0x0005
    redirect_ip: str = "127.0.0.1"
    _reload_interval: int = 60

    async def load_loop(self) -> None:
        while True:
            try:
                await self.load_config()
            except Exception as e:
                print(f"Error loading config: {e}")
                await asyncio.sleep(10)
                continue
            await asyncio.sleep(self._reload_interval)

    async def load_config(self) -> None:
        async with aiofiles.open("config.yaml", "r") as f:
            text = await f.read()
        cfg = yaml.safe_load(text)

        self.upstream = (cfg["upstream"]["host"], cfg["upstream"]["port"])
        self.blacklist = cfg["blacklist"]
        # Преобразование шаблонов доменов в регулярные выражения
        new_patterns = [
            re.compile(self._convert_wildcard_to_regex(domain))
            for domain in self.blacklist
        ]

        self.blacklist_patterns = new_patterns
        response_type = cfg["blacklist_response_type"]
        if response_type == "NXDOMAIN":
            self.blacklist_rcode = 0x0003
        elif response_type == "REFUSED":
            self.blacklist_rcode = 0x0005
        elif response_type == "REDIRECT":
            self.blacklist_rcode = 0x0000

        self.redirect_ip = cfg["redirect_ip"]
        self._reload_interval = cfg.get(
            "reload_interval", self._reload_interval)

    def _convert_wildcard_to_regex(self, domain: str) -> str:
        """Преобразование шаблона с wildcard в регулярное выражение."""
        # Экранирование специальных символов кроме *
        escaped = re.escape(domain).replace("\\*", ".*")
        # Добавляем ограничители начала и конца строки
        return f"^{escaped}$"

    def is_blacklisted(self, domain: str) -> bool:
        """Проверка домена на соответствие шаблонам черного списка."""
        # Проверка на точное совпадение
        if domain in self.blacklist:
            return True

        # Проверка на соответствие шаблонам
        for pattern in self.blacklist_patterns:
            if pattern.match(domain):
                return True

        return False
