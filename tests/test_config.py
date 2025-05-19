import pytest
import yaml
import asyncio
from pathlib import Path

from config_process import Config


@pytest.fixture
def cwd_tmp_path(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    return tmp_path


@pytest.mark.asyncio
async def test_load_config_creates_fields(cwd_tmp_path):
    data = {"upstream": {"host": "1.1.1.1", "port": 5353},
            "blacklist": ["a.com", "b.com"],
            "blacklist_response_type": "REDIRECT",
            "redirect_ip": "2.2.2.2",
            "reload_interval": 2}
    Path("config.yaml").write_text(yaml.safe_dump(data))

    cfg = Config()
    # До загрузки — дефолты
    assert cfg.upstream == ("8.8.8.8", 53)
    assert cfg.blacklist == []
    # Первичная загрузка
    await cfg.load_config()
    # После загрузки
    assert cfg.upstream == ("1.1.1.1", 5353)
    assert cfg.blacklist == ["a.com", "b.com"]
    assert cfg.redirect_ip == "2.2.2.2"
    assert cfg.blacklist_rcode == 0x0000
    assert cfg._reload_interval == 2


@pytest.mark.asyncio
async def test_watch_loop_reloads(cwd_tmp_path):
    cfg_file = Path("config.yaml")
    data = {"upstream": {"host": "9.9.9.9", "port": 53},
            "blacklist": ["x.com"],
            "blacklist_response_type": "NXDOMAIN",
            "redirect_ip": "0.0.0.0",
            "reload_interval": 1}
    cfg_file.write_text(yaml.safe_dump(data))

    cfg = Config()
    await cfg.load_config()
    task = asyncio.create_task(cfg.load_loop())
    # подмена файла
    await asyncio.sleep(0.1)
    data = {"upstream": {"host": "8.8.4.4", "port": 53},
            "blacklist": ["y.com"],
            "blacklist_response_type": "REFUSED",
            "redirect_ip": "127.0.0.1",
            "reload_interval": 1}
    cfg_file.write_text(yaml.safe_dump(data))
    # пауза 1 + 0.1 + 0.1 секунды
    await asyncio.sleep(1.2)
    # проверим, что обновилось
    assert cfg.upstream == ("8.8.4.4", 53)
    assert cfg.blacklist == ["y.com"]
    assert cfg.blacklist_rcode == 0x0005  # REFUSED
    task.cancel()


@pytest.mark.asyncio
async def test_wildcard_blacklist_patterns(cwd_tmp_path):
    """Тест для проверки работы с wildcard-доменами."""
    data = {"upstream": {"host": "8.8.8.8", "port": 53},
            "blacklist": [
                "example.com",        # точное соответствие
                "*.badwebsite.org",   # все поддомены
                "tracker.*",          # все домены начинающиеся с tracker.
                "*.test.*"            # домены содержащие .test.
    ],
        "blacklist_response_type": "REFUSED",
        "redirect_ip": "127.0.0.1"}

    cfg_file = Path("config.yaml")
    cfg_file.write_text(yaml.safe_dump(data))

    cfg = Config()
    await cfg.load_config()

    # Проверка точного соответствия
    assert cfg.is_blacklisted("example.com") == True
    assert cfg.is_blacklisted("notexample.com") == False

    # Проверка доменов с wildcard в начале
    # сам домен не блокируется
    assert cfg.is_blacklisted("badwebsite.org") == False
    assert cfg.is_blacklisted("sub.badwebsite.org") == True
    assert cfg.is_blacklisted("deep.sub.badwebsite.org") == True

    # Проверка доменов с wildcard в конце
    assert cfg.is_blacklisted("tracker.com") == True
    assert cfg.is_blacklisted("tracker.org") == True
    assert cfg.is_blacklisted("mytracker.com") == False  # не блокируется

    # Проверка доменов с wildcard в середине и по краям
    assert cfg.is_blacklisted("sub.test.com") == True
    assert cfg.is_blacklisted("my.test.org") == True
    assert cfg.is_blacklisted("justtest.com") == False  # не содержит .test.
