from __future__ import annotations

import base64
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import main


def build_uri(**overrides: str) -> str:
    parts = {
        "uuid": "b12eebc2-369c-4f3c-96a0-a8bd150ca8d5",
        "host": "example.com",
        "port": "443",
        "query": "type=tcp&security=reality&pbk=Lxs8Ruv2zHH0XW5EiQmu&sni=avito.ru",
        "fragment": "node",
    }
    parts.update(overrides)
    return (
        f"vless://{parts['uuid']}@{parts['host']}:{parts['port']}"
        f"?{parts['query']}#{parts['fragment']}"
    )


def parse(uri: str):
    return main.parse_vless(uri, source="test")


class TestSplitConfigs:
    def test_plain_lines(self):
        data = f"{build_uri()}\n{build_uri(host='other.com')}"
        assert len(main.split_configs(data)) == 2

    def test_comments_are_dropped(self):
        data = f"# a comment\n{build_uri()}"
        assert main.split_configs(data) == [build_uri()]

    def test_glued_configs_are_split(self):
        data = build_uri() + build_uri(host="other.com")
        assert len(main.split_configs(data)) == 2

    def test_base64_subscription_is_decoded(self):
        payload = f"{build_uri()}\n{build_uri(host='other.com')}"
        encoded = base64.b64encode(payload.encode()).decode()
        assert len(main.split_configs(encoded)) == 2

    def test_urlsafe_base64_without_padding_is_decoded(self):
        payload = f"{build_uri()}\n{build_uri(host='other.com')}"
        encoded = base64.urlsafe_b64encode(payload.encode()).decode().rstrip("=")
        assert len(main.split_configs(encoded)) == 2

    def test_plain_text_is_kept_not_decoded(self):
        assert main.split_configs(build_uri()) == [build_uri()]

    def test_random_base64_without_uris_is_ignored(self):
        encoded = base64.b64encode(b"just some unrelated content here").decode()
        assert main.split_configs(encoded) == []


class TestInsecure:
    @pytest.mark.parametrize(
        "query",
        [
            "security=tls&sni=avito.ru&allowInsecure=1",
            "security=tls&sni=avito.ru&allow_insecure=true",
            "security=tls&sni=avito.ru&insecure=yes",
            "security=tls&sni=avito.ru;insecure=yes",
        ],
    )
    def test_insecure_flags_are_detected(self, query: str):
        assert main.insecure(build_uri(query=query)) is True

    def test_clean_uri_is_secure(self):
        assert main.insecure(build_uri()) is False

    def test_flag_inside_remark_is_ignored(self):
        assert main.insecure(build_uri(fragment="node%20%3Fallowinsecure%3D1")) is False

    def test_percent_encoded_flag_is_detected(self):
        assert main.insecure(build_uri(query="security=tls&allowinsecure%3D1")) is True

    def test_flag_without_value_is_ignored(self):
        assert main.insecure(build_uri(query="security=tls&sni=avito.ru&allowinsecure")) is False

    def test_flag_inside_value_is_ignored(self):
        assert main.insecure(build_uri(query="security=tls&path=/xallowinsecure=1")) is False


class TestParseVless:
    @pytest.mark.parametrize(
        "host",
        ["127.0.0.1", "10.0.0.5", "192.168.1.1", "0.0.0.0", "169.254.1.1", "localhost"],
    )
    def test_unroutable_hosts_are_rejected(self, host: str):
        assert parse(build_uri(host=host)) is None

    @pytest.mark.parametrize("host", ["example.com", "8.8.8.8", "193.233.126.104"])
    def test_routable_hosts_are_accepted(self, host: str):
        assert parse(build_uri(host=host)) is not None

    def test_placeholder_id_is_rejected(self):
        assert parse(build_uri(uuid="xxxxxxxxxx1")) is None

    def test_uppercase_uuid_is_accepted(self):
        assert parse(build_uri(uuid="B12EEBC2-369C-4F3C-96A0-A8BD150CA8D5")) is not None

    def test_reality_without_pbk_is_rejected(self):
        assert parse(build_uri(query="type=tcp&security=reality&sni=avito.ru")) is None

    def test_tls_without_pbk_is_accepted(self):
        assert parse(build_uri(query="type=tcp&security=tls&sni=avito.ru")) is not None

    def test_missing_security_is_rejected(self):
        assert parse(build_uri(query="type=tcp&sni=avito.ru")) is None

    def test_missing_sni_and_host_is_rejected(self):
        assert parse(build_uri(query="type=tcp&security=tls")) is None

    def test_non_vless_scheme_is_rejected(self):
        assert parse("trojan://pass@example.com:443?security=tls&sni=avito.ru") is None

    def test_literal_plus_in_path_is_preserved(self):
        config = parse(build_uri(query="type=ws&security=tls&sni=avito.ru&path=/a+b"))
        assert config is not None
        assert config.path == "/a+b"

    def test_percent_encoded_space_in_path_is_decoded(self):
        config = parse(build_uri(query="type=ws&security=tls&sni=avito.ru&path=/a%20b"))
        assert config is not None
        assert config.path == "/a b"


class TestDedupeKey:
    def test_remark_does_not_affect_key(self):
        assert parse(build_uri(fragment="AAA")).key == parse(build_uri(fragment="BBB")).key

    def test_query_order_does_not_affect_key(self):
        first = parse(build_uri(query="type=tcp&security=tls&sni=avito.ru"))
        second = parse(build_uri(query="sni=avito.ru&type=tcp&security=tls"))
        assert first.key == second.key

    def test_case_and_trailing_dot_do_not_affect_key(self):
        first = parse(build_uri(host="Example.COM", query="security=tls&sni=Avito.RU."))
        second = parse(build_uri(host="example.com", query="security=tls&sni=avito.ru"))
        assert first.key == second.key

    def test_different_uuid_yields_different_key(self):
        first = parse(build_uri())
        second = parse(build_uri(uuid="00000000-0000-4000-8000-000000000000"))
        assert first.key != second.key


class TestDomains:
    def test_redundant_subdomains_are_pruned(self, tmp_path: Path):
        path = tmp_path / "domains.txt"
        path.write_text("avito.ru\nsub.avito.ru\nvk.com\nwww.sub.avito.ru\n", encoding="utf-8")
        assert main.domains(path) == {"avito.ru", "vk.com"}

    def test_unrelated_domains_are_kept(self, tmp_path: Path):
        path = tmp_path / "domains.txt"
        path.write_text("a.b.ru\nc.d.com\n", encoding="utf-8")
        assert main.domains(path) == {"a.b.ru", "c.d.com"}

    def test_comments_and_blank_lines_are_ignored(self, tmp_path: Path):
        path = tmp_path / "domains.txt"
        path.write_text("# comment\n\navito.ru\n", encoding="utf-8")
        assert main.domains(path) == {"avito.ru"}

    def test_matches_domain_exact_and_subdomain(self):
        known = {"avito.ru", "vk.com"}
        assert main.matches_domain("avito.ru", known) is True
        assert main.matches_domain("sub.vk.com", known) is True
        assert main.matches_domain("evil-avito.ru", known) is False
        assert main.matches_domain("notvk.com", known) is False


class TestShortlist:
    def _config(self, query: str):
        config = parse(build_uri(query=query))
        assert config is not None
        return config

    def test_reality_without_sid_is_rejected(self):
        config = self._config("type=tcp&security=reality&pbk=abc&sni=avito.ru&fp=chrome")
        assert main.shortlist([config], {"avito.ru"}, limit=10) == []

    def test_reality_with_sid_is_selected(self):
        config = self._config("type=tcp&security=reality&pbk=abc&sid=123456&sni=avito.ru&fp=chrome")
        selected = main.shortlist([config], {"avito.ru"}, limit=10)
        assert len(selected) == 1

    def test_non_ru_sni_is_not_selected(self):
        cfg = ("type=tcp&security=reality&pbk=abc&sid=123456"
               "&sni=google.com&fp=chrome")
        config = self._config(cfg)
        assert main.shortlist([config], {"avito.ru"}, limit=10) == []

    def test_duplicates_are_deduped(self):
        one = self._config("type=tcp&security=reality&pbk=abc&sid=123456&sni=avito.ru&fp=chrome")
        two = self._config("type=ws&security=reality&pbk=abc&sid=123456&sni=avito.ru&fp=chrome")
        assert len(main.shortlist([one, two], {"avito.ru"}, limit=10)) == 1


class FakeResp:
    def __init__(self, chunks):
        self.chunks = chunks

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def raise_for_status(self):
        pass

    def iter_content(self, chunk_size):
        yield from self.chunks


class TestFetch:
    def test_utf8_cyrillic_is_not_garbled(self, monkeypatch):
        payload = "vless://uuid@host:443?security=reality&sni=авито.рф"
        monkeypatch.setattr(main.requests.Session, "get",
                           lambda *a, **k: FakeResp([payload.encode("utf-8")]))
        assert main.fetch("https://example.com", main.session(1)) == payload

    def test_streaming_over_limit_is_rejected(self, monkeypatch):
        monkeypatch.setattr(main.requests.Session, "get",
                           lambda *a, **k: FakeResp([b"a" * 700, b"b" * 700]))
        monkeypatch.setattr(main, "MAX_BYTES", 1000)
        with pytest.raises(ValueError, match="too large"):
            main.fetch("https://example.com", main.session(1))


class TestWrite:
    def test_returns_true_on_change_false_when_same(self, tmp_path: Path):
        path = tmp_path / "out.txt"
        assert main.write(path, "a\nb\n", "Title", "desc") is True
        assert main.write(path, "a\nb\n", "Title", "desc") is False
        assert path.read_text(encoding="utf-8").startswith("# profile-title: Title")

    def test_plain_file_has_no_header(self, tmp_path: Path):
        path = tmp_path / "mirror.txt"
        main.write(path, "vless://x@h:443?security=tls&sni=avito.ru")
        assert path.read_text(encoding="utf-8").startswith("vless://")
