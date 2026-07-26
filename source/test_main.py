from __future__ import annotations

import base64
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import main


def parse(uri: str):
    return main.parse_vless_uri(uri, source_index=1, source_url="test")


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


class TestSplitSubscriptionLines:
    def test_plain_lines(self):
        data = f"{build_uri()}\n{build_uri(host='other.com')}"
        assert len(main.split_subscription_lines(data)) == 2

    def test_indented_comment_is_dropped(self):
        data = f"   # a comment\n{build_uri()}"
        assert main.split_subscription_lines(data) == [build_uri()]

    def test_configs_glued_on_one_line_are_split(self):
        data = build_uri() + build_uri(host="other.com")
        assert len(main.split_subscription_lines(data)) == 2

    def test_base64_subscription_is_decoded(self):
        payload = f"{build_uri()}\n{build_uri(host='other.com')}"
        encoded = base64.b64encode(payload.encode()).decode()
        assert len(main.split_subscription_lines(encoded)) == 2

    def test_base64_urlsafe_without_padding_is_decoded(self):
        payload = f"{build_uri()}\n{build_uri(host='other.com')}"
        encoded = base64.urlsafe_b64encode(payload.encode()).decode().rstrip("=")
        assert len(main.split_subscription_lines(encoded)) == 2

    def test_plain_text_is_not_treated_as_base64(self):
        assert main.decode_base64_subscription(build_uri()) is None

    def test_random_base64_without_uris_is_ignored(self):
        encoded = base64.b64encode(b"just some unrelated content here").decode()
        assert main.decode_base64_subscription(encoded) is None


class TestLoadSources:
    def test_ignores_comments_and_duplicates_preserving_order(self, tmp_path: Path):
        path = tmp_path / "sources.txt"
        path.write_text(
            "# preferred source first\n\nhttps://first.example/list\n"
            "https://second.example/list\nhttps://first.example/list\n",
            encoding="utf-8",
        )

        assert main.load_sources(path) == [
            "https://first.example/list",
            "https://second.example/list",
        ]

    @pytest.mark.parametrize("content", ["ftp://example.com/list\n", "example.com/list\n"])
    def test_rejects_invalid_urls(self, tmp_path: Path, content: str):
        path = tmp_path / "sources.txt"
        path.write_text(content, encoding="utf-8")

        with pytest.raises(ValueError, match="URLs must start"):
            main.load_sources(path)

    def test_rejects_missing_or_empty_file(self, tmp_path: Path):
        missing_path = tmp_path / "missing.txt"
        with pytest.raises(FileNotFoundError, match="Sources file not found"):
            main.load_sources(missing_path)

        empty_path = tmp_path / "empty.txt"
        empty_path.write_text("# no sources\n\n", encoding="utf-8")
        with pytest.raises(ValueError, match="Sources file is empty"):
            main.load_sources(empty_path)


class TestIsInsecureUri:
    @pytest.mark.parametrize(
        "query",
        [
            "security=tls&sni=avito.ru&allowInsecure=1",
            "security=tls&sni=avito.ru&allow_insecure=true",
            "security=tls&sni=avito.ru&insecure=yes",
        ],
    )
    def test_insecure_flags_are_detected(self, query: str):
        assert main.is_insecure_uri(build_uri(query=query)) is True

    def test_clean_uri_is_secure(self):
        assert main.is_insecure_uri(build_uri()) is False

    def test_flag_inside_remark_is_ignored(self):
        uri = build_uri(fragment="node%20%3Fallowinsecure%3D1")
        assert main.is_insecure_uri(uri) is False


class TestHostValidation:
    @pytest.mark.parametrize(
        "host",
        ["127.0.0.1", "10.0.0.5", "192.168.1.1", "0.0.0.0", "169.254.1.1", "localhost"],
    )
    def test_unroutable_hosts_are_rejected(self, host: str):
        config, reason = parse(build_uri(host=host))
        assert config is None
        assert reason == "unroutable_host"

    @pytest.mark.parametrize("host", ["example.com", "8.8.8.8", "193.233.126.104"])
    def test_routable_hosts_are_accepted(self, host: str):
        config, _ = parse(build_uri(host=host))
        assert config is not None


class TestUserIdValidation:
    def test_placeholder_id_is_rejected(self):
        config, reason = parse(build_uri(uuid="xxxxxxxxxx1"))
        assert config is None
        assert reason == "bad_uuid"

    def test_uppercase_uuid_is_accepted(self):
        config, _ = parse(build_uri(uuid="B12EEBC2-369C-4F3C-96A0-A8BD150CA8D5"))
        assert config is not None


class TestSecurityValidation:
    def test_reality_without_pbk_is_rejected(self):
        config, reason = parse(build_uri(query="type=tcp&security=reality&sni=avito.ru"))
        assert config is None
        assert reason == "reality_missing_pbk"

    def test_tls_without_pbk_is_accepted(self):
        config, _ = parse(build_uri(query="type=tcp&security=tls&sni=avito.ru"))
        assert config is not None

    def test_missing_security_is_rejected(self):
        config, reason = parse(build_uri(query="type=tcp&sni=avito.ru"))
        assert config is None
        assert reason == "bad_security"

    def test_missing_sni_and_host_is_rejected(self):
        config, reason = parse(build_uri(query="type=tcp&security=tls"))
        assert config is None
        assert reason == "missing_sni_host"

    def test_non_vless_scheme_is_rejected(self):
        config, reason = parse("trojan://pass@example.com:443?security=tls&sni=avito.ru")
        assert config is None
        assert reason == "non_vless"

    def test_post_quantum_encryption_is_preserved(self):
        query = (
            "type=tcp&security=tls&sni=avito.ru"
            "&encryption=mlkem768x25519plus.native.0rtt.acjHXqKWEZtVE-QeN5i1"
        )
        config, _ = parse(build_uri(query=query))
        assert config is not None


class TestDedupeKey:
    def test_remark_does_not_affect_key(self):
        first, _ = parse(build_uri(fragment="AAA"))
        second, _ = parse(build_uri(fragment="BBB"))
        assert first.dedupe_key == second.dedupe_key

    def test_query_order_does_not_affect_key(self):
        first, _ = parse(build_uri(query="type=tcp&security=tls&sni=avito.ru"))
        second, _ = parse(build_uri(query="sni=avito.ru&type=tcp&security=tls"))
        assert first.dedupe_key == second.dedupe_key

    def test_case_and_trailing_dot_do_not_affect_key(self):
        first, _ = parse(build_uri(host="Example.COM", query="security=tls&sni=Avito.RU."))
        second, _ = parse(build_uri(host="example.com", query="security=tls&sni=avito.ru"))
        assert first.dedupe_key == second.dedupe_key

    def test_different_uuid_yields_different_key(self):
        first, _ = parse(build_uri())
        second, _ = parse(build_uri(uuid="00000000-0000-4000-8000-000000000000"))
        assert first.dedupe_key != second.dedupe_key


class TestDomainMatching:
    def test_exact_and_subdomain_match(self):
        domains = {"avito.ru", "vk.com"}
        assert main.matches_domain("avito.ru", domains) is True
        assert main.matches_domain("sub.vk.com", domains) is True

    def test_suffix_lookalike_does_not_match(self):
        domains = {"avito.ru", "vk.com"}
        assert main.matches_domain("evil-avito.ru", domains) is False
        assert main.matches_domain("notvk.com", domains) is False


class TestRetryPolicy:
    def test_client_errors_are_not_retried(self):
        for status in (403, 404):
            assert main.is_retryable_error(_http_error(status)) is False

    def test_server_errors_are_retried(self):
        for status in (429, 500, 503):
            assert main.is_retryable_error(_http_error(status)) is True

    def test_connection_errors_are_retried(self):
        import requests

        assert main.is_retryable_error(requests.exceptions.ConnectTimeout()) is True


def _http_error(status: int):
    import requests

    response = requests.Response()
    response.status_code = status
    return requests.exceptions.HTTPError(response=response)


def test_dry_run_does_not_write_output(tmp_path: Path):
    output_path = tmp_path / "whitelist-vless.txt"
    profile = main.OutputProfile("base", output_path, "Test", "Test output")

    summary = main.write_output(profile, [build_uri()], dry_run=True)

    assert summary.changed is True
    assert output_path.exists() is False
