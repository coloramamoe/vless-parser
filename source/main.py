#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Fetch whitelist subscriptions, filter broken/insecure configs, write githubmirror/ files."""

import argparse
import base64
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime
from ipaddress import ip_address
from pathlib import Path
from urllib.parse import parse_qsl, unquote, urlsplit

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "source"
MIRROR = ROOT / "githubmirror"
REPO_URL = "https://github.com/coloramamoe/vless-parser"
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36")
GITHUB_HOSTS = {"github.com", "raw.githubusercontent.com", "api.github.com"}
TOKEN = os.environ.get("GITHUB_TOKEN", "").strip()

PREFIXES = ("vmess://", "vless://", "trojan://", "ss://", "ssr://",
            "tuic://", "hysteria://", "hysteria2://")
PROTO_RE = re.compile(r"(vmess|vless|trojan|ss|ssr|tuic|hysteria|hysteria2)://")
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
BASE64_RE = re.compile(r"[A-Za-z0-9+/_-]+={0,2}")
INSECURE = {"allowinsecure", "allow_insecure", "insecure"}
INSECURE_VALUES = {"1", "true", "yes"}
ALLOWED_SECURITY = {"reality", "tls"}
GOOD_PORTS = {443, 8443, 2053, 2083, 2087, 2096, 9443}
GOOD_FP = {"chrome", "firefox", "edge", "safari"}
BAD_FP = {"qq", "random", "randomized"}
TRANSPORT = {"tcp": 14, "xhttp": 12, "grpc": 10, "ws": 7}
RETRY_STATUS = (429, 500, 502, 503, 504)
NO_RETRY_STATUS = {400, 401, 403, 404, 405, 410, 451}
MAX_BYTES = 8 << 20


# ---------- text / config helpers ----------

def lines(path: Path) -> list[str]:
    out = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line and not line.startswith("#"):
            out.append(line)
    return out


def domains(path: Path) -> set[str]:
    norm = {domain(value) for value in lines(path)}
    norm.discard("")
    kept = set()
    for d in sorted(norm, key=lambda v: (len(v.split(".")), v)):
        if not matches_domain(d, kept):
            kept.add(d)
    return kept


def domain(value: str | None) -> str:
    if not value:
        return ""
    d = unquote(value).strip().strip(".").casefold()
    if not d:
        return ""
    if d.startswith("[") and "]" in d:
        d = d[1:d.index("]")]
    d = d.split(",", 1)[0].strip()
    host, sep, port = d.rpartition(":")
    return host if sep and host and port.isdigit() else d


HOST_LABEL = re.compile(r"^[a-z0-9]([a-z0-9_-]*[a-z0-9])?$")


def valid_host(value: str) -> bool:
    v = value.strip(".").casefold()
    if not v or len(v) > 253:
        return False
    if v.startswith("*."):
        v = v[2:]
    try:
        ip_address(v)
        return True
    except ValueError:
        pass
    if "/" in v or "@" in v:
        return False
    return all(bool(HOST_LABEL.match(part)) for part in v.split("."))


def matches_domain(value: str, known: set[str]) -> bool:
    d = domain(value)
    if d in known:
        return True
    parts = d.split(".")
    return any(".".join(parts[i:]) in known for i in range(1, len(parts)))


def split_configs(text: str) -> list[str]:
    compact = "".join(text.split())
    if len(compact) >= 32 and not PROTO_RE.search(text) and BASE64_RE.fullmatch(compact):
        try:
            padded = compact.replace("-", "+").replace("_", "/")
            padded += "=" * (-len(padded) % 4)
            decoded = base64.b64decode(padded).decode("utf-8", errors="replace")
            if PROTO_RE.search(decoded):
                text = decoded
        except (ValueError, base64.binascii.Error):
            pass

    split = PROTO_RE.sub(lambda m: f"\n{m.group(0)}", text)
    out = []
    for line in split.splitlines():
        line = line.strip()
        if line.lower().startswith(PREFIXES):
            out.append(line)
    return out


def insecure(uri: str) -> bool:
    q = unquote(uri.split("#", 1)[0]).partition("?")[2].replace(";", "&")
    for key, value in parse_qsl(q.replace("+", "%2B"), keep_blank_values=True):
        if key.casefold() in INSECURE and value.casefold() in INSECURE_VALUES:
            return True
    return False


# ---------- fetch ----------

def session(pool: int) -> requests.Session:
    s = requests.Session()
    retry = Retry(total=1, backoff_factor=0.3, status_forcelist=RETRY_STATUS,
                  allowed_methods=("GET", "HEAD", "OPTIONS"))
    for scheme in ("http", "https"):
        s.mount(f"{scheme}://", HTTPAdapter(pool_connections=pool, pool_maxsize=pool,
                                            max_retries=retry))
    s.headers.update({"User-Agent": UA})
    return s


def fetch(url: str, s: requests.Session) -> str:
    headers = {}
    if TOKEN and (urlsplit(url).hostname or "").casefold() in GITHUB_HOSTS:
        headers["Authorization"] = f"Bearer {TOKEN}"
    for attempt in range(2):
        try:
            with s.get(url, timeout=8, headers=headers, stream=True) as r:
                r.raise_for_status()
                chunks, total = [], 0
                for chunk in r.iter_content(64 << 10):
                    total += len(chunk)
                    if total > MAX_BYTES:
                        raise ValueError("response too large")
                    chunks.append(chunk)
                return b"".join(chunks).decode("utf-8", errors="replace")
        except requests.RequestException as exc:
            status = getattr(getattr(exc, "response", None), "status_code", None)
            if status in NO_RETRY_STATUS or attempt:
                raise
            time.sleep(0.5)
    raise ValueError("fetch failed")


def err_text(exc: Exception) -> str:
    if isinstance(exc, requests.exceptions.RetryError):
        return "connection error"
    if isinstance(exc, requests.exceptions.HTTPError):
        return f"HTTP {exc.response.status_code}"
    if isinstance(exc, requests.exceptions.ConnectTimeout):
        return "timeout"
    if isinstance(exc, requests.exceptions.ConnectionError):
        return "connection error"
    return str(exc)[:80]


# ---------- vless validation ----------

@dataclass(frozen=True)
class Config:
    raw: str
    key: tuple[str, ...]
    host: str
    port: int
    security: str
    transport: str
    sni: str
    host_header: str
    fp: str
    pbk: str
    sid: str
    path: str
    source: str


def parse_vless(uri: str, source: str) -> Config | None:
    try:
        u = urlsplit(uri)
    except ValueError:
        return None
    if u.scheme.casefold() != "vless":
        return None
    try:
        host, port = u.hostname, u.port
    except ValueError:
        return None
    if not u.username or not host or not port or not 0 < port <= 65535:
        return None
    if not UUID_RE.match(unquote(u.username).strip()):
        return None
    if not routable(host):
        return None

    q = {k.casefold(): v.strip() for k, v in
         parse_qsl(u.query.replace("+", "%2B"), keep_blank_values=True)}
    security = q.get("security", "").casefold()
    if security not in ALLOWED_SECURITY:
        return None
    if security == "reality" and not q.get("pbk"):
        return None
    sni, host_header = domain(q.get("sni")), domain(q.get("host"))
    if not sni and not host_header:
        return None
    if sni and not valid_host(sni):
        return None
    if host_header and not valid_host(host_header):
        return None

    transport = (q.get("type") or "tcp").casefold()
    key = (host.casefold(), str(port), security, transport, sni, host_header,
           q.get("pbk", ""), q.get("sid", ""), q.get("path", ""),
           (q.get("mode") or "").casefold(),
           (q.get("packetingencoding") or q.get("packetencoding") or "").casefold(),
           unquote(u.username).casefold())
    return Config(uri, key, host, port, security, transport, sni, host_header,
                  (q.get("fp") or "").casefold(), q.get("pbk", ""), q.get("sid", ""),
                  q.get("path", ""), source)


def routable(host: str) -> bool:
    h = host.strip().strip("[]").casefold()
    if not h or h == "localhost" or h.endswith(".localhost"):
        return False
    try:
        ip = ip_address(h)
    except ValueError:
        return "." in h
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or
                ip.is_multicast or ip.is_reserved or ip.is_unspecified)


def host_kind(host: str) -> str:
    try:
        return "ipv6" if ip_address(host).version == 6 else "ipv4"
    except ValueError:
        return "hostname"


# ---------- scoring / shortlist ----------

def source_bonus(url: str) -> int:
    u = url.casefold()
    if "igareck" in u or "wlrus.lol" in u:
        return 6
    if "byewhitelists" in u:
        return 4
    if "zieng2" in u:
        return 3
    return 0


def score(c: Config, ru_domains: set[str]) -> int:
    ru = matches_domain(c.sni, ru_domains) or matches_domain(c.host_header, ru_domains)
    if not ru:
        return -100
    v = 24 + (24 if c.security == "reality" else 8)
    v += TRANSPORT.get(c.transport, -6)
    v += 12 if c.pbk else -20
    v += 4 if c.sid else 0
    v += 6 if c.port in GOOD_PORTS else 0
    v += 4 if c.fp in GOOD_FP else 0
    v -= 8 if c.fp in BAD_FP else 0
    v += 2 if c.path and c.transport in {"ws", "grpc", "xhttp"} else 0
    v += 2 if host_kind(c.host) == "hostname" else 0
    v -= 10 if host_kind(c.host) == "ipv6" else 0
    return v + source_bonus(c.source)


def shortlist(configs: list[Config], domains: set[str], limit: int,
              max_per_sni: int) -> list[Config]:
    best: dict[tuple[str, int, str], tuple[int, Config]] = {}
    for c in configs:
        if c.security != "reality" or c.transport not in TRANSPORT or not c.pbk or not c.sid:
            continue
        if c.fp in BAD_FP or host_kind(c.host) == "ipv6":
            continue
        val = score(c, domains)
        if val < 60:
            continue
        k = (c.host.casefold(), c.port, c.sni or c.host_header)
        if best.get(k, (-1, None))[0] < val:
            best[k] = (val, c)

    by_sni: dict[str, list[tuple[int, Config]]] = {}
    for val, c in best.values():
        by_sni.setdefault(c.sni or c.host_header, []).append((val, c))

    out = []
    for entries in by_sni.values():
        out.extend(c for _, c in sorted(entries, key=lambda x: -x[0])[:max_per_sni])
    out.sort(key=lambda c: -score(c, domains))
    return out[:limit]


# ---------- output ----------

def header(title: str, desc: str, count: int) -> list[str]:
    return [
        f"# profile-title: {title}",
        "# profile-update-interval: 9",
        f"# profile-web-page-url: {REPO_URL}",
        "# profile-content-type: vless",
        f"# profile-desc: {desc}; Parsed by VLESS Parser; "
        f"Updated: {datetime.now(UTC).strftime('%Y-%m-%d %H:%M UTC')}",
        f"# profile-count: {count}",
        "",
    ]


def _stable(text: str) -> str:
    return re.sub(r"Updated: [0-9-]+ [0-9:]+ UTC", "Updated: X", text)


def write(path: Path, content: str, title: str, desc: str) -> bool:
    body = "\n".join(header(title, desc, len(content.splitlines()))) + content
    body = body + ("\n" if body and not body.endswith("\n") else "")
    if path.exists() and _stable(path.read_text(encoding="utf-8")) == _stable(body):
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    return True


# ---------- main ----------

def main() -> int:
    ap = argparse.ArgumentParser(description="VLESS whitelist parser")
    ap.add_argument("--dry-run", action="store_true", help="don't write files")
    ap.add_argument("--limit", type=int, default=350, help="shortlist size")
    ap.add_argument("--max-per-sni", type=int, default=8, help="shortlist cap per SNI")
    ap.add_argument("--workers", type=int, default=8)
    args = ap.parse_args()

    sources = lines(SRC / "sources.txt")
    known = domains(SRC / "domains.txt")
    s = session(min(args.workers, len(sources)))

    fetched = {}
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(fetch, url, s): (i, url) for i, url in enumerate(sources, 1)}
        for f, (i, url) in futures.items():
            try:
                fetched[i] = (url, split_configs(f.result()))
            except Exception as exc:
                print(f"error src {i}: {err_text(exc)}")

    if not fetched:
        print("no sources fetched")
        return 1

    vless = {}
    for i, (url, cfgs) in sorted(fetched.items()):
        if not cfgs:
            print(f"src {i}: EMPTY (no configs found)")
            continue
        found = {}
        for line in cfgs:
            if insecure(line):
                continue
            c = parse_vless(line, url)
            if c:
                found[c.key] = c
        vless.update(found)
        print(f"src {i}: {len(found)}/{len(cfgs)} vless")

    base = sorted(vless.values(), key=lambda c: (c.sni or c.host_header or c.host,
                                                 c.host, c.port, c.raw))
    best = shortlist(list(vless.values()), known, args.limit, args.max_per_sni)

    if not args.dry_run:
        write(MIRROR / "whitelist-vless.txt", "\n".join(c.raw for c in base),
              "VLESS Parser | Whitelist", "Whitelist VLESS configs")
        write(MIRROR / "ru-sni-best-vless.txt", "\n".join(c.raw for c in best),
              "VLESS Parser | RU SNI", "RU-SNI shortlist")

    print(f"done: {len(fetched)}/{len(sources)} sources, "
          f"{len(base)} vless, {len(best)} shortlist")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
