#!/usr/bin/env python3

import re
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import unquote, urlsplit

import requests

ROOT = Path(__file__).resolve().parent.parent
SOURCES = ROOT / "source" / "sources.txt"
README = ROOT / "README.md"
MARKDOWN_LINK = re.compile(r"\[[^\]]+\]\(([^)]+)\)")


def links() -> list[str]:
    source_links = [
        line.strip()
        for line in SOURCES.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    readme_links = [
        url
        for url in re.findall(r"https?://[^\s)\]>`]+", README.read_text(encoding="utf-8"))
        if "/badge.svg" not in url
    ]
    return list(dict.fromkeys(source_links + readme_links))


def local_links() -> list[str]:
    markdown = README.read_text(encoding="utf-8")
    return [
        target
        for target in MARKDOWN_LINK.findall(markdown)
        if not urlsplit(target).scheme and not target.startswith("#")
    ]


def check(url: str) -> tuple[str, str]:
    if urlsplit(url).scheme != "https":
        return url, "URL must use HTTPS"
    try:
        response = requests.get(url, timeout=(8, 20), stream=True, allow_redirects=True)
        try:
            response.raise_for_status()
            if urlsplit(response.url).scheme != "https":
                return url, "redirected to a non-HTTPS URL"
            return url, f"HTTP {response.status_code}"
        finally:
            response.close()
    except requests.RequestException as exc:
        return url, str(exc)


def main() -> int:
    urls = links()
    failed = False
    for target in local_links():
        path = (ROOT / unquote(target.split("#", 1)[0])).resolve()
        try:
            path.relative_to(ROOT.resolve())
            exists = path.exists()
        except ValueError:
            exists = False
        state = "OK" if exists else "FAIL"
        detail = "file exists" if exists else "file missing"
        print(f"{state} {target}: {detail}")
        failed |= not exists

    if not urls:
        print("FAIL no external URLs found")
        return 1

    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(check, urls))

    for url, result in results:
        ok = result.startswith("HTTP ")
        print(f"{'OK' if ok else 'FAIL'} {url}: {result}")
        failed |= not ok

    print(f"checked {len(urls)} URLs")
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
