# VLESS Parser

[![Update CFG](https://github.com/coloramamoe/vless-parser/actions/workflows/auto_update.yml/badge.svg)](https://github.com/coloramamoe/vless-parser/actions/workflows/auto_update.yml)

Парсер VLESS-подписок: тянет whitelist-источники, отбрасывает битые и небезопасные конфиги и публикует готовые подписки в `githubmirror/`.

## Что делает

- `whitelist-vless.txt` — все валидные `vless://` (reality/tls, корректный UUID, без `allowinsecure`)
- `ru-sni-best-vless.txt` — shortlist: reality с русским SNI и `sid`, без `fp=randomized` и IPv6
- понимает plain text и base64-подписки, удаляет дубли

## Подписки

```text
https://raw.githubusercontent.com/coloramamoe/vless-parser/main/githubmirror/whitelist-vless.txt
https://raw.githubusercontent.com/coloramamoe/vless-parser/main/githubmirror/ru-sni-best-vless.txt
```

Источники: [`source/sources.txt`](source/sources.txt). Автообновление — GitHub Actions каждые 9 минут.

## Запуск

```bash
pip install -r source/requirements.txt
python source/main.py            # обновить файлы
python source/main.py --dry-run  # статистика без записи
```

Тесты и lint: `pip install -r source/requirements-dev.txt`, затем `python -m pytest source/test_main.py -q` и `ruff check source/`.

Лицензия: BSD-3-Clause.
