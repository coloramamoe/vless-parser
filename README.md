# VLESS Parser

[![Update CFG](https://github.com/coloramamoe/vless-parser/actions/workflows/auto_update.yml/badge.svg)](https://github.com/coloramamoe/vless-parser/actions/workflows/auto_update.yml)

Минималистичный `VLESS` parser для белых списков.
fork https://github.com/AvenCores/goida-vpn-configs

Скрипт обновляет два файла:
- `githubmirror/whitelist-vless.txt` — полный whitelist-список
- `githubmirror/ru-sni-best-vless.txt` — более жёстко отфильтрованный shortlist с русским `SNI`

Что делает parser:
- ходит только во внешние whitelist-источники
- понимает как обычные, так и `base64`-подписки
- оставляет только `vless://`
- отбрасывает конфиги с `allowinsecure` (флаг ищется только в query, а не в `#remark`)
- оставляет только `security=reality` или `security=tls`
- требует `pbk` у `security=reality` — без него конфиг нерабочий
- требует валидный `UUID` в качестве идентификатора
- отбрасывает нероутабельные хосты: `localhost`, приватные, loopback и link-local адреса
- требует наличие `sni` или `host`
- удаляет дубли по серверным параметрам
- сортирует основной файл стабильно, чтобы он не дёргался без причины
- сравнивает текущее и новое содержимое и пишет в лог: изменился файл или нет, сколько строк добавилось и удалилось
- добавляет metadata-шапку с названием профиля, описанием `Parsed by VLESS Parser` и временем последнего обновления содержимого

`ru-sni-best-vless.txt` — это не гарантия, а эвристический shortlist. Туда попадают только более жёстко отобранные конфиги: с русским `SNI`, `security=reality`, `pbk`, нормальным transport и без явных слабых признаков вроде `fp=randomized` или IPv6.

## Источники

Используются только whitelist-источники из [`source/sources.txt`](./source/sources.txt). Добавляйте, удаляйте или меняйте URL в этом файле: один URL в строке. Пустые строки и строки с `#` в начале игнорируются; допустимы только URL, начинающиеся с `http://` или `https://`. Повторяющиеся URL отбрасываются с сохранением порядка — более ранний источник имеет приоритет при дедупликации конфигов.

Если часть источников временно недоступна, parser продолжает работу по тем, которые ответили. Если не ответил ни один источник, существующий `githubmirror/whitelist-vless.txt` не перезаписывается.

## Локальный запуск

```bash
git clone https://github.com/<you>/<repo>.git
cd <repo>
python -m pip install -r source/requirements.txt
echo GITHUB_TOKEN=<your_token> > .env
python source/main.py
```

Проверить доступность источников и итоговую статистику без изменения файлов в `githubmirror/`:

```bash
python source/main.py --dry-run
```

Файл результата:

```text
githubmirror/whitelist-vless.txt
githubmirror/ru-sni-best-vless.txt
```

Дополнительные параметры:

```bash
python source/main.py --output githubmirror/whitelist-vless.txt --reliable-output githubmirror/ru-sni-best-vless.txt --timeout 8 --max-attempts 2 --max-workers 8 --reliable-limit 200
```

## Тесты

```bash
python -m pip install -r source/requirements-dev.txt
python -m pytest source/test_main.py -q
```

## GitHub Actions

Workflow в [.github/workflows/auto_update.yml](./.github/workflows/auto_update.yml) делает только две вещи:
1. запускает parser
2. коммитит `githubmirror/whitelist-vless.txt` и `githubmirror/ru-sni-best-vless.txt`, если они изменились

Python-скрипт больше не пушит в git и не зависит от `MY_TOKEN`.

## Структура

```text
.github/workflows/auto_update.yml  - автообновление каждые 9 минут
githubmirror/whitelist-vless.txt   - итоговая whitelist VLESS-подписка
githubmirror/ru-sni-best-vless.txt - shortlist более жёстко отобранных RU-SNI конфигов
source/main.py                     - parser
source/test_main.py                - тесты
source/sources.txt                 - URL whitelist-источников в порядке приоритета
source/domains.txt                 - домены для RU-SNI shortlist
source/requirements.txt            - зависимости
source/requirements-dev.txt        - зависимости для тестов
```

## Примечание

Это whitelist-only fork. Автоматизация обновляет `githubmirror/whitelist-vless.txt` и `githubmirror/ru-sni-best-vless.txt`.

`GITHUB_TOKEN` в корневом `.env` необязателен, но если он задан, parser будет использовать его только для запросов к GitHub-хостам.
