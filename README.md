# vless-parser

VLESS subscriptions from public sources. Written in Go; live checks use Mihomo.

| Feed | Use |
| --- | --- |
| [full.txt](https://raw.githubusercontent.com/coloramamoe/vless-parser/main/githubmirror/full.txt) | All valid links |
| [whitelist-vless.txt](https://raw.githubusercontent.com/coloramamoe/vless-parser/main/githubmirror/whitelist-vless.txt) | SNI from the [domain list](sources/domains.txt) |
| [ru-sni-best-vless.txt](https://raw.githubusercontent.com/coloramamoe/vless-parser/main/githubmirror/ru-sni-best-vless.txt) | Short RU shortlist |
| [internet.txt](https://raw.githubusercontent.com/coloramamoe/vless-parser/main/githubmirror/internet.txt) | Passed two HTTP checks through the proxy |

Checks run from GitHub Actions. A matching SNI alone does not prove access on a mobile network. Empty runs keep the last nonempty feed.

Sources: [VLESS](sources/vless.txt), [domains](sources/domains.urls). Updates are scheduled every 9 minutes.
Domain data: [hxehex/russia-mobile-internet-whitelist](https://github.com/hxehex/russia-mobile-internet-whitelist) (MIT).

```sh
go run ./src --dry-run
go run ./src --check --mihomo /path/to/mihomo
go test ./...
```

BSD-3-Clause.
