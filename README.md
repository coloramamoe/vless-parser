# vless-parser

VLESS subscriptions from public sources. Written in Go; live checks use Mihomo.

| Feed | Use |
| --- | --- |
| [full.txt](https://raw.githubusercontent.com/coloramamoe/vless-parser/main/githubmirror/full.txt) | All valid links |
| [whitelist-vless.txt](https://raw.githubusercontent.com/coloramamoe/vless-parser/main/githubmirror/whitelist-vless.txt) | SNI from the [domain list](source/domains.txt) |
| [ru-sni-best-vless.txt](https://raw.githubusercontent.com/coloramamoe/vless-parser/main/githubmirror/ru-sni-best-vless.txt) | Short RU shortlist |
| [internet.txt](https://raw.githubusercontent.com/coloramamoe/vless-parser/main/githubmirror/internet.txt) | Passed two HTTP checks through the proxy |

Checks run from GitHub Actions. Reachability from your network may differ. Empty runs keep the last nonempty feed.

Sources: [source/sources.txt](source/sources.txt). Updates run hourly.

```sh
go run . --dry-run
go run . --check --mihomo /path/to/mihomo
go test ./...
```

BSD-3-Clause.
