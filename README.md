# nr-authz-radar

New Relic を使って API の認可攻撃（IDOR / BOLA・SQLi など）に気づき、ソースコードの認可の抜けを監査する Claude Code プラグイン。

**プラグイン本体と README は [`plugin/`](plugin/) にあります → [plugin/README.md](plugin/README.md)**（[English](plugin/README.en.md)）。

このリポジトリの構成:

| 場所 | 内容 |
|---|---|
| [`plugin/`](plugin/) | 配布されるプラグイン（skills・scripts・shared・templates・instrumentation・docs） |
| [`examples/`](examples/) | ローカルで試す脆弱なデモ（**開発用**。プラグインには含まれない） |
| [`tests/`](tests/) | テスト（**開発用**。プラグインには含まれない） |

インストールと使い方は [plugin/docs/getting-started.md](plugin/docs/getting-started.md)、現状（今できること）は [plugin/docs/status.md](plugin/docs/status.md)。

## License

MIT（[LICENSE](LICENSE)）
