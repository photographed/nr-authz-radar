# Knowledge 用ランブック

New Relic Knowledge に登録して、Autopilot が調査中に参照できるようにする。アラート条件の `runbook_url` からもリンクされる。
1つの文書に1つのテーマ（検知のまとまり）を書く。

| ファイル | 対象の検知 |
|---|---|
| `idor.md` | D01・D02・D03 |
| `recon.md` | D04 |
| `sqli.md` | D06・D07 |
| `auth.md` | D10・D11 |
| `automation.md` | D12 |
| `rce.md` | D21（D20 を併せて確認） |

各ランブックの構成: 意味 → 最初の15分（今わかることを集める）→ 判断 → 封じ込め（承認制）→ ④ 調査へ → 誤検知 → 再発防止。
クエリの ID（D・U・I）は `skills/nr-appsec-guard/references/` を参照。
