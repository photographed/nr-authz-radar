# 優先度ランキング仕様

計算は `scripts/risk_score.py` が決定的に行う。**Claude は特徴量の抽出まで**を担当し、点数付けはしない。
同じ入力なら必ず同じ順位になり、点数の内訳（`breakdown`）をレポートに出せる。

## 原則

```
優先度 = 本来の危険度（コードから判定。順位の主軸）
       + 攻撃兆候による引き上げ（兆候があれば P0）
       + 実トラフィックによる微調整（同じ段階の中での並び順にだけ使う）
```

- **トラフィックは順位を下げない。** 使われていない重大 API は、攻撃者にとってむしろ狙い目
  （アプリ解析で見つかる旧 API、監視されていない内部 API）。
- **トラフィック0 ≠ 未使用。** New Relic で観測されないのは、計装漏れ・別サービス・トランザクション名の集約が原因の場合もある。
  そのため `traffic_rpm: null`（未観測）と `0`（観測できていて0件）を区別する。

## 1. 本来の危険度 = 影響度 (0–5) × 攻撃のしやすさ (0–5)

### 影響度
| 入力 | 値 |
|---|---|
| `data_sensitivity` | none 0 / internal 1 / personal 3 / sensitive_personal 5（マイナンバー・健康情報等）/ credential 5 / payment 5 |
| `privilege` | none 0 / user 1 / elevated 3 / admin 5 |
| 基本値 | `max(data_sensitivity, privilege)` |
| `bulk: true` | +1（一覧取得・エクスポート・上限なしの `size`） |
| F7 (SQLi) | 最低4（エンドポイントのデータに関係なく DB 全体に届くため） |
| `business_criticality` | critical → 最低5 / high → 最低4（人による上書き） |

### 攻撃のしやすさ
| 入力 | 値 |
|---|---|
| Finding 種別ごとの基本値 | F1 5 / F2 3 / F3 3 / F4 4 / F5 4 / F6 3 / F7 5 / F8 2 |
| `auth_required: false`（F1 以外） | +1 |
| F4 で `id_type: sequential` | +1（列挙が容易。AI エージェントが得意） |
| F4 で `id_type: uuid` | −1（難しくなるが安全ではない） |
| `exposure: external` / `mobile` | +1（mobile はアプリ解析で露出） |
| `exposure: internal_only` | −1 |
| `gateway_enforced: true`（F1/F2/F3/F5） | −2 |
| 下限 | **1**（0にしない。内部 API も侵入後の横展開で攻撃されるため） |

### 段階
| 本来の危険度 | 段階 |
|---|---|
| 16 以上 | Critical |
| 9 以上 | High |
| 4 以上 | Medium |
| 4 未満 | Low |

## 2. 優先度（P0〜P4）

| 優先度 | 条件 |
|---|---|
| **P0** | `attack_signal: strong` かつ Medium 以上、または `weak` かつ High 以上 |
| P1 | Critical（**トラフィックは問わない**） |
| P2 | High |
| P3 | Medium |
| P4 | Low |

同じ優先度の中での並び順: 攻撃兆候 → 確度（confirmed > likely > needs_review）→ 本来の危険度 → トラフィック → ID。

## 3. フラグと最初の対応

| フラグ | 条件 | 最初の対応 |
|---|---|---|
| `dormant_critical` | Critical かつ `traffic_rpm == 0` | **無効化または削除**（修正より速く確実） |
| `not_observed` | `traffic_rpm == null` | 修正。あわせて計装漏れを Readiness 監査で確認 |
| `needs_review` | コードだけでは判定しきれない | 人が確認 |

## 4. 入力形式

```json
{
  "findings": [
    {
      "id": "F4-001",
      "endpoint": "GET /api/v1/orders/{id}",
      "finding_type": "F4",
      "confidence": "likely",
      "features": {
        "data_sensitivity": "personal",
        "privilege": "user",
        "bulk": false,
        "auth_required": true,
        "id_type": "sequential",
        "exposure": "mobile",
        "gateway_enforced": false
      },
      "runtime": { "traffic_rpm": 12.5, "attack_signal": "none" },
      "evidence": [{ "file": "src/main/java/.../OrderController.java", "line": 42 }]
    }
  ]
}
```

## 5. 人による上書き（`criticality.yaml` または `.json`）

```yaml
- path: /api/v1/payments/**
  business_criticality: critical
- path: /internal/batch/**
  exposure: internal_only
  gateway_enforced: true
```

`path` はエンドポイントのパス部分への glob。後に書いたものが優先される。
