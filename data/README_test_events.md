# 待测案例配置说明

在 **`data/test_events.json`** 中手动输入待测事件，供 Step1 下载 RIPEstat 真实 BGP updates 并过滤。

## 格式样例

```json
[
  {
    "prefix": "8.8.8.0/24",
    "victim": "15169",
    "attacker": "174",
    "start_time": "2024-06-15T00:00:00",
    "end_time": "2024-06-15T12:00:00",
    "source": "anomaly"
  }
]
```

## 字段说明

| 字段 | 必填 | 说明 |
|------|------|------|
| prefix | ✓ | 目标前缀，如 8.8.8.0/24 |
| victim | ✓ | 合法持有者 AS 号（Expected Owner） |
| attacker | ✓ | 可疑/攻击者 AS 号（真值，用于 Step2 比对） |
| start_time | ✓ | 时间窗口开始，ISO8601，如 2024-06-15T00:00:00 |
| end_time | ✓ | 时间窗口结束，ISO8601 |
| source |   | 来源标签，如 anomaly / ares / ares-leak |

## 注意事项

- RIPEstat BGPlay 仅支持 **2024-01 之后** 的数据
- 时间窗口不宜过大，建议 12 小时以内
