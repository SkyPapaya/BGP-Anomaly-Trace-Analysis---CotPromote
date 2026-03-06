#!/usr/bin/env python3
"""
校验分类案例库：
1) 每类 cases_10.json 必须包含 10 条
2) synthetic 样本必须包含 simulation_reason
3) real/synthetic 数量与 index.json 一致
"""
from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "data" / "case_catalog"


def load_json(path: Path):
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def main() -> int:
    errors = []
    index = load_json(CATALOG / "index.json")

    for entry in index.get("types", []):
        event_type = entry.get("event_type")
        paths = entry.get("paths", {})

        real_path = ROOT / paths.get("real", "")
        synthetic_path = ROOT / paths.get("synthetic", "")
        cases_path = ROOT / paths.get("cases_10", "")

        real_cases = load_json(real_path)
        synthetic_cases = load_json(synthetic_path)
        merged_cases = load_json(cases_path)

        if len(merged_cases) != 10:
            errors.append(f"[{event_type}] cases_10 数量不是 10，而是 {len(merged_cases)}")

        if len(real_cases) != int(entry.get("real", -1)):
            errors.append(
                f"[{event_type}] real 数量不一致: index={entry.get('real')} file={len(real_cases)}"
            )
        if len(synthetic_cases) != int(entry.get("synthetic", -1)):
            errors.append(
                f"[{event_type}] synthetic 数量不一致: index={entry.get('synthetic')} file={len(synthetic_cases)}"
            )
        if len(merged_cases) != int(entry.get("total", -1)):
            errors.append(
                f"[{event_type}] total 数量不一致: index={entry.get('total')} file={len(merged_cases)}"
            )

        for c in synthetic_cases:
            if not str(c.get("simulation_reason", "")).strip():
                cid = c.get("case_id", "unknown")
                errors.append(f"[{event_type}] synthetic 案例缺少 simulation_reason: {cid}")

    if errors:
        print("校验失败：")
        for e in errors:
            print(f"- {e}")
        return 1

    print("校验通过：case_catalog 结构与数量一致。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
