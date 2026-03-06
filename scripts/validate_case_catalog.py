#!/usr/bin/env python3
"""
校验分类案例库：
1) 每类 cases_10.json 必须包含 10 条
2) synthetic 样本必须包含 simulation_reason
3) real/synthetic 数量与 index.json 一致
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tools.project_paths import CASE_CATALOG_DIR

ROOT = Path(__file__).resolve().parents[1]
CATALOG = CASE_CATALOG_DIR


def load_json(path: Path):
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def load_json_or_empty(path: Path, errors: list[str], label: str):
    if not path.exists():
        errors.append(f"[{label}] 文件不存在: {path}")
        return []
    try:
        return load_json(path)
    except Exception as e:
        errors.append(f"[{label}] 文件读取失败: {path} ({e})")
        return []


def main() -> int:
    errors = []
    index = load_json(CATALOG / "index.json")

    for entry in index.get("types", []):
        event_type = entry.get("event_type")
        paths = entry.get("paths", {})

        real_path = ROOT / paths.get("real", "")
        synthetic_path = ROOT / paths.get("synthetic", "")
        cases_path = ROOT / paths.get("cases_10", "")

        real_cases = load_json_or_empty(real_path, errors, event_type or "UNKNOWN")
        synthetic_cases = load_json_or_empty(synthetic_path, errors, event_type or "UNKNOWN")
        merged_cases = load_json_or_empty(cases_path, errors, event_type or "UNKNOWN")

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
