#!/usr/bin/env python3
"""
可行性实验脚本：
1) 优先用真实 BGP 事件评估
2) 若真实事件覆盖不足（数量或类型），自动补充模拟事件
3) 输出统一 JSON 报告（准确率、耗时、分类型表现、数据覆盖度）
"""
import argparse
import asyncio
import json
import os
import shutil
import statistics
import subprocess
import sys
import time
from typing import Dict, List, Any

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bgp_agent import BGPAgent
from tools.project_paths import (
    BENCHMARK_REAL_FILE,
    BENCHMARK_SYNTHETIC_FILE,
    EXPERIMENT_REAL_EVENTS_DIR,
    FEASIBILITY_REPORT,
)


def normalize_asn(val) -> str:
    if val is None:
        return "None"
    s = str(val).strip().upper()
    if s in ("", "NONE", "UNKNOWN"):
        return "None"
    if s.startswith("AS"):
        s = s[2:]
    digits = "".join(ch for ch in s if ch.isdigit())
    return digits if digits else "None"


def run_step1_collect(input_path: str, output_dir: str, source: str) -> None:
    if os.path.isdir(output_dir):
        shutil.rmtree(output_dir)
    os.makedirs(output_dir, exist_ok=True)

    cmd = [
        sys.executable,
        "scripts/step1_collect_events.py",
        "--input",
        input_path,
        "--output",
        output_dir,
        "--source",
        source,
    ]
    subprocess.run(cmd, check=True)


def load_real_cases(events_dir: str) -> List[Dict[str, Any]]:
    cases = []
    if not os.path.isdir(events_dir):
        return cases

    for name in sorted(os.listdir(events_dir)):
        ev_dir = os.path.join(events_dir, name)
        if not os.path.isdir(ev_dir):
            continue
        meta_path = os.path.join(ev_dir, "meta.json")
        updates_path = os.path.join(ev_dir, "suspicious_updates.json")
        if not (os.path.exists(meta_path) and os.path.exists(updates_path)):
            continue

        try:
            with open(meta_path, "r", encoding="utf-8") as f:
                meta = json.load(f)
            with open(updates_path, "r", encoding="utf-8") as f:
                updates = json.load(f)
        except Exception:
            continue

        if not updates:
            continue

        model_updates = []
        for u in updates:
            model_updates.append(
                {
                    "prefix": u.get("prefix", meta.get("prefix")),
                    "as_path": u.get("as_path", ""),
                    "detected_origin": u.get("detected_origin", u.get("suspicious_as", "")),
                    "expected_origin": u.get("expected_origin", meta.get("victim", "")),
                }
            )

        attacker = meta.get("attacker", "None")
        event_type = str(meta.get("event_type", "")).upper().strip()
        if not event_type:
            event_type = "BENIGN" if normalize_asn(attacker) == "None" else "MALICIOUS"

        cases.append(
            {
                "case_name": meta.get("case_name") or f"{meta.get('prefix', 'unknown')}_{attacker}",
                "event_type": event_type,
                "expected_attacker": attacker,
                "accept_uncertain": False,
                "context": {
                    "time_window": {
                        "start": meta.get("start_time"),
                        "end": meta.get("end_time"),
                    },
                    "updates": model_updates,
                },
                "stage": "real",
                "data_source": meta.get("data_source", "unknown"),
                "is_fallback": str(meta.get("data_source", "")).lower() == "fallback",
                "meta": meta,
            }
        )

    return cases


def load_synthetic_cases(path: str) -> List[Dict[str, Any]]:
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    cases = []
    for item in data:
        cases.append(
            {
                "case_name": item.get("case_name", "synthetic_case"),
                "event_type": str(item.get("event_type", "UNKNOWN")).upper().strip(),
                "expected_attacker": item.get("expected_attacker", "None"),
                "accept_uncertain": bool(item.get("accept_uncertain", False)),
                "context": item.get("context", {}),
                "stage": "synthetic",
                "data_source": "synthetic",
                "is_fallback": False,
                "meta": item,
            }
        )
    return cases


async def evaluate_cases(cases: List[Dict[str, Any]], agent: BGPAgent) -> List[Dict[str, Any]]:
    results = []
    for idx, case in enumerate(cases, 1):
        start = time.time()
        status = "ERROR"
        pred = "None"
        rag_diag = None
        err = None

        try:
            trace = await agent.diagnose_batch(case["context"], verbose=False)
            final = trace.get("final_result") or {}
            status = str(final.get("status", "UNKNOWN")).upper()
            pred = normalize_asn(final.get("most_likely_attacker", final.get("attacker_as", "None")))
            rag_diag = trace.get("rag_diagnostics")
        except Exception as e:
            err = str(e)

        duration = time.time() - start
        expected = normalize_asn(case.get("expected_attacker"))
        accept_uncertain = bool(case.get("accept_uncertain", False))

        if expected == "None":
            if accept_uncertain:
                is_correct = (pred == "None") or (status in ("BENIGN", "UNCERTAIN"))
            else:
                is_correct = (pred == "None") or (status == "BENIGN")
        else:
            is_correct = pred == expected

        results.append(
            {
                "index": idx,
                "case_name": case.get("case_name"),
                "stage": case.get("stage"),
                "event_type": case.get("event_type"),
                "data_source": case.get("data_source"),
                "is_fallback": case.get("is_fallback", False),
                "expected_attacker": expected,
                "predicted_attacker": pred,
                "status": status,
                "is_correct": is_correct,
                "uncertain": status == "UNCERTAIN",
                "duration_sec": round(duration, 3),
                "rag_diagnostics": rag_diag,
                "error": err,
            }
        )

    return results


def summarize(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    if not results:
        return {
            "count": 0,
            "accuracy": 0.0,
            "uncertain_rate": 0.0,
            "mean_latency_sec": 0.0,
            "median_latency_sec": 0.0,
            "p90_latency_sec": 0.0,
        }

    total = len(results)
    hit = sum(1 for r in results if r.get("is_correct"))
    uncertain = sum(1 for r in results if r.get("uncertain"))
    durs = [float(r.get("duration_sec", 0.0)) for r in results]
    durs_sorted = sorted(durs)
    p90_idx = max(0, min(len(durs_sorted) - 1, int(0.9 * len(durs_sorted)) - 1))

    return {
        "count": total,
        "accuracy": round(hit / total, 4),
        "uncertain_rate": round(uncertain / total, 4),
        "mean_latency_sec": round(sum(durs) / total, 4),
        "median_latency_sec": round(statistics.median(durs), 4),
        "p90_latency_sec": round(durs_sorted[p90_idx], 4),
    }


def summarize_by_type(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    bucket: Dict[str, List[Dict[str, Any]]] = {}
    for r in results:
        et = r.get("event_type", "UNKNOWN")
        bucket.setdefault(et, []).append(r)
    return {k: summarize(v) for k, v in sorted(bucket.items())}


def print_summary(title: str, summary: Dict[str, Any], by_type: Dict[str, Any]) -> None:
    print("\n" + "=" * 88)
    print(title)
    print("=" * 88)
    print(
        f"count={summary.get('count', 0)} | "
        f"accuracy={summary.get('accuracy', 0):.2%} | "
        f"uncertain={summary.get('uncertain_rate', 0):.2%} | "
        f"latency(mean/median/p90)="
        f"{summary.get('mean_latency_sec', 0):.2f}/"
        f"{summary.get('median_latency_sec', 0):.2f}/"
        f"{summary.get('p90_latency_sec', 0):.2f}s"
    )
    if by_type:
        print("-- By Event Type --")
        for et, s in by_type.items():
            print(
                f"{et:8s} count={s['count']:3d} "
                f"acc={s['accuracy']:.2%} "
                f"uncertain={s['uncertain_rate']:.2%} "
                f"lat={s['mean_latency_sec']:.2f}s"
            )


async def main():
    parser = argparse.ArgumentParser(description="BGP 溯源可行性实验（真实事件优先）")
    parser.add_argument("--real-input", default=str(BENCHMARK_REAL_FILE), help="真实事件配置文件")
    parser.add_argument("--real-events-dir", default=str(EXPERIMENT_REAL_EVENTS_DIR), help="真实事件抓取输出目录")
    parser.add_argument("--source", choices=["ris_mrt", "ripestat", "auto"], default="auto", help="真实事件抓取数据源")
    parser.add_argument("--synthetic-input", default=str(BENCHMARK_SYNTHETIC_FILE), help="模拟事件配置文件")
    parser.add_argument("--min-real-cases", type=int, default=6, help="真实非 fallback 事件最小数量")
    parser.add_argument(
        "--required-types",
        default="HIJACK,LEAK,BENIGN",
        help="真实非 fallback 必须覆盖的事件类型，逗号分隔",
    )
    parser.add_argument("--report-out", default=str(FEASIBILITY_REPORT), help="实验报告输出路径")
    parser.add_argument("--disable-synthetic", action="store_true", help="禁用模拟事件补充")
    args = parser.parse_args()

    required_types = {x.strip().upper() for x in args.required_types.split(",") if x.strip()}

    print("[Stage-1] 收集并评估真实事件...")
    run_step1_collect(args.real_input, args.real_events_dir, args.source)
    real_cases = load_real_cases(args.real_events_dir)
    if not real_cases:
        print("❌ 未加载到真实事件，请检查输入与抓取配置。")
        return

    agent = BGPAgent()
    real_results = await evaluate_cases(real_cases, agent)

    real_all_summary = summarize(real_results)
    real_by_type = summarize_by_type(real_results)

    real_non_fallback = [r for r in real_results if not r.get("is_fallback")]
    real_non_fb_summary = summarize(real_non_fallback)
    real_non_fb_by_type = summarize_by_type(real_non_fallback)
    covered_types = {r.get("event_type") for r in real_non_fallback}
    missing_types = sorted(t for t in required_types if t not in covered_types)

    need_synthetic = (
        (not args.disable_synthetic)
        and (
            len(real_non_fallback) < args.min_real_cases
            or bool(missing_types)
        )
    )

    synthetic_results: List[Dict[str, Any]] = []
    if need_synthetic:
        print("[Stage-2] 真实事件覆盖不足，补充模拟事件...")
        synthetic_cases = load_synthetic_cases(args.synthetic_input)
        if missing_types:
            picked = [c for c in synthetic_cases if c.get("event_type") in set(missing_types)]
            synthetic_cases = picked if picked else synthetic_cases
        synthetic_results = await evaluate_cases(synthetic_cases, agent)

    synthetic_summary = summarize(synthetic_results)
    synthetic_by_type = summarize_by_type(synthetic_results)

    merged_results = real_non_fallback + synthetic_results
    merged_summary = summarize(merged_results)
    merged_by_type = summarize_by_type(merged_results)

    report = {
        "config": {
            "real_input": args.real_input,
            "real_events_dir": args.real_events_dir,
            "source": args.source,
            "synthetic_input": args.synthetic_input,
            "min_real_cases": args.min_real_cases,
            "required_types": sorted(list(required_types)),
            "synthetic_enabled": not args.disable_synthetic,
        },
        "real_stage": {
            "summary_all": real_all_summary,
            "summary_non_fallback": real_non_fb_summary,
            "by_type_all": real_by_type,
            "by_type_non_fallback": real_non_fb_by_type,
            "non_fallback_coverage": round(len(real_non_fallback) / len(real_results), 4) if real_results else 0.0,
            "covered_types_non_fallback": sorted(list(covered_types)),
            "missing_types_non_fallback": missing_types,
        },
        "synthetic_stage": {
            "enabled": need_synthetic,
            "summary": synthetic_summary,
            "by_type": synthetic_by_type,
        },
        "final_evaluation": {
            "summary": merged_summary,
            "by_type": merged_by_type,
            "used_real_non_fallback": len(real_non_fallback),
            "used_synthetic": len(synthetic_results),
        },
        "cases": {
            "real": real_results,
            "synthetic": synthetic_results,
        },
    }

    os.makedirs(os.path.dirname(args.report_out) or ".", exist_ok=True)
    with open(args.report_out, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    print_summary("真实事件（全部）", real_all_summary, real_by_type)
    print_summary("真实事件（仅非 fallback）", real_non_fb_summary, real_non_fb_by_type)
    if need_synthetic:
        print_summary("模拟事件补充", synthetic_summary, synthetic_by_type)
    print_summary("最终评估（真实非 fallback + 模拟补充）", merged_summary, merged_by_type)

    print("\n✅ 报告已输出:", args.report_out)


if __name__ == "__main__":
    asyncio.run(main())
