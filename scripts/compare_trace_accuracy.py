#!/usr/bin/env python3
"""
Compare trace-back accuracy between:
- Ground truth attacker AS in data/
- Predicted attacker AS in report/forensics/

Matching key:
    (prefix, start_time, end_time)

Default output:
    report/evaluation/trace_accuracy_eval.json
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tools.project_paths import DATA_DIR, REPORT_FORENSICS_DIR, TRACE_ACCURACY_REPORT


Key = Tuple[str, str, str]


@dataclass
class TruthRecord:
    key: Key
    attacker: str
    priority: int
    source_files: List[str] = field(default_factory=list)
    case_ids: List[str] = field(default_factory=list)


@dataclass
class ReportRecord:
    key: Key
    attacker: str
    status: str
    file: str
    started_at: str = ""


def normalize_asn(value: Any) -> str:
    if value is None:
        return "None"
    s = str(value).strip()
    if not s or s.lower() in {"none", "unknown", "null", "n/a"}:
        return "None"
    if s.upper().startswith("AS"):
        s = s[2:]
    digits = "".join(ch for ch in s if ch.isdigit())
    return digits if digits else "None"


def parse_iso_time(value: str) -> Optional[datetime]:
    s = (value or "").strip()
    if not s:
        return None
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(s)
    except ValueError:
        return None


def canonical_key(prefix: Any, start_time: Any, end_time: Any) -> Optional[Key]:
    p = str(prefix or "").strip()
    s = str(start_time or "").strip()
    e = str(end_time or "").strip()
    if not p or not s or not e:
        return None
    return (p, s, e)


def source_priority(path: Path) -> int:
    p = str(path).replace("\\", "/")
    if "/events/" in p and p.endswith("/meta.json"):
        return 0
    if "/experiments/" in p and p.endswith("/meta.json"):
        return 1
    if "/case_catalog/" in p and p.endswith("/cases_10.json"):
        return 2
    if "/case_catalog/" in p:
        return 3
    if p.endswith("test_events.json"):
        return 4
    if "benchmark" in p:
        return 5
    return 6


def build_truth_candidate(
    prefix: Any,
    start_time: Any,
    end_time: Any,
    attacker: Any,
    source_path: Path,
    case_id: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    key = canonical_key(prefix, start_time, end_time)
    if key is None:
        return None
    return {
        "key": key,
        "attacker": normalize_asn(attacker),
        "source": str(source_path),
        "priority": source_priority(source_path),
        "case_id": case_id or "",
    }


def extract_truth_from_item(item: Dict[str, Any], source_path: Path) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    case_id = str(item.get("case_id", "")).strip() or None

    direct_attacker = item.get("attacker", item.get("expected_attacker"))
    if {"prefix", "start_time", "end_time"}.issubset(item.keys()) and direct_attacker is not None:
        c = build_truth_candidate(
            item.get("prefix"),
            item.get("start_time"),
            item.get("end_time"),
            direct_attacker,
            source_path,
            case_id=case_id,
        )
        if c:
            out.append(c)

    event = item.get("event")
    if isinstance(event, dict):
        c = build_truth_candidate(
            event.get("prefix"),
            event.get("start_time"),
            event.get("end_time"),
            event.get("attacker", event.get("expected_attacker")),
            source_path,
            case_id=case_id,
        )
        if c:
            out.append(c)

    context = item.get("context")
    if isinstance(context, dict):
        tw = context.get("time_window", {})
        updates = context.get("updates", [])
        prefix = item.get("prefix") or context.get("prefix")
        if not prefix and isinstance(updates, list) and updates and isinstance(updates[0], dict):
            prefix = updates[0].get("prefix")
        c = build_truth_candidate(
            prefix,
            item.get("start_time") or (tw.get("start") if isinstance(tw, dict) else None),
            item.get("end_time") or (tw.get("end") if isinstance(tw, dict) else None),
            item.get("expected_attacker", item.get("attacker")),
            source_path,
            case_id=case_id,
        )
        if c:
            out.append(c)

    return out


def collect_truth(data_dir: Path) -> Tuple[Dict[Key, TruthRecord], List[Dict[str, Any]]]:
    truth_map: Dict[Key, TruthRecord] = {}
    conflicts: List[Dict[str, Any]] = []

    for path in sorted(data_dir.rglob("*.json")):
        if path.name in {"suspicious_updates.json", "raw_bgplay.json"}:
            continue

        try:
            with path.open("r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            continue

        candidates: List[Dict[str, Any]] = []
        if isinstance(data, dict):
            candidates.extend(extract_truth_from_item(data, path))
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    candidates.extend(extract_truth_from_item(item, path))

        for c in candidates:
            key: Key = c["key"]
            attacker = c["attacker"]
            src = c["source"]
            priority = c["priority"]
            case_id = c["case_id"]

            existing = truth_map.get(key)
            if existing is None:
                truth_map[key] = TruthRecord(
                    key=key,
                    attacker=attacker,
                    priority=priority,
                    source_files=[src],
                    case_ids=[case_id] if case_id else [],
                )
                continue

            if existing.attacker == attacker:
                if src not in existing.source_files:
                    existing.source_files.append(src)
                if case_id and case_id not in existing.case_ids:
                    existing.case_ids.append(case_id)
                if priority < existing.priority:
                    existing.priority = priority
                continue

            if priority < existing.priority:
                conflicts.append(
                    {
                        "key": key,
                        "old_attacker": existing.attacker,
                        "new_attacker": attacker,
                        "resolution": "replaced_by_higher_priority_source",
                        "old_sources": existing.source_files,
                        "new_source": src,
                    }
                )
                truth_map[key] = TruthRecord(
                    key=key,
                    attacker=attacker,
                    priority=priority,
                    source_files=[src],
                    case_ids=[case_id] if case_id else [],
                )
            else:
                conflicts.append(
                    {
                        "key": key,
                        "old_attacker": existing.attacker,
                        "new_attacker": attacker,
                        "resolution": "kept_existing_source",
                        "old_sources": existing.source_files,
                        "new_source": src,
                    }
                )

    return truth_map, conflicts


def parse_report(path: Path) -> Optional[ReportRecord]:
    try:
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return None

    target = data.get("target", {})
    if not isinstance(target, dict):
        return None

    tw = target.get("time_window", {})
    updates = target.get("updates", [])

    prefix = target.get("prefix")
    if not prefix and isinstance(updates, list) and updates and isinstance(updates[0], dict):
        prefix = updates[0].get("prefix")

    start_time = tw.get("start") if isinstance(tw, dict) else None
    end_time = tw.get("end") if isinstance(tw, dict) else None
    key = canonical_key(prefix, start_time, end_time)
    if key is None:
        return None

    final = data.get("final_result", {})
    if not isinstance(final, dict):
        final = {}

    raw_attacker = final.get("most_likely_attacker", final.get("attacker_as", final.get("attacker")))
    predicted = normalize_asn(raw_attacker)
    status = str(final.get("status", "UNKNOWN"))

    return ReportRecord(
        key=key,
        attacker=predicted,
        status=status,
        file=str(path),
        started_at=str(data.get("start_time", "")),
    )


def report_sort_time(record: ReportRecord, file_path: Path) -> datetime:
    t = parse_iso_time(record.started_at)
    if t is not None:
        return t
    return datetime.fromtimestamp(file_path.stat().st_mtime)


def collect_reports(report_dir: Path) -> Tuple[Dict[Key, ReportRecord], List[Dict[str, Any]], List[str]]:
    report_map: Dict[Key, ReportRecord] = {}
    duplicates: List[Dict[str, Any]] = []
    invalid_files: List[str] = []

    for path in sorted(report_dir.rglob("forensics*.json")):
        rec = parse_report(path)
        if rec is None:
            invalid_files.append(str(path))
            continue

        existing = report_map.get(rec.key)
        if existing is None:
            report_map[rec.key] = rec
            continue

        existing_path = Path(existing.file)
        old_time = report_sort_time(existing, existing_path)
        new_time = report_sort_time(rec, path)

        if new_time >= old_time:
            kept = "newer_report_replaced_old"
            report_map[rec.key] = rec
        else:
            kept = "kept_existing_newer_report"

        duplicates.append(
            {
                "key": rec.key,
                "existing_file": str(existing_path),
                "new_file": str(path),
                "resolution": kept,
            }
        )

    return report_map, duplicates, invalid_files


def evaluate(
    truth_map: Dict[Key, TruthRecord], report_map: Dict[Key, ReportRecord]
) -> Tuple[List[Dict[str, Any]], Dict[str, Any], List[Dict[str, Any]], List[Dict[str, Any]]]:
    rows: List[Dict[str, Any]] = []
    matched_truth_keys = set()

    for key in sorted(report_map.keys()):
        report = report_map[key]
        truth_key = key
        truth = truth_map.get(key)
        match_strategy = "exact"
        if truth is None:
            truth_key, truth = find_truth_by_prefix_fallback(key, truth_map)
            if truth is not None:
                match_strategy = "prefix_fallback"
            else:
                match_strategy = "none"
        has_truth = truth is not None
        expected = truth.attacker if truth else ""
        is_match = bool(has_truth and expected == report.attacker)

        if has_truth:
            matched_truth_keys.add(truth_key)

        rows.append(
            {
                "prefix": key[0],
                "start_time": key[1],
                "end_time": key[2],
                "matched_truth_prefix": truth_key[0] if truth else "",
                "expected_attacker": expected,
                "predicted_attacker": report.attacker,
                "status": report.status,
                "is_match": is_match,
                "has_truth": has_truth,
                "match_strategy": match_strategy,
                "report_file": report.file,
                "truth_sources": truth.source_files if truth else [],
                "case_ids": truth.case_ids if truth else [],
            }
        )

    matched_count = sum(1 for r in rows if r["has_truth"])
    correct_count = sum(1 for r in rows if r["is_match"])
    total_truth = len(truth_map)
    total_reports = len(report_map)

    accuracy = (correct_count / matched_count) if matched_count else 0.0
    coverage = (matched_count / total_truth) if total_truth else 0.0

    unmatched_reports = [r for r in rows if not r["has_truth"]]
    unmatched_truth = []
    for key in sorted(set(truth_map.keys()) - matched_truth_keys):
        t = truth_map[key]
        unmatched_truth.append(
            {
                "prefix": key[0],
                "start_time": key[1],
                "end_time": key[2],
                "expected_attacker": t.attacker,
                "truth_sources": t.source_files,
                "case_ids": t.case_ids,
            }
        )

    summary = {
        "total_truth_events": total_truth,
        "total_report_events": total_reports,
        "matched_events": matched_count,
        "correct_predictions": correct_count,
        "accuracy_on_matched_events": round(accuracy, 6),
        "coverage_vs_truth_events": round(coverage, 6),
        "prefix_fallback_matches": sum(1 for r in rows if r["match_strategy"] == "prefix_fallback"),
        "unmatched_report_events": len(unmatched_reports),
        "unmatched_truth_events": len(unmatched_truth),
    }
    return rows, summary, unmatched_reports, unmatched_truth


def parse_network(prefix: str) -> Optional[ipaddress._BaseNetwork]:
    try:
        return ipaddress.ip_network(prefix, strict=False)
    except ValueError:
        return None


def find_truth_by_prefix_fallback(
    report_key: Key, truth_map: Dict[Key, TruthRecord]
) -> Tuple[Key, Optional[TruthRecord]]:
    report_prefix, report_start, report_end = report_key
    report_net = parse_network(report_prefix)
    if report_net is None:
        return report_key, None

    candidates: List[Tuple[int, int, Key, TruthRecord]] = []
    for truth_key, truth in truth_map.items():
        truth_prefix, truth_start, truth_end = truth_key
        if truth_start != report_start or truth_end != report_end:
            continue
        truth_net = parse_network(truth_prefix)
        if truth_net is None:
            continue
        if report_net.subnet_of(truth_net) or truth_net.subnet_of(report_net):
            # Prefer the closest prefix length, then prefer more specific truth prefix.
            diff = abs(report_net.prefixlen - truth_net.prefixlen)
            candidates.append((diff, -truth_net.prefixlen, truth_key, truth))

    if not candidates:
        return report_key, None
    candidates.sort(key=lambda x: (x[0], x[1]))
    _, _, truth_key, truth = candidates[0]
    return truth_key, truth


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Compare ground-truth attacker AS in data/ with predictions in report/forensics/"
    )
    parser.add_argument("--data-dir", default=str(DATA_DIR), help="Data directory containing input truth files.")
    parser.add_argument("--report-dir", default=str(REPORT_FORENSICS_DIR), help="Report directory containing forensics*.json files.")
    parser.add_argument(
        "--output",
        default=str(TRACE_ACCURACY_REPORT),
        help="Output JSON file path.",
    )
    parser.add_argument(
        "--show-mismatches",
        type=int,
        default=20,
        help="Max mismatch rows to print in terminal.",
    )
    args = parser.parse_args()

    data_dir = Path(args.data_dir)
    report_dir = Path(args.report_dir)
    output_path = Path(args.output)

    if not data_dir.exists():
        raise SystemExit(f"data directory not found: {data_dir}")
    if not report_dir.exists():
        raise SystemExit(f"report directory not found: {report_dir}")

    truth_map, truth_conflicts = collect_truth(data_dir)
    report_map, report_duplicates, invalid_reports = collect_reports(report_dir)
    rows, summary, unmatched_reports, unmatched_truth = evaluate(truth_map, report_map)

    payload = {
        "generated_at": datetime.now().isoformat(),
        "data_dir": str(data_dir),
        "report_dir": str(report_dir),
        "summary": summary,
        "truth_conflicts": truth_conflicts,
        "report_duplicates": report_duplicates,
        "invalid_report_files": invalid_reports,
        "details": rows,
        "unmatched_report_events": unmatched_reports,
        "unmatched_truth_events": unmatched_truth,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)

    print("=" * 88)
    print("Trace-back Accuracy Comparison")
    print("=" * 88)
    print(f"Truth events loaded:   {summary['total_truth_events']}")
    print(f"Report events loaded:  {summary['total_report_events']}")
    print(f"Matched events:        {summary['matched_events']}")
    print(f"Correct predictions:   {summary['correct_predictions']}")
    print(
        f"Accuracy (matched):    {summary['correct_predictions']}/{summary['matched_events']} "
        f"({summary['accuracy_on_matched_events'] * 100:.2f}%)"
    )
    print(
        f"Coverage (vs truth):   {summary['matched_events']}/{summary['total_truth_events']} "
        f"({summary['coverage_vs_truth_events'] * 100:.2f}%)"
    )
    print(f"Unmatched reports:     {summary['unmatched_report_events']}")
    print(f"Unmatched truth:       {summary['unmatched_truth_events']}")
    print(f"Truth conflicts:       {len(truth_conflicts)}")
    print(f"Report duplicates:     {len(report_duplicates)}")
    print(f"Invalid report files:  {len(invalid_reports)}")

    mismatches = [r for r in rows if r["has_truth"] and not r["is_match"]]
    print(f"Mismatches (matched):  {len(mismatches)}")
    if mismatches and args.show_mismatches > 0:
        print("-" * 88)
        print("Sample mismatches:")
        for r in mismatches[: args.show_mismatches]:
            print(
                f"{r['prefix']} | {r['start_time']} -> {r['end_time']} | "
                f"expected AS{r['expected_attacker']} | predicted AS{r['predicted_attacker']} | "
                f"status={r['status']} | report={Path(r['report_file']).name}"
            )

    print("-" * 88)
    print(f"Saved: {output_path}")


if __name__ == "__main__":
    main()
