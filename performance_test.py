"""
BGP 溯源系统准确性评估
支持三种数据源：
1. 本地 test_cases.json
2. Step2 本地事件：data/events/（由 Step1 抓取并过滤的原始 updates）
3. BGP Watch 在线：直接拉取（无原始 updates，不推荐）
通过对比 BGP Watch 给出的可疑 AS 与系统判定结果，验证系统可行性。
"""
import asyncio
import time
import json
import os
import sys
from bgp_agent import BGPAgent
from tabulate import tabulate
from tools.project_paths import EVENTS_DIR, TEST_CASES_FILE

try:
    from tqdm import tqdm
except ImportError:
    tqdm = None

def load_test_cases():
    """从本地 JSON 加载测试案例"""
    if not os.path.exists(TEST_CASES_FILE):
        print(f"⚠️ 本地测试文件不存在: {TEST_CASES_FILE}")
        return []

    try:
        with open(TEST_CASES_FILE, "r", encoding="utf-8") as f:
            cases = json.load(f)
        print(f"📂 从本地加载 {len(cases)} 个测试案例。")
        return cases
    except Exception as e:
        print(f"❌ 读取本地测试文件失败: {e}")
        return []


def load_local_events(events_dir=EVENTS_DIR):
    """
    从 Step1 输出的 data/events/ 加载本地事件（含真实过滤的 suspicious updates）
    :return: list of {name, type, context, expected_attacker, source}
    """
    if not os.path.isdir(events_dir):
        print(f"⚠️ 事件目录不存在: {events_dir}")
        print("   请先运行: python scripts/step1_collect_events.py")
        return []

    cases = []
    for name in sorted(os.listdir(events_dir)):
        ev_dir = os.path.join(events_dir, name)
        if not os.path.isdir(ev_dir):
            continue
        meta_path = os.path.join(ev_dir, "meta.json")
        updates_path = os.path.join(ev_dir, "suspicious_updates.json")
        if not os.path.exists(meta_path) or not os.path.exists(updates_path):
            continue

        try:
            with open(meta_path, "r", encoding="utf-8") as f:
                meta = json.load(f)
            with open(updates_path, "r", encoding="utf-8") as f:
                updates = json.load(f)
        except Exception as e:
            print(f"   ⚠️ 读取 {name} 失败: {e}")
            continue

        if not updates:
            continue

        # 转为我们系统的 updates 格式
        our_updates = []
        for u in updates:
            our_updates.append({
                "prefix": u.get("prefix", meta["prefix"]),
                "as_path": u.get("as_path", ""),
                "detected_origin": u.get("detected_origin", u.get("suspicious_as", "")),
                "expected_origin": u.get("expected_origin", meta["victim"]),
            })

        context = {
            "time_window": {"start": meta.get("start_time"), "end": meta.get("end_time")},
            "updates": our_updates,
        }

        exp = meta.get("attacker", "")
        is_benign = not exp or str(exp).lower() == "none"
        cases.append({
            "name": f"{meta['prefix']}_{meta['attacker']}"[:40],
            "type": "BENIGN" if is_benign else "MALICIOUS",
            "context": context,
            "expected_attacker": None if is_benign else meta["attacker"],
            "source": meta.get("source", "local"),
        })

    if cases:
        print(f"📂 从 {events_dir} 加载 {len(cases)} 个事件（含真实过滤的 updates）")
    return cases


def load_bgpwatch_cases(days_back=7, max_per_source=15):
    """从 BGP Watch 获取异常事件"""
    try:
        from tools.bgpwatch_fetcher import fetch_all_sources
    except ImportError:
        print("❌ 无法导入 tools.bgpwatch_fetcher，请确保 tools 在 Python 路径下")
        return []

    print(f"🌐 正在从 BGP Watch 获取异常事件 (过去 {days_back} 天)...")
    cases = fetch_all_sources(days_back=days_back, max_per_source=max_per_source)
    if not cases:
        print("⚠️ BGP Watch 未返回数据，可能是网络问题或该时段无异常事件。")
        return []
    print(f"📂 从 BGP Watch 获取 {len(cases)} 条异常事件。")
    return cases


def _normalize_asn(val):
    """清洗 AS 号，只保留数字"""
    if val is None:
        return "None"
    s = str(val).strip()
    if s.lower() in ("none", "unknown", ""):
        return "None"
    digits = "".join(filter(str.isdigit, s))
    return digits if digits else "None"


def _extract_ai_attacker(final, is_batch=False):
    """从 Agent 结果中提取判定的攻击者 AS"""
    raw = final.get("most_likely_attacker" if is_batch else "attacker_as", "None")
    return _normalize_asn(raw)


async def run_benchmark(cases, agent, results_table, correct_count_ref):
    """执行单轮基准测试"""
    correct_count = correct_count_ref[0]
    iterator = tqdm(enumerate(cases), total=len(cases), desc="性能测试", unit="案例") if tqdm else enumerate(cases)
    for i, case in iterator:
        expected = case.get("expected_attacker")
        case_type = case.get("type", "MALICIOUS")
        name = case.get("name", f"Case_{i+1}")[:35]
        source_tag = f" [{case.get('source', '')}]" if case.get("source") else ""

        if tqdm and hasattr(iterator, "set_postfix_str"):
            iterator.set_postfix_str(f"{name}{source_tag}")
        print(f"[{i+1}/{len(cases)}] {name}{source_tag} ... ", end="", flush=True)

        start_time = time.time()
        ai_attacker = "N/A"
        status = "UNKNOWN"
        verdict_icon = "❓"

        try:
            context = case.get("context", case)
            if isinstance(context, list) or "updates" in context:
                trace = await agent.diagnose_batch(context, verbose=False)
                is_batch = True
            else:
                trace = await agent.diagnose(context, verbose=False)
                is_batch = False

            final = trace.get("final_result") or {}
            status = final.get("status", "UNKNOWN")
            ai_attacker = _extract_ai_attacker(final, is_batch=is_batch)

            expected_norm = _normalize_asn(expected) if expected else "None"
            if case_type == "BENIGN":
                is_correct = ai_attacker == "None" or status == "BENIGN"
            else:
                is_correct = ai_attacker == expected_norm

            if is_correct:
                correct_count += 1
                verdict_icon = "✅ HIT"
            else:
                verdict_icon = "❌ MISS"

        except Exception as e:
            print(f"\n❌ [CRASH] {e}")
            status = "ERROR"
            verdict_icon = "⚠️ CRASH"

        correct_count_ref[0] = correct_count
        duration = time.time() - start_time
        print(f"完成 ({duration:.2f}s)")

        results_table.append([
            name,
            case_type,
            f"AS{expected}" if expected else "None",
            f"AS{ai_attacker}",
            status,
            verdict_icon,
            f"{duration:.1f}s",
        ])


async def main():
    parser_argv = sys.argv[1:]
    use_events = "--events" in parser_argv or "-e" in parser_argv
    use_bgpwatch = "--bgpwatch" in parser_argv or "-b" in parser_argv
    days = 7
    events_dir = EVENTS_DIR
    for i, arg in enumerate(parser_argv):
        if arg in ("--days", "-d") and i + 1 < len(parser_argv):
            try:
                days = int(parser_argv[i + 1])
            except ValueError:
                pass
        if arg == "--events-dir" and i + 1 < len(parser_argv):
            events_dir = parser_argv[i + 1]

    # 1. 加载案例（优先 Step2 本地事件）
    if use_events:
        cases = load_local_events(events_dir=events_dir)
    elif use_bgpwatch:
        cases = load_bgpwatch_cases(days_back=days, max_per_source=20)
    else:
        cases = load_test_cases()

    if not cases:
        print("\n💡 使用方式:")
        print("  Step2 本地事件: python performance_test.py --events  [--events-dir data/events]")
        print("  本地 test_cases: python performance_test.py")
        print("  BGP Watch 在线: python performance_test.py --bgpwatch [--days 7]")
        return

    # 2. 初始化 Agent
    print("\n🚀 正在初始化 BGP 溯源 Agent...")
    try:
        agent = BGPAgent()
    except Exception as e:
        print(f"❌ Agent 初始化失败: {e}")
        return

    results_table = []
    correct_count_ref = [0]
    mode = "Step2 本地事件" if use_events else ("BGP Watch 在线" if use_bgpwatch else "本地 test_cases")
    print(f"\n⚡ 开始 {len(cases)} 轮测试 [{mode}] (真值 vs 系统判定)...\n")

    await run_benchmark(cases, agent, results_table, correct_count_ref)

    # 4. 输出报告
    print("\n" + "=" * 110)
    title = "Step2 验证报告" if use_events else ("BGP Watch 验证报告" if use_bgpwatch else "BGP Agent 综合实战评估报告")
    print(f"📢 {title}")
    print("=" * 110)
    headers = ["Case Name", "Type", "BGP Watch 可疑AS", "系统判定", "Status", "Result", "Time"]
    print(tabulate(results_table, headers=headers, tablefmt="grid"))

    correct_count = correct_count_ref[0]
    accuracy = (correct_count / len(cases)) * 100 if cases else 0
    print(f"\n🎯 准确性: {correct_count}/{len(cases)} ({accuracy:.1f}%)")
    print("   (系统判定的攻击者 AS 与 BGP Watch 给出的可疑 AS 一致则计为正确)")

    if accuracy >= 80:
        print("🏆 评级: 优秀 (Expert)")
    elif accuracy >= 60:
        print("🥈 评级: 合格 (Junior)")
    else:
        print("🔧 评级: 需要优化 (Needs Improvement)")

    if use_events:
        print("\n📎 数据来源: data/events/ (Step1 从 BGP Watch + RIPEstat 抓取并过滤)")
    elif use_bgpwatch:
        print("\n📎 数据来源: https://bgpwatch.cgtf.net/#/anomaly | #/ares | #/ares-leak")


if __name__ == "__main__":
    asyncio.run(main())
