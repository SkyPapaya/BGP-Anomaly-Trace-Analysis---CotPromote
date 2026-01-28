import asyncio
import time
import json
import os
import traceback
from bgp_agent import BGPAgent
from tabulate import tabulate

# 配置文件路径
TEST_CASES_FILE = "data/test_cases.json"

def load_test_cases():
    """从 JSON 文件加载测试案例"""
    if not os.path.exists(TEST_CASES_FILE):
        print(f"❌ 错误: 找不到测试文件 {TEST_CASES_FILE}")
        return []
    
    try:
        with open(TEST_CASES_FILE, 'r', encoding='utf-8') as f:
            cases = json.load(f)
            print(f"📂 成功加载 {len(cases)} 个测试案例。")
            return cases
    except Exception as e:
        print(f"❌ 读取 JSON 失败: {e}")
        return []

async def run_benchmark():
    # 1. 加载案例
    cases = load_test_cases()
    if not cases:
        return

    # 2. 初始化 Agent
    print("🚀 正在初始化 BGP 溯源 Agent...")
    try:
        agent = BGPAgent()
    except Exception as e:
        print(f"❌ Agent 初始化失败: {e}")
        return

    results_table = []
    print(f"\n⚡ 开始 {len(cases)} 轮全场景测试 (溯源能力评估)...\n")

    # 3. 循环测试
    correct_count = 0
    
    for i, case in enumerate(cases):
        print(f"[{i+1}/{len(cases)}] {case['name']} ({case['type']}) ... ", end="", flush=True)
        
        start_time = time.time()
        
        # 默认值
        ai_attacker = "N/A"
        status = "UNKNOWN"
        verdict_icon = "❓"
        
        try:
            # === 核心调用 ===
            trace = await agent.diagnose(case['context'], verbose=False)
            
            # 提取结果
            final = trace.get("final_result", {}) or {}
            status = final.get("status", "UNKNOWN")
            
            # 清洗 AI 返回的 Attacker AS (只保留数字)
            raw_attacker = str(final.get("attacker_as", "None"))
            if raw_attacker.lower() == "none" or raw_attacker.lower() == "unknown":
                ai_attacker = "None"
            else:
                ai_attacker = ''.join(filter(str.isdigit, raw_attacker))
                if not ai_attacker: ai_attacker = "None"

            # === 判分逻辑 ===
            expected = case['expected_attacker']
            
            # 特殊情况：如果是 BENIGN (正常)，Expected 是 None
            if case['type'] == 'BENIGN':
                if ai_attacker == "None" or status == "BENIGN":
                    is_correct = True
                else:
                    is_correct = False
            else:
                # 攻击案例：必须找对 AS 号
                is_correct = (ai_attacker == expected)

            if is_correct:
                correct_count += 1
                verdict_icon = "✅ HIT"
            else:
                verdict_icon = "❌ MISS"

        except Exception as e:
            print(f"\n❌ [CRASH] {str(e)}")
            # traceback.print_exc()
            status = "ERROR"
            verdict_icon = "⚠️ CRASH"

        duration = time.time() - start_time
        print(f"完成 ({duration:.2f}s)")

        # 添加到结果表
        results_table.append([
            case['name'][:30], # 截断名字以免太长
            case['type'],
            f"AS{case['expected_attacker']}",
            f"AS{ai_attacker}",
            status,
            verdict_icon,
            f"{duration:.1f}s"
        ])

    # 4. 输出最终报告
    print("\n" + "="*110)
    print("📢 BGP Agent 综合实战评估报告")
    print("="*110)
    headers = ["Case Name", "Type", "Real Attacker", "AI Verdict", "Status", "Result", "Time"]
    print(tabulate(results_table, headers=headers, tablefmt="grid"))
    
    accuracy = (correct_count / len(cases)) * 100
    print(f"\n🎯 最终得分: {correct_count}/{len(cases)} ({accuracy:.1f}%)")
    
    if accuracy > 80:
        print("🏆 评级: 优秀 (Expert)")
    elif accuracy > 60:
        print("🥈 评级: 合格 (Junior)")
    else:
        print("🔧 评级: 需要优化 (Needs Improvement)")

if __name__ == "__main__":
    asyncio.run(run_benchmark())