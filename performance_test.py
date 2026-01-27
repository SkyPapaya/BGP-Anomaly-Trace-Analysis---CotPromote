import asyncio
import time
import json
import traceback
from bgp_agent import BGPAgent
from tabulate import tabulate

# ==========================================
# 🕵️‍♂️ 5大经典 BGP 溯源案例 (Forensics Cases)
# ==========================================
CLASSIC_FORENSICS_CASES = [
    # Case 1: YouTube 劫持案 (2008)
    # 事实: 巴基斯坦电信 (AS17557) 为了封锁 YouTube，错误地将路由宣告到了全球。
    # 关键点: Origin 变成了 17557，而合法 Owner 是 36561。
    {
        "name": "YouTube / Pakistan Telecom",
        "context": {
            "prefix": "208.65.153.0/24",
            "as_path": "3491 17557",  # PCCW -> Pakistan Telecom
            "detected_origin": "17557",
            "expected_origin": "36561"
        },
        "expected_attacker": "17557", # 必须精准锁定这个 AS
        "type": "HIJACK"
    },

    # Case 2: Twitter 劫持案 (2022)
    # 事实: 俄罗斯 Rostelecom (AS12389) 劫持了 Twitter 的流量。
    # 关键点: Origin 突变为 12389。
    {
        "name": "Twitter / Rostelecom",
        "context": {
            "prefix": "104.244.42.0/24",
            "as_path": "174 12389", 
            "detected_origin": "12389",
            "expected_origin": "13414"
        },
        "expected_attacker": "12389",
        "type": "HIJACK"
    },

    # Case 3: Amazon DNS (MyEtherWallet) 劫持案 (2018)
    # 事实: eNet (AS10297) 劫持了 Amazon Route53 的网段，目的是盗取加密货币。
    # 关键点: Origin 变为 10297。
    {
        "name": "Amazon / eNet (Crypto Hack)",
        "context": {
            "prefix": "205.251.192.0/24",
            "as_path": "6939 10297", 
            "detected_origin": "10297",
            "expected_origin": "16509"
        },
        "expected_attacker": "10297",
        "type": "HIJACK"
    },

    # Case 4: Google / Indosat 劫持案 (2014)
    # 事实: 印尼 ISP (Indosat, AS4761) 错误宣告了 Google 的前缀。
    # 关键点: Origin 变为 4761。
    {
        "name": "Google / Indosat Hijack",
        "context": {
            "prefix": "209.85.128.0/24",
            "as_path": "3356 4761",
            "detected_origin": "4761",
            "expected_origin": "15169"
        },
        "expected_attacker": "4761",
        "type": "HIJACK"
    },

    # Case 5: 路由泄露 (复杂题) - Cloudflare / Verizon (2019)
    # 事实: DQE (AS33154) 把路由泄露给了 Verizon (AS701)。
    # 关键点: Origin (13335) 是正确的！但是路径里出现了不该出现的中间人 DQE (33154)。
    # 这里的 "Attacker/Culprit" 是泄露者 33154。
    {
        "name": "Cloudflare / Verizon Leak",
        "context": {
            "prefix": "1.1.1.1/32",
            "as_path": "701 33154 13335", # Verizon -> DQE -> Cloudflare
            "detected_origin": "13335",
            "expected_origin": "13335" # Origin 是对的
        },
        "expected_attacker": "33154", # 期望找出中间泄露者 (难度高，看Agent造化)
        "type": "LEAK"
    }
]

async def run_benchmark():
    print("🚀 正在初始化 BGP 溯源 Agent (Forensics Mode)...")
    try:
        agent = BGPAgent()
    except Exception as e:
        print(f"❌ 初始化失败: {e}")
        return

    results_table = []
    print(f"\n⚡ 开始 5 轮核心溯源测试 (寻找 Attacker AS)...\n")

    for i, case in enumerate(CLASSIC_FORENSICS_CASES):
        print(f"[{i+1}/5] 分析案件: {case['name']} ... ", end="", flush=True)
        
        start_time = time.time()
        
        try:
            # 执行诊断
            trace = await agent.diagnose(case['context'], verbose=False)
            
            # 提取 AI 的判断
            final = trace.get("final_result", {}) or {}
            
            # 获取 AI 锁定的攻击者 AS
            # AI 可能返回 "AS12389" 或 "12389"，我们统一清洗一下
            ai_attacker_raw = str(final.get("attacker_as", "Unknown"))
            ai_attacker = ''.join(filter(str.isdigit, ai_attacker_raw)) # 只保留数字
            
            status = final.get("status", "UNKNOWN")
            
            # 判断是否命中 (只要数字对上就算对)
            expected = case['expected_attacker']
            is_correct = (ai_attacker == expected)
            
            verdict_icon = "✅ HIT" if is_correct else f"❌ MISS (Got {ai_attacker})"
            
        except Exception as e:
            print(f"\n❌ [CRASH] Case: {case['name']}")
            traceback.print_exc()
            ai_attacker = "ERROR"
            verdict_icon = "⚠️ ERROR"
            status = "CRASH"

        duration = time.time() - start_time
        print(f"完成 ({duration:.2f}s)")

        # 记录数据
        results_table.append([
            case['name'],
            case['type'],
            f"AS{case['expected_attacker']}",
            f"AS{ai_attacker}" if ai_attacker.isdigit() else ai_attacker,
            status,
            verdict_icon,
            f"{duration:.1f}s"
        ])

    # 输出漂亮的表格
    print("\n" + "="*100)
    print("📢 BGP 溯源能力评估报告 (Attribution Test)")
    print("="*100)
    headers = ["Case Name", "Type", "Real Attacker", "AI Identified", "AI Status", "Verdict", "Time"]
    print(tabulate(results_table, headers=headers, tablefmt="grid"))
    
    # 计算准确率
    hits = sum(1 for r in results_table if "HIT" in r[5])
    print(f"\n🎯 准确率: {hits}/{len(CLASSIC_FORENSICS_CASES)} ({hits/len(CLASSIC_FORENSICS_CASES)*100:.0f}%)")

if __name__ == "__main__":
    asyncio.run(run_benchmark())