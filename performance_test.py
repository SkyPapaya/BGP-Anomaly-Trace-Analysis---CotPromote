import asyncio
import time
from bgp_agent import BGPAgent
from tabulate import tabulate  
import traceback

# --- 5个经典 BGP 案例 (真实 ASN) ---
CLASSIC_CASES = [
    # 1. [Twitter Hijack 2022] - 你的毕设核心案例
    # 特征：俄罗斯 ISP 劫持 Twitter，图谱应显示“拓扑异常”
    {
        "name": "Twitter/Rostelecom Hijack",
        "context": {
            "prefix": "104.244.42.0/24",
            "as_path": "174 12389", 
            "detected_origin": "12389",
            "expected_origin": "13414",
            "timestamp": 1648474800
        },
        "expected_result": "MALICIOUS"
    },
    
    # 2. [YouTube/Pakistan Telecom 2008] - 著名的审查劫持
    # 特征：巴基斯坦电信 (AS17557) 劫持 YouTube (AS36561)
    {
        "name": "YouTube/Pakistan Censorship",
        "context": {
            "prefix": "208.65.153.0/24",
            "as_path": "3491 17557",
            "detected_origin": "17557",
            "expected_origin": "36561",
            "timestamp": 1203879600
        },
        "expected_result": "MALICIOUS"
    },

    # 3. [Google/MainOne Route Leak 2018] - 著名的路由泄露
    # 特征：尼日利亚 ISP (AS37282) 泄露了 Google (AS15169) 的流量
    # 注意：Origin 正确，但路径完全错误 (Valley-Free 违规)
    {
        "name": "Google/MainOne Leak",
        "context": {
            "prefix": "216.58.200.0/24",
            "as_path": "174 37282 15169", # Cogent -> MainOne -> Google
            "detected_origin": "15169", # Origin 是对的！
            "expected_origin": "15169",
            "timestamp": 1542000000
        },
        "expected_result": "LEAK" # 或者是 Anomalous / Warning
    },

    # 4. [Cloudflare/Verizon Leak 2019] - 导致全球掉线
    # 特征：Verizon (AS701) 错误接收了 DQE (AS33154) 的路由
    {
        "name": "Cloudflare/Verizon Leak",
        "context": {
            "prefix": "104.16.0.0/12",
            "as_path": "701 33154 13335",
            "detected_origin": "13335",
            "expected_origin": "13335",
            "timestamp": 1561380000
        },
        "expected_result": "LEAK"
    },

    # 5. [正常案例] - 负样本测试
    # 特征：Google 直连正常路径
    {
        "name": "Google Normal Traffic",
        "context": {
            "prefix": "8.8.8.0/24",
            "as_path": "3356 15169",
            "detected_origin": "15169",
            "expected_origin": "15169",
            "timestamp": 1678888888
        },
        "expected_result": "BENIGN"
    }
]

async def run_benchmark():
    print("🚀 正在初始化 BGP Agent (加载 Neo4j + Vector DB)...")
    agent = BGPAgent()
    
    results_table = []
    print(f"\n⚡ 开始 5 轮经典案例测试...\n")

    for i, case in enumerate(CLASSIC_CASES):
        print(f"[{i+1}/5] 测试: {case['name']} ... ", end="", flush=True)
        
        start_time = time.time()
        
        # 核心调用
        try:
            trace = await agent.diagnose(case['context'], verbose=False)
            
            # 提取结果
            final = trace.get("final_result", {})
            status = final.get("status", "UNKNOWN")
            summary = final.get("summary", "")[:50] + "..." # 只取前50个字
            
            # 检查是否调用了 Graph RAG
            chain = trace.get("chain_of_thought", [])
            used_tools = [step.get("tool_used") for step in chain if step.get("tool_used")]
            has_graph = "graph_analysis" in used_tools
            
        except Exception as e:
            print(f"\n❌ [CRASH] Case: {case['name']}")
            traceback.print_exc()  # <--- 【关键】打印完整报错堆栈！
            status = f"ERROR: {e}"
            summary = "N/A"
            has_graph = False

        duration = time.time() - start_time
        print(f"✅ 完成 ({duration:.2f}s)")

        # 记录数据
        results_table.append([
            case['name'],
            case['expected_result'],
            status,
            f"{duration:.2f}s",
            "✅ YES" if has_graph else "❌ NO",
            summary
        ])

    # 输出漂亮的表格
    print("\n" + "="*80)
    print("📢 BGP Agent 综合性能测试报告")
    print("="*80)
    headers = ["Case Name", "Expected", "AI Verdict", "Time", "Graph RAG?", "Summary"]
    print(tabulate(results_table, headers=headers, tablefmt="grid"))

if __name__ == "__main__":
    import sys, os

    asyncio.run(run_benchmark())