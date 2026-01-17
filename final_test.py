import asyncio
import json
from bgp_agent import BGPAgent

# --- 盲测数据集 ---
TEST_SUITE = [
    {
        # Case 1: 真实劫持 (Twitter / Rostelecom)
        "prefix": "104.244.42.0/24",
        "as_path": "174 12389", 
        "timestamp": 1648474800
    },
    {
        # Case 2: 正常流量 (Google)
        "prefix": "8.8.8.0/24",
        "as_path": "3356 15169",
        "timestamp": 1678888888
    }
]

async def run_blind_test():
    # 实例化 Agent (它知道报告该存哪)
    agent = BGPAgent()
    
    print(f"🚀 启动 BGP Agent 盲测...\n")
    
    for i, case in enumerate(TEST_SUITE):
        print(f"Dataset #{i+1} Testing [Prefix: {case['prefix']}] ... ", end="", flush=True)
        
        # 只管调用，不管保存 (Agent 内部会处理)
        final_trace = await agent.diagnose(case, verbose=True)
        
        print("Done ✅")
        
        # 简单打印一下结论确认
        result = final_trace.get("final_result", {})
        status = result.get("status") if result else "无法判断"
        print(f"   -> Agent 结论: {status}")
        print("-" * 60)

if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(run_blind_test())