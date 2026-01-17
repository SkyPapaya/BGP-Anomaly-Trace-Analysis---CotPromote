import asyncio
from bgp_agent import BGPAgent

async def main():
    print(">>> 启动 BGP Agent 综合测试 (Powered by RIPEstat) <<<\n")
    
    # 场景 1: Twitter 劫持 (真实案例复现)
    # 预期: MALICIOUS
    hijack_case = {
        "prefix": "104.244.42.0/24",
        "as_path": "174 12389",  # Cogent -> Rostelecom
        "description": "Twitter Hijack by Rostelecom"
    }

    # 场景 2: Google 正常流量
    # 预期: BENIGN
    normal_case = {
        "prefix": "8.8.8.0/24",
        "as_path": "3356 15169", # Level3 -> Google
        "description": "Google DNS Normal Traffic"
    }

    agent = BGPAgent()

    # 运行 劫持案例
    print(f"🚨 测试案例 A: {hijack_case['description']}")
    await agent.diagnose(hijack_case)
    
    print("\n--------------------------------------------------\n")

    # 运行 正常案例
    print(f"✅ 测试案例 B: {normal_case['description']}")
    await agent.diagnose(normal_case)

if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())