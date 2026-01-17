import asyncio
import json
import re
from openai import AsyncOpenAI
from tools.bgp_toolkit import BGPToolKit  # 导入刚才做好的工具箱

# --- 配置 ---
API_KEY = "sk-9944c48494394db6b8bc31b40f8a710f"
BASE_URL = "https://api.deepseek.com"

class BGPAgent:
    def __init__(self):
        self.client = AsyncOpenAI(api_key=API_KEY, base_url=BASE_URL)
        self.toolkit = BGPToolKit()
        
        # 定义系统人设和可用工具说明
        self.system_prompt = """
你是一个高级 BGP 安全分析专家 (Agent)。你的任务是对 BGP 异常告警进行根因分析 (RCA)。
你拥有以下工具箱，请根据需要申请调用工具来验证你的假设：

1. `authority_check`: 查询 RPKI/ROA 授权状态 (检测非法宣告)。
2. `geo_check`: 检测 IP 与 Origin AS 的地理位置冲突 (检测跨国劫持)。
3. `neighbor_check`: 分析传播该路由的上游邻居 (Tier-1/ISP)。
4. `topology_check`: 检查 AS 路径是否违背商业逻辑 (Valley-Free)。
5. `stability_analysis`: 查询该前缀的历史更新频率。

**交互规则：**
1. 每次回复必须严格遵循 JSON 格式。
2. 即使你认为证据已经足够，也必须输出 JSON。
3. 这是一个多轮对话，你会分阶段获取信息。

**JSON 输出格式要求：**
{
    "thought_process": "简述你当前的分析思路...",
    "needs_more_evidence": true/false,
    "tool_requests": ["tool_name1", "tool_name2"],  // 如果不需要工具，填 []
    "final_diagnosis": {                             // 仅当 needs_more_evidence 为 false 时填写
        "status": "MALICIOUS_HIJACK" | "CONFIGURATION_ERROR" | "BENIGN",
        "confidence_score": 0-100,
        "summary": "最终的根因分析报告..."
    }
}
"""

    async def _call_llm(self, messages):
        """调用 DeepSeek 并解析 JSON"""
        try:
            response = await self.client.chat.completions.create(
                model="deepseek-chat",
                messages=messages,
                response_format={'type': 'json_object'}, # 强制 JSON 模式
                temperature=0.1 # 降低随机性，保证逻辑严密
            )
            content = response.choices[0].message.content
            # 清洗可能存在的 markdown 标记
            content = re.sub(r"```json|```", "", content).strip()
            return json.loads(content)
        except Exception as e:
            print(f"❌ LLM 调用或解析失败: {e}")
            return None

    async def diagnose(self, alert_context):
        """执行三层追问诊断流程"""
        print(f"\n🛡️  [Agent 启动] 开始诊断前缀: {alert_context['prefix']}")
        
        # 初始化对话历史
        messages = [
            {"role": "system", "content": self.system_prompt},
            {"role": "user", "content": f"检测到异常 BGP 更新：{json.dumps(alert_context)}。请开始分析。"}
        ]

        # 最多进行 3 轮追问 (防止死循环)
        max_rounds = 3
        
        for round_idx in range(1, max_rounds + 1):
            print(f"\n--- 第 {round_idx} 轮思考 (Layer {round_idx}) ---")
            
            # 1. AI 思考
            response_json = await self._call_llm(messages)
            if not response_json: break
            
            print(f"🧠 思维链: {response_json.get('thought_process')}")

            # 2. 判断是否结束
            if not response_json.get("needs_more_evidence", False):
                print("✅ 诊断完成，生成最终报告。")
                return response_json.get("final_diagnosis")

            # 3. 执行工具调用 (Action)
            tools_to_run = response_json.get("tool_requests", [])
            if not tools_to_run:
                print("⚠️ AI 表示需要证据但未指定工具，强制结束。")
                break

            tool_outputs = []
            print(f"🛠️  AI 申请调用工具: {tools_to_run}")
            
            for tool_name in tools_to_run:
                # 实际调用 bgp_toolkit
                result = self.toolkit.call_tool(tool_name, alert_context)
                print(f"    -> {result}")
                tool_outputs.append(result)

            # 4. 将工具结果反馈给 AI (Observation)
            feedback_msg = f"工具执行结果如下：\n" + "\n".join(tool_outputs) + "\n请根据这些新证据继续分析。"
            messages.append({"role": "assistant", "content": json.dumps(response_json)})
            messages.append({"role": "user", "content": feedback_msg})

        return None

# --- 测试入口 ---
if __name__ == "__main__":
    # 模拟 Twitter 2022 真实劫持数据
    # AS12389 (Rostelecom) 劫持 AS13414 (Twitter)
    test_alert = {
        "prefix": "104.244.42.0/24",
        "as_path": "174 12389",  # Cogent -> Rostelecom
        "timestamp": 1648474800,
        "anomaly_score": 0.85
    }

    agent = BGPAgent()
    
    # 运行异步任务
    loop = asyncio.get_event_loop()
    final_report = loop.run_until_complete(agent.diagnose(test_alert))

    if final_report:
        print("\n" + "="*40)
        print("📝 最终 RCA 报告 (Root Cause Analysis)")
        print("="*40)
        print(f"判定状态: {final_report['status']}")
        print(f"置信度:   {final_report['confidence_score']}/100")
        print(f"详细总结: {final_report['summary']}")
        print("="*40)