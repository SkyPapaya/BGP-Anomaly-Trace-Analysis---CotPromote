import asyncio
import json
import re
import os
from datetime import datetime , timezone
from openai import AsyncOpenAI
from tools.bgp_toolkit import BGPToolKit

# --- 配置 ---
API_KEY = "sk-9944c48494394db6b8bc31b40f8a710f"
BASE_URL = "https://api.deepseek.com"

class BGPAgent:
    
    def __init__(self):
        self.client = AsyncOpenAI(api_key=API_KEY, base_url=BASE_URL)
        self.toolkit = BGPToolKit()
        
        # 定义核心人设 (System Prompt)
        self.system_prompt = """
你是一个 BGP 安全专家 Agent。你的目标是通过多轮排查，确定一个 BGP 更新是否为恶意劫持。
你拥有以下工具：
1. `authority_check`: 查询 RPKI 状态 (验证授权)。
2. `geo_check`: 对比 IP 和 ASN 的地理位置 (验证跨国冲突)。
3. `neighbor_check`: 查询传播路径的上游邻居 (验证传播范围)。
4. `topology_check`: 检查商业关系逻辑 (验证路由泄露)。
5. `stability_analysis`: 检查前缀更新历史 (验证震荡)。

**工作流程：**
这是一个 3 轮的对话。每一轮你都需要根据当前的已知信息，决定下一步行动。

**输出格式要求 (必须是 JSON)：**
{
    "round_id": int,                 // 当前是第几轮 (1, 2, or 3)
    "thought_process": "string",     // 详细的思维链：你看到了什么？你怀疑什么？为什么？
    "suspicion_level": "low/medium/high", 
    "missing_info": "string",        // 你觉得还缺什么证据？
    "tool_request": "string",        // 你决定调用的工具名 (一次只调一个，若无需工具填 null)
    "final_decision": {              // 仅在第 3 轮或证据确凿时填写，否则为 null
        "status": "MALICIOUS" | "BENIGN" | "UNKNOWN",
        "summary": "最终结论..."
    }
}
"""

    async def _call_llm(self, messages):
        """发送当前所有对话历史给 DeepSeek"""
        try:
            print("⏳ 正在请求 DeepSeek 思考...", end="", flush=True)
            response = await self.client.chat.completions.create(
                model="deepseek-chat",
                messages=messages,
                response_format={'type': 'json_object'},
                temperature=0.1
            )
            print(" ✅ 完成")
            content = response.choices[0].message.content
            return json.loads(content)
        except Exception as e:
            print(f"\n❌ API 调用失败: {e}")
            return None

    def _save_trace(self, trace_data):
        current_time = datetime.now(timezone.utc)

        """将完整的思维链保存到本地文件"""
        #filename = "./report/diagnosis_trace_"+ current_time.strftime("%Y-%m-%d_%H:%M:%S")+f"{time}"+".json"
        filename = "./report/diagnosis_trace_"+ current_time.strftime("%Y-%m-%d_%H:%M:%S")+".json"
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(trace_data, f, indent=4, ensure_ascii=False)
        return filename

    async def diagnose(self, alert_context):
        print(f"\n🛡️  [Agent] 开始诊断前缀: {alert_context['prefix']}")
        print(f"📄 原始 AS_PATH: {alert_context['as_path']}")
        
        # 1. 初始化记忆 (Memory)
        messages = [
            {"role": "system", "content": self.system_prompt},
            {"role": "user", "content": f"【系统告警】检测到异常路由更新：\n{json.dumps(alert_context, indent=2)}\n请开始第 1 轮分析。"}
        ]
        
        # 用于保存到本地的完整记录
        full_trace = {
            "target": alert_context,
            "start_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "rounds": []
        }

        
        # 2. 开始三层追问循环
        for round_idx in range(1, 4):
            
            print(f"\n--- Round {round_idx}/3 (Layer {round_idx}) ---")
            
            # --- STEP 1: AI 思考 ---
            response_json = await self._call_llm(messages)
            if not response_json: break
            
            # 打印 AI 的思考过程
            print(f"🧠 AI 想法: {response_json.get('thought_process')}")
            print(f"🔍 怀疑等级: {response_json.get('suspicion_level')}")
            
            # 记录到本地 Trace
            full_trace["rounds"].append({
                "round": round_idx,
                "ai_response": response_json,
                "tool_output": None
            })
            self._save_trace(full_trace) # 实时保存
           

            # --- STEP 2: 检查是否得出结论 ---
            final_decision = response_json.get("final_decision")
            if final_decision:
                print(f"\n🎉 诊断结束！结论已生成。")
                return final_decision

            # --- STEP 3: 执行工具 (Action) ---
            tool_name = response_json.get("tool_request")
            tool_result = "未请求工具，请直接进行下一轮推断。"
            
            if tool_name:
                print(f"🛠️  调用工具: {tool_name} ...", end="")
                tool_output_raw = self.toolkit.call_tool(tool_name, alert_context)
                print(f" -> 返回结果")
                print(f"    📄 {tool_output_raw}")
                
                # 格式化工具结果
                tool_result = f"【工具 {tool_name} 运行结果】:\n{tool_output_raw}"
                
                # 更新本地 Trace
                full_trace["rounds"][-1]["tool_output"] = tool_output_raw
                self._save_trace(full_trace)

            # --- STEP 4: 更新上下文 (Memory) ---
            # 将 AI 的回复加入历史 (Assistant 角色)
            messages.append({"role": "assistant", "content": json.dumps(response_json)})
            # 将工具的结果加入历史 (User 角色，模拟外界反馈)
            messages.append({"role": "user", "content": f"{tool_result}\n\n现在请基于以上新证据，进行第 {round_idx + 1} 轮分析。"})
            
        return None

# --- 主程序 ---
if __name__ == "__main__":
    # 模拟数据
    test_alert = {
        "prefix": "104.244.42.0/24",
        "as_path": "174 12389",
        "timestamp": 1648474800,
        "anomaly_score": 0.85
    }
    agent = BGPAgent()

    loop = asyncio.get_event_loop()
    final_report = loop.run_until_complete(agent.diagnose(test_alert))

    if final_report:
        print("\n" + "="*40)
        print("📝 最终 RCA 报告")
        print("="*40)
        print(f"判定: {final_report['status']}")
        print(f"总结: {final_report['summary']}")
        print(f"\n✅ 完整思维链已保存至: diagnosis_trace.json")