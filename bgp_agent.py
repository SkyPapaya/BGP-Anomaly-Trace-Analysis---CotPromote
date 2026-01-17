import asyncio
import json
import os
import re
from datetime import datetime
from openai import AsyncOpenAI
from tools.bgp_toolkit import BGPToolKit

# --- 配置 ---
API_KEY = "sk-9944c48494394db6b8bc31b40f8a710f"
BASE_URL = "https://api.deepseek.com"

class BGPAgent:
    def __init__(self, report_dir="./report"):
        self.client = AsyncOpenAI(api_key=API_KEY, base_url=BASE_URL)
        self.toolkit = BGPToolKit()
        
        # 报告存储路径
        self.report_dir = report_dir
        
        self.system_prompt = """
你是一个 BGP 安全专家 Agent。你的目标是通过多轮排查，确定一个 BGP 更新是否为恶意劫持。
**可用工具箱 (严禁使用除此之外的任何工具):**
1. `authority_check`: 查询 RPKI 授权状态 (检查 Origin AS 是否合法)。
2. `geo_check`: 检查 IP 和 ASN 的地理位置 (检查跨国冲突)。
3. `neighbor_check`: 检查传播该路由的上游邻居 (AS 174, 3356 等)。
4. `topology_check`: 检查 AS 路径的商业关系 (检查路由泄露)。

**工作流程与“死线”机制：**
这是一个最多 3 轮的对话。
1. 在第 1 轮和第 2 轮：如果证据不足，优先申请工具。
2. **在第 3 轮（最后一轮）：你必须根据当前所有已知信息，强制给出 final_decision。严禁在第 3 轮申请工具或返回 final_decision 为 null。**

**输出格式要求 (必须是 JSON)：**
{
    "round_id": int,
    "thought_process": "string",
    "suspicion_level": "low/medium/high", 
    "tool_request": "string",  // 第 3 轮必须为 null
    "final_decision": {        // 第 3 轮或证据确凿时必须填写
        "status": "MALICIOUS" | "BENIGN" | "UNKNOWN",
        "summary": "最终结论..."
    }
}
"""

    async def _call_llm(self, messages):
        try:
            response = await self.client.chat.completions.create(
                model="deepseek-chat",
                messages=messages,
                response_format={'type': 'json_object'},
                temperature=0.0
            )
            content = response.choices[0].message.content
            return json.loads(content)
        except Exception as e:
            return {"error": str(e)}

    def _save_report_to_disk(self, trace_data):
        """内部方法：将诊断结果写入硬盘"""
        # 1. 确保目录存在
        if not os.path.exists(self.report_dir):
            try:
                os.makedirs(self.report_dir, exist_ok=True)
            except Exception as e:
                print(f"❌ 无法创建目录 {self.report_dir}: {e}")
                return

        # 2. 生成文件名
        # 安全处理: 将 104.244.42.0/24 转换为 104.244.42.0_24
        raw_prefix = trace_data.get("target", {}).get("prefix", "unknown")
        safe_prefix = raw_prefix.replace("/", "_")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        filename = f"analysis_{safe_prefix}_{timestamp}.json"
        file_path = os.path.join(self.report_dir, filename)

        # 3. 写入文件
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(trace_data, f, indent=4, ensure_ascii=False)
            print(f"💾 [Agent] 报告已自动归档: {file_path}")
        except Exception as e:
            print(f"❌ [Agent] 报告保存失败: {e}")

    async def diagnose(self, alert_context, verbose=False):
        """
        执行诊断流程，并自动保存报告到指定目录。
        """
        if verbose:
            print(f"\n🛡️  [Agent] 开始诊断: {alert_context.get('prefix')}...")

        messages = [
            {"role": "system", "content": self.system_prompt},
            {"role": "user", "content": f"【系统告警】检测到异常路由更新：\n{json.dumps(alert_context)}\n请开始分析。"}
        ]
        
        full_trace = {
            "target": alert_context,
            "start_time": datetime.now().isoformat(),
            "chain_of_thought": [],
            "final_result": None
        }

        for round_idx in range(1, 4):
            if verbose: print(f"--- Round {round_idx} ---")
            
            # 1. AI 思考
            response_json = await self._call_llm(messages)
            if not response_json: break
            
            trace_item = {
                "round": round_idx,
                "ai_thought": response_json.get("thought_process"),
                "suspicion": response_json.get("suspicion_level"),
                "tool_used": response_json.get("tool_request"),
                "tool_output": None
            }

            # 2. 检查结论
            final_decision = response_json.get("final_decision")
            if final_decision:
                full_trace["final_result"] = final_decision
                full_trace["chain_of_thought"].append(trace_item)
                if verbose: print("✅ 诊断结束。")
                
                # --- 关键修改：退出前自动保存 ---
                self._save_report_to_disk(full_trace)
                return full_trace

            # 3. 执行工具
            tool_name = response_json.get("tool_request")
            tool_result_str = "未请求工具。"
            
            if tool_name:
                if verbose: print(f"🛠️  Calling: {tool_name}")
                tool_result_str = self.toolkit.call_tool(tool_name, alert_context)
                trace_item["tool_output"] = tool_result_str

            full_trace["chain_of_thought"].append(trace_item)

            # 4. 更新上下文
            messages.append({"role": "assistant", "content": json.dumps(response_json)})
            messages.append({"role": "user", "content": f"【工具结果】\n{tool_result_str}\n\n请继续分析。"})

            #5. 循环结束后的强制结算 ---
        if full_trace["final_result"] is None:
            if verbose: print("⚠️ 达到最大轮次未出结论，强制进行最终判定...")
            
            # 构造一条强制指令
            messages.append({
                "role": "user", 
                "content": "【系统指令】已达到最大分析轮次。请忽略未完成的工具调用，根据现有的 RPKI、地理位置和 AS 路径证据，必须立即生成 final_decision JSON。"
            })
            
            # 最后调用一次 LLM
            final_resp = await self._call_llm(messages)
            
            if final_resp and final_resp.get("final_decision"):
                full_trace["final_result"] = final_resp.get("final_decision")
                # 记录这一轮“强制思考”
                full_trace["chain_of_thought"].append({
                    "round": "Final_Summary",
                    "ai_thought": final_resp.get("thought_process", "Forced Summary"),
                    "suspicion": final_resp.get("suspicion_level"),
                    "tool_used": None,
                    "tool_output": None
                })

        # 如果循环结束还没有结论，也保存当前状态
        self._save_report_to_disk(full_trace)
        return full_trace

if __name__ == "__main__":
    # 简单自测
    agent = BGPAgent() # 默认路径 /home/skypapaya/code/report
    test_data = {"prefix": "1.1.1.0/24", "as_path": "174 13335"} 
    asyncio.run(agent.diagnose(test_data, verbose=True))