import asyncio
import json
import os
import traceback  # 引入这个以便打印报错细节
from datetime import datetime
from openai import AsyncOpenAI
from tools.bgp_toolkit import BGPToolKit
from tools.rag_manager import RAGManager

# --- 配置 ---
API_KEY = "sk-9944c48494394db6b8bc31b40f8a710f"
BASE_URL = "https://api.deepseek.com"

class BGPAgent:
    def __init__(self, report_dir="./report"):
        self.client = AsyncOpenAI(api_key=API_KEY, base_url=BASE_URL)
        self.toolkit = BGPToolKit()
        # 确保路径与 build_vector_db.py 中一致
        self.rag = RAGManager(db_path="./rag_db") 
        self.report_dir = report_dir

        # ==========================================
        # 🎯 核心修改：强化 Prompt 的格式约束
        # ==========================================
        self.base_system_prompt = """
你是一个 BGP 安全专家 Agent。你的目标是结合【历史案例知识】和【实时工具检测】，对 BGP 异常进行定性。

**可用工具清单:**
1. `authority_check`: 查询 RPKI 授权状态。
2. `geo_check`: 检查地理位置冲突。
3. `neighbor_check`: 检查上游邻居信誉。
4. `topology_check`: 检查 AS 路径商业关系 (Valley-Free)。
5. `graph_analysis`: 查询知识图谱，检查 Origin 与 Owner 的真实拓扑距离。

**⚠️ 严格输出格式约束 (JSON):**
你必须每一次回复都只输出一个标准的 JSON 对象，格式如下：
{
    "thought_process": "你的思考过程...",
    "suspicion_level": "LOW" | "MEDIUM" | "HIGH",
    "tool_request": "工具名称字符串" OR null, 
    "final_decision": null OR { "status": "MALICIOUS/LEAK/BENIGN", "summary": "..." }
}

**❌ 禁忌事项:**
1. `tool_request` 字段必须是 **字符串 (String)** (例如 "graph_analysis") 或 null。
2. **严禁** 在 `tool_request` 中返回对象/字典 (例如 {"name": "graph_analysis"} 是错误的！)。
3. 如果需要使用工具，`final_decision` 必须为 null。
4. 只有在收集到足够证据后，才将 `tool_request` 设为 null 并填充 `final_decision`。
"""

    async def _call_llm(self, messages):
        """调用 DeepSeek 大模型"""
        try:
            response = await self.client.chat.completions.create(
                model="deepseek-chat",
                messages=messages,
                response_format={'type': 'json_object'}, # 强制 JSON 模式
                temperature=0.0 # 0 温度保证逻辑严谨
            )
            content = response.choices[0].message.content
            return json.loads(content)
        except Exception as e:
            print(f"❌ API 调用失败: {e}")
            return {"thought_process": f"API Error: {str(e)}", "tool_request": None}

    def _save_report_to_disk(self, trace_data):
        """保存报告"""
        if not os.path.exists(self.report_dir):
            os.makedirs(self.report_dir, exist_ok=True)

        raw_prefix = trace_data.get("target", {}).get("prefix", "unknown")
        safe_prefix = raw_prefix.replace("/", "_")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"analysis_{safe_prefix}_{timestamp}.json"
        file_path = os.path.join(self.report_dir, filename)

        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(trace_data, f, indent=4, ensure_ascii=False)
            # print(f"💾 报告归档: {filename}")
        except Exception as e:
            print(f"❌ 保存失败: {e}")

    async def diagnose(self, alert_context, verbose=False):
        if verbose: print(f"\n🛡️  [Agent] 开始诊断: {alert_context.get('prefix')}...")

        # --- Phase 1: RAG 检索 ---
        try:
            retrieved_knowledge = self.rag.search_similar_cases(alert_context, k=2)
            if verbose and "未找到" not in str(retrieved_knowledge):
                print(f"📚 [RAG 命中] 检索到历史案例参考...")
        except Exception:
            retrieved_knowledge = "(RAG 暂时不可用)"

        # --- Phase 2: 构建 Prompt ---
        dynamic_prompt = f"""
{self.base_system_prompt}

【🧠 历史知识库参考 (RAG)】
{retrieved_knowledge}

【当前待分析告警】
Prefix: {alert_context.get('prefix')}
Path: {alert_context.get('as_path')}
Origin: {alert_context.get('detected_origin')}
Expected Origin: {alert_context.get('expected_origin')}
"""
        messages = [
            {"role": "system", "content": dynamic_prompt},
            {"role": "user", "content": "检测到 BGP 异常，请严格按 JSON 格式输出分析。"}
        ]
        
        full_trace = {
            "target": alert_context,
            "start_time": datetime.now().isoformat(),
            "rag_context": retrieved_knowledge,
            "chain_of_thought": [],
            "final_result": None
        }

        # --- Phase 3: 多轮推理 ---
        for round_idx in range(1, 4):
            if verbose: print(f"--- Round {round_idx} ---")
            
            response_json = await self._call_llm(messages)
            if not response_json: break
            
            # 提取关键字段
            tool_name_raw = response_json.get("tool_request")
            final_decision = response_json.get("final_decision")

            # ==========================================
            # 🛡️ 代码防御：防止 "unhashable type: dict"
            # 即使 Prompt 写得再好，也要防止 AI 偶尔抽风
            # ==========================================
            tool_name = tool_name_raw
            if tool_name_raw:
                # 1. 如果是字典，尝试提取 values
                if isinstance(tool_name_raw, dict):
                    if verbose: print(f"⚠️ [自动修正] AI 返回了字典格式: {tool_name_raw}")
                    # 尝试取第一个 value，或者是 'name' 字段
                    tool_name = tool_name_raw.get('name') or tool_name_raw.get('tool') or list(tool_name_raw.values())[0]
                
                # 2. 强制转为字符串并去空格
                tool_name = str(tool_name).strip()
                
                # 3. 处理 "None" 字符串的情况
                if tool_name.lower() == "none":
                    tool_name = None

            trace_item = {
                "round": round_idx,
                "ai_thought": response_json.get("thought_process"),
                "tool_used": tool_name, # 记录修正后的名字
                "tool_output": None
            }

            # 逻辑分支：优先执行工具
            if tool_name:
                if verbose: print(f"🛠️  Agent 调用工具: {tool_name}")
                
                # 这里现在肯定是安全的字符串了
                tool_result_str = self.toolkit.call_tool(tool_name, alert_context)
                trace_item["tool_output"] = tool_result_str
                
                full_trace["chain_of_thought"].append(trace_item)
                
                # 将结果喂回给 AI
                messages.append({"role": "assistant", "content": json.dumps(response_json)})
                messages.append({"role": "user", "content": f"【工具反馈】\n{tool_result_str}\n\n请继续分析。如果证据不足可继续调用其他工具；如果证据确凿，请返回 final_decision。"})
                continue # 跳过下面的结案逻辑

            # 如果没有工具请求，检查是否结案
            if final_decision:
                full_trace["final_result"] = final_decision
                full_trace["chain_of_thought"].append(trace_item)
                if verbose: print("✅ 诊断结束 (AI 自主结案)。")
                self._save_report_to_disk(full_trace)
                return full_trace

            # 既没工具也没结论 (罕见)
            full_trace["chain_of_thought"].append(trace_item)
            messages.append({"role": "assistant", "content": json.dumps(response_json)})
            messages.append({"role": "user", "content": "请继续分析。"})

        # --- Phase 4: 强制结算 ---
        if full_trace["final_result"] is None:
            if verbose: print("⚠️ 强制结算...")
            messages.append({"role": "user", "content": "分析轮次已尽。请忽略未完成步骤，立即基于现有信息生成 final_decision JSON。"})
            final_resp = await self._call_llm(messages)
            if final_resp:
                full_trace["final_result"] = final_resp.get("final_decision")
        
        self._save_report_to_disk(full_trace)
        return full_trace

if __name__ == "__main__":
    agent = BGPAgent()
    test_data = {
        "prefix": "104.244.42.0/24", 
        "as_path": "174 12389", 
        "detected_origin": "12389", 
        "expected_origin": "13414"
    }
    asyncio.run(agent.diagnose(test_data, verbose=True))