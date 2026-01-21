import asyncio
import json
import os
from datetime import datetime
from openai import AsyncOpenAI
from tools.bgp_toolkit import BGPToolKit
from tools.rag_manager import RAGManager

# --- 配置 ---
# 请确保这是有效的 DeepSeek API Key
API_KEY = "sk-9944c48494394db6b8bc31b40f8a710f"
BASE_URL = "https://api.deepseek.com"

class BGPAgent:
    def __init__(self, report_dir="./report"):
        """
        初始化 BGP Agent
        :param report_dir: 报告存储目录
        """
        self.client = AsyncOpenAI(api_key=API_KEY, base_url=BASE_URL)
        
        # 1. 初始化工具箱 (用于查询 RPKI, Geo 等)
        self.toolkit = BGPToolKit()
        
        # 2. 初始化 RAG 引擎 (指向我们刚才修复好的新数据库)
        # 注意：这里必须和 fix_rag_data.py 里生成的路径一致
        self.rag = RAGManager(db_path="./rag_db_new")
        
        self.report_dir = report_dir
        
        # 基础 Prompt模板 (后续会被动态 RAG 内容填充)
        self.base_system_prompt = """
你是一个 BGP 安全专家 Agent。你的目标是结合【历史案例知识】和【实时工具检测】，对 BGP 异常进行定性。

**可用工具:**
1. `authority_check`: 查询 RPKI 授权状态 (检查 Origin AS 是否合法)。
2. `geo_check`: 检查 IP 和 ASN 的地理位置 (检查跨国冲突)。
3. `neighbor_check`: 检查传播该路由的上游邻居 (AS 174, 3356 等)。
4. `topology_check`: 检查 AS 路径的商业关系 (检查路由泄露)。

**工作流程:**
这是一个最多 3 轮的对话。
- 第 1-2 轮: 根据现有信息，决定是否调用工具获取更多证据。
- 第 3 轮: 必须结合所有证据给出最终结论 (final_decision)。

**输出 JSON 格式:**
{
    "round_id": int,
    "thought_process": "思维链：分析当前情况，对比历史案例，决定下一步...",
    "suspicion_level": "low/medium/high", 
    "tool_request": "tool_name" | null,
    "final_decision": {
        "status": "MALICIOUS" | "BENIGN" | "UNKNOWN",
        "summary": "最终结论摘要..."
    }
}
"""

    async def _call_llm(self, messages):
        """调用 DeepSeek 大模型"""
        try:
            response = await self.client.chat.completions.create(
                model="deepseek-chat",
                messages=messages,
                response_format={'type': 'json_object'},
                temperature=0.0 # 0 温度保证逻辑严谨
            )
            content = response.choices[0].message.content
            return json.loads(content)
        except Exception as e:
            # 简单的错误处理，防止单次 API 失败导致崩盘
            return {"thought_process": f"API Error: {str(e)}", "tool_request": None}

    def _save_report_to_disk(self, trace_data):
        """将完整思维链保存为 JSON 文件"""
        if not os.path.exists(self.report_dir):
            os.makedirs(self.report_dir, exist_ok=True)

        # 生成文件名 (安全处理 / 转为 _)
        raw_prefix = trace_data.get("target", {}).get("prefix", "unknown")
        safe_prefix = raw_prefix.replace("/", "_")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        filename = f"analysis_{safe_prefix}_{timestamp}.json"
        file_path = os.path.join(self.report_dir, filename)

        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(trace_data, f, indent=4, ensure_ascii=False)
            print(f"💾 [Agent] 报告已自动归档: {file_path}")
        except Exception as e:
            print(f"❌ [Agent] 保存报告失败: {e}")

    async def diagnose(self, alert_context, verbose=False):
        """
        核心诊断流程
        :param alert_context: 异常上下文 (Prefix, Path, Origin...)
        :param verbose: 是否打印详细日志 (并发模式建议 False)
        """
        if verbose:
            print(f"\n🛡️  [Agent] 开始诊断: {alert_context.get('prefix')}...")

        # --- Phase 1: RAG 知识检索 ---
        # 无论 verbose 是否开启，我们先查知识库
        try:
            retrieved_knowledge = self.rag.search_similar_cases(alert_context, k=2)
            
            # [调试反馈] 如果检索到了内容，且不是“未找到”，在控制台闪一下，让你知道 RAG 在工作
            if "未找到相似历史案例" not in retrieved_knowledge:
                print(f"📚 [RAG 命中] Agent 已检索到关于 {alert_context.get('prefix')} 的相似历史案例！")
                
        except Exception as e:
            retrieved_knowledge = f"(RAG 检索系统暂时不可用: {e})"

        # --- Phase 2: 构建动态 Prompt ---
        dynamic_prompt = f"""
{self.base_system_prompt}

【🧠 历史知识库参考 (RAG)】
以下是系统检索到的最相似历史案例，请利用它们进行类比推理 (Case-Based Reasoning)：
{retrieved_knowledge}

【当前待分析告警】
Prefix: {alert_context.get('prefix')}
Path: {alert_context.get('as_path')}
Origin: {alert_context.get('detected_origin')}
Expected Origin: {alert_context.get('expected_origin')}
"""

        messages = [
            {"role": "system", "content": dynamic_prompt},
            {"role": "user", "content": "检测到 BGP 异常，请开始分析。"}
        ]
        
        # 初始化完整追踪记录
        full_trace = {
            "target": alert_context,
            "start_time": datetime.now().isoformat(),
            "rag_context": retrieved_knowledge, # 记录 RAG 结果以便后续审计
            "chain_of_thought": [],
            "final_result": None
        }

        # --- Phase 3: 多轮推理循环 ---
        for round_idx in range(1, 4):
            if verbose: print(f"--- Round {round_idx} ---")
            
            # 1. AI 思考
            response_json = await self._call_llm(messages)
            if not response_json: break
            
            # 初始化本轮记录
            trace_item = {
                "round": round_idx,
                "ai_thought": response_json.get("thought_process"),
                "suspicion": response_json.get("suspicion_level"),
                "tool_used": response_json.get("tool_request"),
                "tool_output": None
            }

            # ---------------- 关键修改开始 ----------------
            tool_name = response_json.get("tool_request")
            final_decision = response_json.get("final_decision")

            # 逻辑修正：只要有工具请求，就优先执行工具，无视 final_decision
            if tool_name:
                if verbose: print(f"🛠️  Calling: {tool_name}")
                
                # 执行工具
                tool_result_str = self.toolkit.call_tool(tool_name, alert_context)
                trace_item["tool_output"] = tool_result_str
                
                # 记录本轮
                full_trace["chain_of_thought"].append(trace_item)
                
                # 更新对话历史，强制进入下一轮
                messages.append({"role": "assistant", "content": json.dumps(response_json)})
                messages.append({"role": "user", "content": f"【工具反馈】\n{tool_result_str}\n\n请根据工具结果继续分析 (不要过早下结论)。"})
                
                # ⚠️ 关键：直接 continue，跳过下面的结案判断
                continue

            # 只有在【没有】请求工具的情况下，才允许结案
            if final_decision:
                full_trace["final_result"] = final_decision
                full_trace["chain_of_thought"].append(trace_item)
                if verbose: print("✅ 诊断结束 (自主结案)。")
                self._save_report_to_disk(full_trace)
                return full_trace
            # ---------------- 关键修改结束 ----------------

            # 如果既没工具也没结论（极其罕见），记录并继续
            full_trace["chain_of_thought"].append(trace_item)
            messages.append({"role": "assistant", "content": json.dumps(response_json)})
            messages.append({"role": "user", "content": "请继续分析，或者给出 final_decision。"})

        # --- Phase 4: 强制结算 (Safety Net) ---
        # 如果跑了 3 轮还没结论，强制 AI 总结
        if full_trace["final_result"] is None:
            if verbose: print("⚠️ 达到最大轮次，强制结算...")
            
            messages.append({
                "role": "user", 
                "content": "【系统指令】已达到最大分析轮次。请忽略未完成的工具调用，根据现有的 RAG 知识、RPKI 状态和地理位置证据，必须立即生成 final_decision JSON。"
            })
            
            final_resp = await self._call_llm(messages)
            
            if final_resp and final_resp.get("final_decision"):
                full_trace["final_result"] = final_resp.get("final_decision")
                full_trace["chain_of_thought"].append({
                    "round": "Final_Summary",
                    "ai_thought": final_resp.get("thought_process", "Forced Summary"),
                    "suspicion": final_resp.get("suspicion_level"),
                    "tool_used": None
                })

        # 保存并返回
        self._save_report_to_disk(full_trace)
        return full_trace

if __name__ == "__main__":
    # 简单自测
    agent = BGPAgent()
    test_data = {
        "prefix": "104.244.42.0/24", 
        "as_path": "174 12389", 
        "detected_origin": "12389",
        "expected_origin": "13414"
    }
    asyncio.run(agent.diagnose(test_data, verbose=True))