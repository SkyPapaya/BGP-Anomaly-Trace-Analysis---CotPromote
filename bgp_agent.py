import asyncio
import json
import os
import traceback
from datetime import datetime
from openai import AsyncOpenAI
from tools.bgp_toolkit import BGPToolKit
from tools.rag_manager import RAGManager

# --- 配置 ---
API_KEY = "sk-9944c48494394db6b8bc31b40f8a710f"
BASE_URL = "https://api.deepseek.com"

class BGPAgent:
    def __init__(self, report_dir="./report"):
        """
        初始化 BGP 溯源 Agent
        """
        self.client = AsyncOpenAI(api_key=API_KEY, base_url=BASE_URL)
        
        # 1. 初始化工具箱
        self.toolkit = BGPToolKit()
        
        # 2. 初始化 RAG (指向溯源专用数据库)
        # 注意: 请确保你运行了 gen_forensics_data.py 并构建了此数据库
        db_path = "./rag_db"
        
        # 为了防止目录不存在报错，加个判断，如果新库不存在则回退到默认
        if not os.path.exists(db_path):
            print(f"⚠️ [Warning] 溯源数据库 {db_path} 未找到，尝试使用默认 ./rag_db")
            db_path = "./rag_db"
            
        self.rag = RAGManager(db_path=db_path)
        self.report_dir = report_dir

        # ==========================================
        # 🎯 System Prompt: 溯源专家设定（单条）
        # ==========================================
        self.base_system_prompt = """
你是一个 BGP 安全溯源专家 (Digital Forensics Expert)。
你的核心任务是分析 BGP 路由更新，并**找出攻击者 (Attacker AS)**。

**溯源分析方法论 (Methodology):**
1. **Path Forensics (路径取证)**:
   - 检查 `AS_PATH` 属性。
   - 路径最右侧的 AS (Last Hop) 是 **Origin AS**。
   - 如果 Origin AS != Expected Owner，且无合法授权，则该 Origin AS 是**首要嫌疑人 (Primary Suspect)**。

2. **Route Leak (路由泄露)**:
   - 如果 Origin 正确，但路径违反商业关系 (例如 Tier-1 互联出现异常)，攻击者可能是路径中间的 AS。

**可用工具:**
- `path_forensics`: 专门用于解析 AS Path，提取 Origin 并自动判定嫌疑人。
- `graph_analysis`: 查询图谱，验证嫌疑人与 Owner 是否有真实连接。
- `authority_check`: 查询 RPKI 授权。

**⚠️ 严格输出格式 (JSON):**
每一次回复必须是标准 JSON，格式如下：
{
    "thought_process": "你的详细推理过程 (思维链)...",
    "tool_request": "工具名称字符串" OR null,
    "final_decision": null OR {
        "status": "MALICIOUS" | "LEAK" | "BENIGN",
        "attacker_as": "ASxxxx" (必须明确指出，如果是误判则填 'None'),
        "summary": "简短的结案陈词"
    }
}

**禁忌:**
- `tool_request` 必须是字符串，严禁返回字典/对象。
- 只有在证据确凿（已锁定 Attacker AS 或排除攻击）时，才返回 `final_decision`。
"""

        # ==========================================
        # 🎯 Batch System Prompt: 批量告警综合溯源
        # ==========================================
        self.batch_system_prompt = """
你是一个 BGP 安全溯源专家 (Digital Forensics Expert)。
你收到**一个时间窗口内的多条告警消息**，每条告警包含可疑的 BGP Update。

**重要前提：**
- 告警消息不一定 100% 准确，可能存在误报或噪声。
- 你需要**汇总所有 updates**，综合进行异常溯源分析。
- 输出**基于目前异常告警消息、最有可能是攻击者的 AS 号**，并给出置信度。

**溯源分析方法论:**
1. **Path Forensics**: 对每条 update 提取 Origin，统计哪些 AS 作为可疑 Origin 出现最频繁。
2. **交叉验证**: 若多条 update 指向同一 AS，则该 AS 嫌疑更大；若相互矛盾，需权衡证据强度。
3. **Route Leak**: 若 Origin 正确但路径异常，攻击者可能是路径中间的 Leaker。

**可用工具:**
- `path_forensics`: 对批量 updates 做路径取证，返回每条的分析 + 汇总统计。
- `graph_analysis`: 查询图谱验证嫌疑人与 Owner 的拓扑关系（可指定某条 update）。
- `authority_check`: 查询 RPKI 授权（可指定某条 update）。

**⚠️ 严格输出格式 (JSON):**
{
    "thought_process": "你的详细推理过程，需考虑多条告警的综合证据...",
    "tool_request": "工具名称字符串" OR null,
    "final_decision": null OR {
        "status": "MALICIOUS" | "LEAK" | "BENIGN" | "UNCERTAIN",
        "most_likely_attacker": "ASxxxx" (基于目前告警最可能的攻击者，若无则填 'None'),
        "confidence": "High" | "Medium" | "Low",
        "summary": "综合 X 条告警消息的分析结论，说明为何该 AS 最有可能是攻击者"
    }
}
"""

    async def _call_llm(self, messages):
        """调用 DeepSeek API (JSON 模式)"""
        try:
            response = await self.client.chat.completions.create(
                model="deepseek-chat",
                messages=messages,
                response_format={'type': 'json_object'}, # 强制 JSON
                temperature=0.0 # 零温度，确保逻辑严谨
            )
            content = response.choices[0].message.content
            return json.loads(content)
        except Exception as e:
            print(f"❌ API 调用失败: {e}")
            return {"thought_process": f"API Error: {str(e)}", "tool_request": None}

    def _save_report(self, trace_data, is_batch=False):
        """归档分析报告"""
        if not os.path.exists(self.report_dir):
            os.makedirs(self.report_dir, exist_ok=True)

        if is_batch:
            target = trace_data.get("target", {})
            updates = target.get("updates", [])
            prefix = updates[0].get("prefix", "unknown").replace("/", "_") if updates else "batch"
            timestamp = datetime.now().strftime("%H%M%S")
            filename = f"forensics_batch_{prefix}_{len(updates)}updates_{timestamp}.json"
        else:
            prefix = trace_data.get("target", {}).get("prefix", "unknown").replace("/", "_")
            timestamp = datetime.now().strftime("%H%M%S")
            filename = f"forensics_{prefix}_{timestamp}.json"
        
        try:
            with open(os.path.join(self.report_dir, filename), 'w', encoding='utf-8') as f:
                json.dump(trace_data, f, indent=4, ensure_ascii=False)
        except Exception:
            pass

    async def diagnose(self, alert_context, verbose=False):
        """
        执行诊断流程
        """
        if verbose: 
            print(f"\n🕵️‍♂️ [Agent] 开始溯源取证: {alert_context.get('prefix')} ...")

        # --- Phase 1: RAG 知识检索 ---
        try:
            # 搜索相似的溯源案例
            rag_knowledge = self.rag.search_similar_cases(alert_context, k=2)
            if verbose and "未找到" not in str(rag_knowledge):
                print(f"📚 [RAG] 已加载历史溯源档案...")
        except Exception:
            rag_knowledge = "(RAG Database Unavailable)"

        # --- Phase 2: 构造动态 Prompt ---
        dynamic_prompt = f"""
{self.base_system_prompt}

【📂 历史溯源档案 (RAG Reference)】
{rag_knowledge}

【RAG 使用约束】
- RAG 案例仅作为辅助参考，不能直接当作当前事件事实。
- 若 RAG 与工具输出（path_forensics / authority_check / graph_analysis）冲突，必须以工具证据为准。

【🚨 当前案情证据 (Evidence)】
- Target Prefix: {alert_context.get('prefix')}
- Suspicious AS_PATH: {alert_context.get('as_path')}
- Detected Origin: {alert_context.get('detected_origin')}
- Legitimate Owner: {alert_context.get('expected_origin')}
"""
        messages = [
            {"role": "system", "content": dynamic_prompt},
            {"role": "user", "content": "请分析上述证据，使用工具拆解路径，并锁定攻击者 (Attacker AS)。"}
        ]
        
        trace = {
            "target": alert_context,
            "start_time": datetime.now().isoformat(),
            "rag_context": rag_knowledge,
            "chain_of_thought": [],
            "final_result": None
        }

        # --- Phase 3: 推理循环 (Max 3 Rounds) ---
        for round_idx in range(1, 4):
            if verbose: print(f"--- Round {round_idx} ---")
            
            # 1. AI 思考
            resp_json = await self._call_llm(messages)
            if not resp_json: break
            
            # 2. 解析输出
            tool_req = resp_json.get("tool_request")
            final_decision = resp_json.get("final_decision")

            # === 🛡️ 鲁棒性防御: 清洗工具名 ===
            if tool_req:
                if isinstance(tool_req, dict):
                    # 如果 AI 还是返回了字典，提取第一个值
                    tool_req = list(tool_req.values())[0]
                tool_req = str(tool_req).strip()
                if tool_req.lower() == "none": tool_req = None
            # ==============================

            step_record = {
                "round": round_idx,
                "thought": resp_json.get("thought_process"),
                "ai_full_response": resp_json,
                "tool_used": tool_req,
                "tool_output": None
            }

            # 3. 分支处理
            # 优先执行工具
            if tool_req:
                if verbose: print(f"🛠️  Agent 调用工具: {tool_req}")
                
                tool_output = self.toolkit.call_tool(tool_req, alert_context)
                step_record["tool_output"] = tool_output
                trace["chain_of_thought"].append(step_record)
                
                # 将工具结果喂回给 AI
                messages.append({"role": "assistant", "content": json.dumps(resp_json)})
                messages.append({"role": "user", "content": f"【工具结果】\n{tool_output}\n\n请根据结果判断：能否锁定 Attacker AS？如果能，请输出 final_decision。"})
                continue
            
            # 如果没有工具，检查是否结案
            if final_decision:
                trace["final_result"] = final_decision
                trace["chain_of_thought"].append(step_record)
                if verbose: 
                    attacker = final_decision.get('attacker_as', 'Unknown')
                    print(f"✅ 结案! 锁定攻击者: {attacker}")
                
                self._save_report(trace)
                return trace

            # 既没工具也没结论 (罕见情况)
            trace["chain_of_thought"].append(step_record)
            messages.append({"role": "assistant", "content": json.dumps(resp_json)})
            messages.append({"role": "user", "content": "请继续分析。"})

        # --- Phase 4: 强制结算 ---
        if trace["final_result"] is None:
            if verbose: print("⚠️ 强制结案...")
            messages.append({"role": "user", "content": "分析结束。请忽略未完成步骤，立即输出 JSON，必须包含 'attacker_as'。"})
            final_resp = await self._call_llm(messages)
            if final_resp and final_resp.get("final_decision"):
                trace["final_result"] = final_resp.get("final_decision")
                trace["chain_of_thought"].append({
                    "round": "force",
                    "thought": final_resp.get("thought_process"),
                    "ai_full_response": final_resp,
                    "tool_used": None,
                    "tool_output": None,
                })

        self._save_report(trace)
        return trace

    async def diagnose_batch(self, alert_batch, verbose=False):
        """
        批量告警综合溯源：汇总时间窗口内多条 updates，综合分析，输出最有可能是攻击者的 AS。

        输入格式:
        {
            "time_window": {"start": "...", "end": "..."},  # 可选
            "updates": [
                {"prefix": "8.8.8.0/24", "as_path": "701 174", "detected_origin": "174", "expected_origin": "15169"},
                {"prefix": "8.8.8.0/24", "as_path": "701 4761", "detected_origin": "4761", "expected_origin": "15169"},
                ...
            ]
        }
        """
        updates = alert_batch.get("updates", [])
        if not updates:
            return {"error": "updates 不能为空", "final_result": None}

        if verbose:
            print(f"\n🕵️‍♂️ [Agent] 批量溯源: 共 {len(updates)} 条告警 updates ...")

        # --- Phase 1: RAG 知识检索（汇总所有 updates 分别查询，合并去重取 top-k）---
        try:
            rag_knowledge = self.rag.search_similar_cases_batch(updates, k=2)
            if verbose and "未找到" not in str(rag_knowledge):
                print(f"📚 [RAG] 已加载历史溯源档案（汇总 {len(updates)} 条 updates 检索）...")
        except Exception:
            rag_knowledge = "(RAG Database Unavailable)"

        # --- Phase 2: 构造批量 Prompt ---
        time_info = alert_batch.get("time_window", {})
        tw_str = f"时间窗口: {time_info.get('start', 'N/A')} ~ {time_info.get('end', 'N/A')}\n" if time_info else ""

        updates_text = "\n".join([
            f"  [{i+1}] prefix={u.get('prefix')} | as_path={u.get('as_path')} | "
            f"detected_origin={u.get('detected_origin')} | expected_origin={u.get('expected_origin')}"
            for i, u in enumerate(updates)
        ])

        dynamic_prompt = f"""
{self.batch_system_prompt}

【📂 历史溯源档案 (RAG Reference)】
{rag_knowledge}

【RAG 使用约束】
- RAG 案例仅作为辅助参考，不能直接当作当前事件事实。
- 若 RAG 与工具输出（path_forensics / authority_check / graph_analysis）冲突，必须以工具证据为准。

【🚨 批量告警证据 (Batch Evidence)】
{tw_str}
共 {len(updates)} 条可疑 Update 消息:
{updates_text}

请汇总以上所有 updates，综合判断：**基于目前异常告警消息，最有可能是攻击者的 AS 号**。
"""
        messages = [
            {"role": "system", "content": dynamic_prompt},
            {"role": "user", "content": "请分析上述批量告警，使用 path_forensics 等工具综合溯源，输出 most_likely_attacker 及 confidence。"}
        ]

        trace = {
            "target": alert_batch,
            "start_time": datetime.now().isoformat(),
            "rag_context": rag_knowledge,
            "chain_of_thought": [],
            "final_result": None
        }

        # --- Phase 3: 推理循环 ---
        for round_idx in range(1, 4):
            if verbose:
                print(f"--- Round {round_idx} ---")

            resp_json = await self._call_llm(messages)
            if not resp_json:
                break

            tool_req = resp_json.get("tool_request")
            final_decision = resp_json.get("final_decision")

            if tool_req:
                if isinstance(tool_req, dict):
                    tool_req = list(tool_req.values())[0]
                tool_req = str(tool_req).strip()
                if tool_req.lower() == "none":
                    tool_req = None

            step_record = {
                "round": round_idx,
                "thought": resp_json.get("thought_process"),
                "ai_full_response": resp_json,
                "tool_used": tool_req,
                "tool_output": None
            }

            if tool_req:
                if verbose:
                    print(f"🛠️  Agent 调用工具: {tool_req}")
                tool_output = self.toolkit.call_tool(tool_req, alert_batch, is_batch=True)
                step_record["tool_output"] = tool_output
                trace["chain_of_thought"].append(step_record)

                messages.append({"role": "assistant", "content": json.dumps(resp_json)})
                messages.append({"role": "user", "content": f"【工具结果】\n{tool_output}\n\n请综合以上结果判断：最有可能是攻击者的 AS？若能确定，请输出 final_decision（含 most_likely_attacker 与 confidence）。"})
                continue

            if final_decision:
                trace["final_result"] = final_decision
                trace["chain_of_thought"].append(step_record)
                if verbose:
                    attacker = final_decision.get("most_likely_attacker", final_decision.get("attacker_as", "Unknown"))
                    conf = final_decision.get("confidence", "")
                    print(f"✅ 结案! 最可能攻击者: {attacker} (置信度: {conf})")
                self._save_report(trace, is_batch=True)
                return trace

            trace["chain_of_thought"].append(step_record)
            messages.append({"role": "assistant", "content": json.dumps(resp_json)})
            messages.append({"role": "user", "content": "请继续分析。"})

        # --- Phase 4: 强制结算 ---
        if trace["final_result"] is None:
            if verbose:
                print("⚠️ 强制结案...")
            messages.append({"role": "user", "content": "分析结束。请立即输出 JSON，必须包含 most_likely_attacker 和 confidence。"})
            final_resp = await self._call_llm(messages)
            if final_resp and final_resp.get("final_decision"):
                trace["final_result"] = final_resp.get("final_decision")
                trace["chain_of_thought"].append({
                    "round": "force",
                    "thought": final_resp.get("thought_process"),
                    "ai_full_response": final_resp,
                    "tool_used": None,
                    "tool_output": None,
                })

        self._save_report(trace, is_batch=True)
        return trace

if __name__ == "__main__":
    import sys
    agent = BGPAgent()

    # 批量模式：多条告警综合溯源
    if len(sys.argv) > 1 and sys.argv[1] == "batch":
        batch_case = {
            "time_window": {"start": "2024-01-15T10:00:00", "end": "2024-01-15T10:30:00"},
            "updates": [
                {"prefix": "8.8.8.0/24", "as_path": "701 174", "detected_origin": "174", "expected_origin": "15169"},
                {"prefix": "8.8.8.0/24", "as_path": "701 174", "detected_origin": "174", "expected_origin": "15169"},
                {"prefix": "8.8.8.0/24", "as_path": "3356 4761", "detected_origin": "4761", "expected_origin": "15169"},
            ]
        }
        asyncio.run(agent.diagnose_batch(batch_case, verbose=True))
    else:
        # 单条模式：模拟 Google 2005 真实劫持案
        test_case = {
            "prefix": "64.233.161.0/24",
            "as_path": "701 174",
            "detected_origin": "174",
            "expected_origin": "15169"
        }
        asyncio.run(agent.diagnose(test_case, verbose=True))
