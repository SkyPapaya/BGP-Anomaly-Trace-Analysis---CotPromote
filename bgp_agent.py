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
        # 🎯 System Prompt: 溯源专家设定
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

    def _save_report(self, trace_data):
        """归档分析报告"""
        if not os.path.exists(self.report_dir):
            os.makedirs(self.report_dir, exist_ok=True)

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
        
        self._save_report(trace)
        return trace

if __name__ == "__main__":
    # --- 快速自测 ---
    # 模拟 Google 2005 真实劫持案
    test_case = {
        "prefix": "64.233.161.0/24",
        "as_path": "701 174",  # 异常路径: 701 -> 174 (Origin)
        "detected_origin": "174",
        "expected_origin": "15169" # Google
    }
    
    agent = BGPAgent()
    asyncio.run(agent.diagnose(test_case, verbose=True))