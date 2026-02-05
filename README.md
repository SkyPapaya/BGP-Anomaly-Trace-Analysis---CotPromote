# 基于思维链的 BGP 异常溯源分析 (CotPromote)

结合大语言模型的思维链（Chain-of-Thought, CoT）推理能力，构建一种基于层次化思考的 BGP 异常溯源分析方法。通过「观测—关联—推理—归因」的思维链，实现对前缀劫持、路由泄露等复杂网络异常的精准定位与可解释溯源。

---

## 一、设计思路

### 1. 思维链框架：观测 → 关联 → 推理 → 归因

| 环节 | 实现模块 | 功能说明 |
|------|----------|----------|
| **观测** | `data_provider`、告警上下文 | 路由事件观测与数据采集（RIPEstat API） |
| **关联** | `graph_rag`、`topology`、`geo`、`neighbor` | 拓扑与多源数据关联分析 |
| **推理** | `bgp_agent` + RAG + LLM | 思维链式结构化推理 |
| **归因** | `path_forensics`、`authority_check`、`final_decision` | 精确定位攻击者 AS |

### 2. 核心流程

1. **RAG 知识注入**：分析开始前，从向量库检索相似历史案例（`rag_db`），注入到 System Prompt，为 AI 提供先验知识支撑。
2. **三轮思考与工具调用**：每轮思考允许 AI 调用工具（`path_forensics`、`graph_analysis`、`authority_check` 等），最多 3 轮；每轮可请求工具，根据工具结果继续推理，直至输出 `final_decision`。
3. **单条溯源**：输入单条告警，输出 `attacker_as` 与 `status`。
4. **批量溯源**：输入时间窗口内多条告警，汇总分析后输出 `most_likely_attacker` 与 `confidence`。

### 3. 知识库与联网

- **知识库**：`config/knowledge_base.json` 存放实体、Tier-1 AS、风险 AS、已知前缀归属等，代码通过 `config_loader` 读取。
- **联网获取**：RPKI、AS 信息、地理位置等优先通过 RIPEstat API 获取最新状态；API 失败时使用知识库兜底。

---

## 二、项目结构

```
.
├── bgp_agent.py              # 核心 Agent：单条/批量溯源
├── build_vector_db.py        # 构建 RAG 向量库
├── performance_test.py       # 溯源能力评估
├── collect.py                # 项目上下文收集（辅助）
├── config/
│   └── knowledge_base.json   # 知识库配置（实体、Tier-1、风险 AS 等）
├── data/                     # 溯源案例、测试用例（需生成）
├── report/                   # 溯源报告输出
├── auto_generator/
│   └── auto_generator.py     # 多类型攻击案例生成（Direct/PathForgery/RouteLeak）
└── tools/
    ├── bgp_toolkit.py        # 工具集：path_forensics、graph_analysis、authority_check 等
    ├── rag_manager.py        # ChromaDB RAG 检索
    ├── config_loader.py      # 知识库加载
    ├── data_provider.py      # RIPEstat API 接口
    ├── authority.py          # RPKI 校验
    ├── topology.py           # Valley-Free 检测
    ├── geo.py                # 地理位置冲突检测
    ├── neighbor.py           # 邻居传播分析
    ├── graph_rag.py          # Neo4j 拓扑图谱
    ├── import_real_word.py   # CAIDA 拓扑数据导入 Neo4j
    ├── gen_forensics_data.py # 溯源案例生成（简化版）
    ├── stability.py
    └── ...
```

---

## 三、环境与依赖

```bash
pip install openai chromadb sentence-transformers neo4j requests aiofiles tqdm tabulate mrtparse
```

> **tqdm**: 用于 Step1 与性能测试的进度条展示

- **LLM**：DeepSeek API（在 `bgp_agent.py`、`gen_forensics_data.py`、`auto_generator.py` 中配置 API_KEY）
- **RAG**：ChromaDB + SentenceTransformer
- **拓扑**（可选）：Neo4j + CAIDA 数据

---

## 四、使用方法

### 1. 配置知识库（可选）

编辑 `config/knowledge_base.json`，可修改：
- `entities`：victims、attackers、transit（数据生成用）
- `known_prefix_origin`：已知前缀归属
- `tier1_asns`：Tier-1 AS 列表
- `risk_asns`：历史风险 AS

### 2. 生成溯源案例并构建 RAG 库

```bash
# 方式 A：auto_generator（推荐，支持 Direct Hijack / Path Forgery / Route Leak）
python auto_generator/auto_generator.py
# 输出: data/full_attack_cases.jsonl

# 方式 B：gen_forensics_data（简化版）
python tools/gen_forensics_data.py
# 输出: data/forensics_cases.jsonl

# 构建 RAG 向量库
python build_vector_db.py
# 输入: data/full_attack_cases.jsonl（可在 build_vector_db.py 中修改路径）
# 输出: ./rag_db
```

### 3. 运行溯源 Agent

```bash
# 单条模式（默认）
python bgp_agent.py

# 批量模式：多条告警综合溯源
python bgp_agent.py batch
```

### 4. 代码调用示例

**单条溯源：**
```python
from bgp_agent import BGPAgent
import asyncio

agent = BGPAgent()
alert = {
    "prefix": "8.8.8.0/24",
    "as_path": "701 174",
    "detected_origin": "174",
    "expected_origin": "15169"
}
trace = asyncio.run(agent.diagnose(alert, verbose=True))
# trace["final_result"] = {"status": "MALICIOUS", "attacker_as": "174", "summary": "..."}
```

**批量溯源：**
```python
batch = {
    "time_window": {"start": "2024-01-15T10:00:00", "end": "2024-01-15T10:30:00"},
    "updates": [
        {"prefix": "8.8.8.0/24", "as_path": "701 174", "detected_origin": "174", "expected_origin": "15169"},
        {"prefix": "8.8.8.0/24", "as_path": "3356 4761", "detected_origin": "4761", "expected_origin": "15169"},
    ]
}
trace = asyncio.run(agent.diagnose_batch(batch, verbose=True))
# trace["final_result"] = {"most_likely_attacker": "174", "confidence": "High", "summary": "..."}
```

### 5. 性能评估（两步式验证）

**Step1：收集真实事件并过滤可疑 updates**

1. 在 **`data/test_events.json`** 中手动配置待测案例（格式见 `data/README_test_events.md`）
2. 下载目标前缀在时间窗口内的原始 BGP updates（默认 RIPE RIS MRT，支持历史数据；可选 RIPEstat BGPlay）
3. 按论文四步法筛选可疑 updates：前缀过滤、Origin 校验（MOAS）、Valley-Free 违规
4. 按事件存储到 `data/events/<event_id>/`

```bash
# 默认使用 RIPE RIS MRT（支持历史数据，如 2005/2008/2014 等）
python scripts/step1_collect_events.py --input data/test_events.json --source ris_mrt

# 或 RIPEstat BGPlay（仅 2024-01+）
python scripts/step1_collect_events.py --input data/test_events.json --source ripestat

# auto: 优先 RIS，失败则 BGPlay
python scripts/step1_collect_events.py --input data/test_events.json --source auto
```

**Step2：用系统分析并验证命中率**

```bash
python performance_test.py --events
```

对比系统判定的攻击者 AS 与 BGP Watch 给出的可疑 AS，计算准确率。

**其他数据源：**

- 本地 `test_cases.json`：`python performance_test.py`
- BGP Watch 在线（无原始 updates）：`python performance_test.py --bgpwatch`

### 6. 拓扑分析（可选）

- 安装并启动 Neo4j
- 运行 `python tools/import_real_word.py` 导入 CAIDA 拓扑数据
- 在 `tools/graph_rag.py`、`tools/bgp_toolkit.py` 中配置 Neo4j 连接信息

---

## 五、工具说明

| 工具 | 功能 | 数据来源 |
|------|------|----------|
| `path_forensics` | 解析 AS_PATH，提取 Origin，判定嫌疑人 | 本地解析 |
| `graph_analysis` | 查询 Origin 与 Owner 拓扑关系 | Neo4j（或离线提示） |
| `authority_check` | RPKI 授权校验 | RIPEstat API + 知识库兜底 |
| `geo_check` | 地理冲突检测 | RIPEstat MaxMind/Whois |
| `neighbor_check` | 传播源与风险 AS 分析 | RIPEstat + 知识库 |
| `topology_check` | Valley-Free 违规检测 | RIPEstat + 知识库 Tier-1 |

---

## 六、输出报告

溯源报告保存在 `report/` 目录：
- 单条：`forensics_{prefix}_{timestamp}.json`
- 批量：`forensics_batch_{prefix}_{N}updates_{timestamp}.json`

报告字段说明：
- `rag_context`：RAG 检索到的历史案例
- `chain_of_thought`：每轮完整记录，含 `round`、`thought`、`ai_full_response`（AI 当轮完整 JSON 回复）、`tool_used`、`tool_output`
- `final_result`：结案结论
