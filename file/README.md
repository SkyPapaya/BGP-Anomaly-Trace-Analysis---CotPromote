# 基于思维链的 BGP 异常溯源分析 (CotPromote)

结合大语言模型的思维链（Chain-of-Thought, CoT）推理能力，构建一种基于层次化思考的 BGP 异常溯源分析方法。通过「观测—关联—推理—归因」的思维链，实现对前缀劫持、路由泄露等复杂网络异常的精准定位与可解释溯源。

---

## 一、整体数据流（从告警输入到报告输出）

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                              完整使用流程                                                 │
└─────────────────────────────────────────────────────────────────────────────────────────┘

  [输入] 告警事件配置                    [预处理] 获取源数据                     [分析] Agent 溯源                   [输出] 报告

  data/test_events.json      →    Step1: step1_collect_events.py    →    performance_test.py     →    report/*.json
  ├─ prefix                         ├─ fetch_and_filter()                    ├─ load_local_events()
  ├─ victim                         │   ├─ RIS MRT / BGPlay 下载             ├─ BGPAgent.diagnose_batch()
  ├─ attacker                       │   └─ 四步法筛选可疑 updates             └─ 比对真值计算准确率
  ├─ start_time                     │
  └─ end_time                       └─ 输出 data/events/<event_id>/
                                           ├─ meta.json
                                           ├─ suspicious_updates.json
                                           └─ raw_bgplay.json

  [RAG 知识库] 需预先构建
  auto_generator.py → full_attack_cases.jsonl → build_vector_db.py → rag_db/
```

---

## 二、使用流程概览

### 流程 A：完整验证流程（推荐，含真实 BGP 数据）

| 阶段 | 命令 | 说明 |
|------|------|------|
| **0. 预构建 RAG** | `python auto_generator/auto_generator.py` | 生成溯源案例 JSONL |
| | `python build_vector_db.py` | 构建向量库 `./rag_db` |
| **1. 输入告警** | 编辑 `data/test_events.json` | 配置 prefix、victim、attacker、时间窗口 |
| **2. 抓取并筛选** | `python scripts/step1_collect_events.py` | 下载 BGP updates，四步法过滤 |
| **3. 溯源评估** | `python performance_test.py --events` | Agent 分析 + 准确率评估 |

### 流程 B：快速单条/批量溯源（无真实抓取）

| 阶段 | 命令 | 说明 |
|------|------|------|
| **0. 预构建 RAG** | 同流程 A | 同上 |
| **1. 直接运行** | `python bgp_agent.py` 或 `python bgp_agent.py batch` | 使用内置示例告警 |

---

## 三、关键步骤与代码说明

### Step 0：RAG 知识库构建

| 文件 | 关键函数/逻辑 | 说明 |
|------|---------------|------|
| `auto_generator/auto_generator.py` | `AttackDataGenerator.generate_case()` | LLM 生成 Direct Hijack / Path Forgery / Route Leak 三类案例，输出含 `scenario_desc`、`analysis_logic`、`conclusion` |
| `build_vector_db.py` | `rag.load_knowledge_base(json_path)` | 入口：读取 JSONL → 调用 RAG 加载 |
| `tools/rag_manager.py` | `load_knowledge_base()` | 每条案例取 `scenario_desc` 作为文档，`model.encode(documents)` 生成向量，写入 ChromaDB |
| | `search_similar_cases()` | 单条：将 `{prefix, as_path, detected_origin}` 转为查询文本，检索 top-k |
| | `search_similar_cases_batch()` | 批量：汇总所有 updates 分别查询，合并去重后取 top-k（见下方 RAG 检索策略） |

**输入**：`data/full_attack_cases.jsonl`（或 `data/forensics_cases.jsonl`）  
**输出**：`./rag_db`（ChromaDB 持久化）

---

### Step 1：输入告警事件

**输入文件**：`data/test_events.json`（格式见 `data/README_test_events.md`）

```json
[
  {
    "prefix": "8.8.8.0/24",
    "victim": "15169",
    "attacker": "4761",
    "start_time": "2014-04-01T08:00:00",
    "end_time": "2014-04-01T18:00:00",
    "source": "anomaly"
  }
]
```

| 字段 | 必填 | 说明 |
|------|------|------|
| prefix | ✓ | 目标前缀 |
| victim | ✓ | 合法持有者 AS（Expected Owner） |
| attacker | ✓ | 真值攻击者 AS（用于 Step2 比对） |
| start_time / end_time | ✓ | 时间窗口 ISO8601 |

---

### Step 2：抓取源数据并筛选可疑 updates

| 文件 | 关键函数/逻辑 | 说明 |
|------|---------------|------|
| `scripts/step1_collect_events.py` | `main()` | 入口：遍历 `test_events.json`，对每个事件调用 `fetch_and_filter()` |
| | `load_local_events(path)` | 加载待测事件列表 |
| | `fetch_and_filter()` | **核心**：下载 + 四步法筛选 |
| `tools/update_fetcher.py` | `fetch_and_filter(prefix, expected_origin, start_time, end_time, source)` | 根据 `source` 选择数据源：`ris_mrt` / `ripestat` / `auto` |
| | `_try_ris()` | 调用 RIS MRT 抓取 |
| | `_try_ripestat()` | 调用 BGPlay API |
| `tools/ris_mrt_fetcher.py` | `fetch_and_parse()` | 生成 MRT URL（`https://data.ris.ripe.net/rrc00/YYYY.MM/updates.YYYYMMDD.HHmm.gz`），下载并解析 |
| | `_parse_mrt_file()` | 用 `mrtparse` 解析 MRT，按 prefix 过滤 |
| | `filter_suspicious_from_ris()` | 对 RIS 解析结果应用四步法 |
| `tools/update_fetcher.py` | `filter_suspicious_updates()` | 对 BGPlay 数据应用四步法 |

**四步法筛选逻辑**（论文方法论）：
1. 前缀过滤：仅保留目标 prefix 的 updates（数据源已按 prefix 查询，天然满足）
2. Origin 校验：`Detected Origin != Expected Owner` → ORIGIN_MISMATCH
3. 时间相关：限定在时间窗口内
4. Valley-Free：路径中出现 Tier1→非Tier1→Tier1 → VALLEY_FREE_VIOLATION

**输出目录结构**：`data/events/<event_id>/`

```
<event_id>/
├── meta.json              # 事件元数据（prefix, victim, attacker, data_source 等）
├── suspicious_updates.json # 筛选后的可疑 updates
└── raw_bgplay.json        # 原始 BGPlay/RIS 数据（备用）
```

---

### Step 3：Agent 溯源与性能评估

| 文件 | 关键函数/逻辑 | 说明 |
|------|---------------|------|
| `performance_test.py` | `load_local_events(events_dir)` | 从 `data/events/` 读取 meta + suspicious_updates，组装为 `context` |
| | `run_benchmark()` | 遍历事件，调用 `agent.diagnose_batch(context)` |
| `bgp_agent.py` | `BGPAgent.__init__()` | 初始化 toolkit、RAG、System Prompt |
| | `diagnose_batch(alert_batch)` | **批量溯源主流程** |
| | Phase 1 | 单条用 `search_similar_cases()`；批量用 `search_similar_cases_batch()` 汇总检索 |
| | Phase 2 | 构造 System + User 消息 |
| | Phase 3 | 最多 3 轮：`_call_llm()` → 解析 `tool_request` → `toolkit.call_tool()` → 将工具结果喂回 LLM |
| | Phase 4 | 若未结案则强制要求输出 `final_decision` |
| | `_save_report(trace)` | 写入 `report/forensics_batch_*.json` |

**报告格式**（`report/forensics_batch_{prefix}_{N}updates_{timestamp}.json`）：

```json
{
  "target": { "time_window": {...}, "updates": [...] },
  "rag_context": "检索到的历史案例文本",
  "chain_of_thought": [
    {
      "round": 1,
      "thought": "思维链摘要",
      "ai_full_response": { "thought_process": "...", "tool_request": "path_forensics", "final_decision": null },
      "tool_used": "path_forensics",
      "tool_output": "工具返回内容"
    }
  ],
  "final_result": {
    "status": "MALICIOUS",
    "most_likely_attacker": "4761",
    "confidence": "High",
    "summary": "..."
  }
}
```

---

## 四、项目结构

```
.
├── bgp_agent.py              # 核心 Agent：单条/批量溯源，三轮思考 + 工具调用
├── build_vector_db.py        # RAG 向量库构建入口
├── performance_test.py       # 溯源能力评估（Step2）
├── config/
│   └── knowledge_base.json   # 实体、Tier-1 AS、已知前缀归属等
├── data/
│   ├── test_events.json      # 【输入】待测事件配置
│   ├── full_attack_cases.jsonl # RAG 知识库源（auto_generator 生成）
│   ├── events/               # 【Step1 输出】按事件存储
│   │   └── <event_id>/
│   │       ├── meta.json
│   │       ├── suspicious_updates.json
│   │       └── raw_bgplay.json
│   └── README_test_events.md # test_events.json 格式说明
├── report/                   # 【最终输出】溯源报告
├── scripts/
│   └── step1_collect_events.py # Step1：抓取并筛选
├── auto_generator/
│   └── auto_generator.py     # 多类型攻击案例生成
└── tools/
    ├── update_fetcher.py     # 统一入口：RIS/BGPlay 抓取 + 四步法筛选
    ├── ris_mrt_fetcher.py    # RIPE RIS MRT 下载与解析
    ├── rag_manager.py        # ChromaDB RAG 检索（单条 search_similar_cases / 批量 search_similar_cases_batch）
    ├── bgp_toolkit.py        # path_forensics、graph_analysis、authority_check 等
    ├── config_loader.py      # 知识库加载
    ├── data_provider.py      # RIPEstat API
    ├── authority.py          # RPKI 校验
    ├── topology.py           # Valley-Free 检测
    └── ...
```

---

## 五、环境与依赖

```bash
pip install openai chromadb sentence-transformers neo4j requests aiofiles tqdm tabulate mrtparse
```

- **LLM**：DeepSeek API（在 `bgp_agent.py`、`auto_generator.py` 等中配置 API_KEY）
- **RAG**：ChromaDB + SentenceTransformer(`all-MiniLM-L6-v2`)
- **tqdm**：Step1 与 performance_test 进度条
- **mrtparse**：解析 RIPE RIS MRT 文件

---

## 六、命令速查

```bash
# Step 0：构建 RAG
python auto_generator/auto_generator.py
python build_vector_db.py

# Step 1：输入 data/test_events.json 后，抓取并筛选
python scripts/step1_collect_events.py --input data/test_events.json --source ris_mrt
# --source: ris_mrt(默认) | ripestat | auto

# Step 2：溯源评估
python performance_test.py --events
# 其他: python performance_test.py (test_cases) | python performance_test.py --bgpwatch

# 直接单条/批量溯源（无 Step1）
python bgp_agent.py
python bgp_agent.py batch
```

---

## 七、设计要点

### RAG 检索策略（单条 vs 批量）

多条可疑 updates 中可能包含噪声或误报，使用多条正是为了降低误判概率。因此**批量模式采用汇总检索**，而非只用第一条。

| 模式 | 方法 | 检索策略 |
|------|------|----------|
| **单条** | `search_similar_cases(alert_context, k=2)` | 用该条告警的 `{prefix, as_path, detected_origin}` 构造查询，检索 top-2 相似案例 |
| **批量** | `search_similar_cases_batch(updates, k=2)` | **汇总检索**：对每条 update 分别查询 → 合并去重 → 按相关性排序 → 取 top-2 |

**批量汇总检索的具体做法**（`tools/rag_manager.py` 中 `search_similar_cases_batch`）：

1. **逐条查询**：对 `updates` 中的每条 update，用其 `{prefix, as_path, detected_origin}` 构造查询文本，向向量库检索若干候选案例（每条约取 `per_k` 个）。
2. **合并去重**：将各次检索结果按 doc_id 合并；若同一案例被多条 update 命中，保留**距离更小**（更相似）的那次。
3. **排序取 top-k**：按距离升序排列，取前 k 个（默认 k=2）作为最终 RAG 参考案例。

这样每条 update 都能贡献相关信息，若某条为噪声，其他条仍可召回相关案例，提高批量溯源的稳健性和精度。

---

### 思维链与三轮思考

- **RAG 注入**：分析前从 `rag_db` 检索相似案例，注入 System Prompt
- **三轮推理**：每轮可调用工具（path_forensics、graph_analysis、authority_check），根据工具结果继续推理，直至输出 `final_decision`
- **报告记录**：`chain_of_thought` 保存每轮 `thought`、`ai_full_response`、`tool_used`、`tool_output`

### 数据源选择

| source | 说明 | 时间范围 |
|--------|------|----------|
| ris_mrt | RIPE RIS MRT，`https://data.ris.ripe.net/...` | 支持历史（如 2005/2008/2014） |
| ripestat | RIPEstat BGPlay API | 仅 2024-01+ |
| auto | 优先 RIS，失败则 BGPlay | 同上 |

### Agent 可用工具（`tools/bgp_toolkit.py`）

| 工具 | 功能 | 数据来源 |
|------|------|----------|
| `path_forensics` | 解析 AS_PATH，提取 Origin，判定嫌疑人 | 本地解析 |
| `graph_analysis` | 查询 Origin 与 Owner 拓扑关系 | Neo4j（或离线提示） |
| `authority_check` | RPKI 授权校验 | RIPEstat API + 知识库兜底 |
| `geo_check` | 地理冲突检测 | RIPEstat MaxMind/Whois |
| `topology_check` | Valley-Free 违规检测 | RIPEstat + 知识库 Tier-1 |

### 代码调用示例

```python
from bgp_agent import BGPAgent
import asyncio

agent = BGPAgent()

# 单条溯源
alert = {"prefix": "8.8.8.0/24", "as_path": "701 174", "detected_origin": "174", "expected_origin": "15169"}
trace = asyncio.run(agent.diagnose(alert, verbose=True))

# 批量溯源
batch = {"time_window": {"start": "2024-01-15T10:00:00", "end": "2024-01-15T10:30:00"}, "updates": [...]}
trace = asyncio.run(agent.diagnose_batch(batch, verbose=True))
```
