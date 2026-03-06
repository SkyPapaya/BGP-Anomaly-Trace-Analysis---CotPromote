import chromadb
import os
import json
import logging
import math
import re
from sentence_transformers import SentenceTransformer

# 设置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("RAGManager")


class RAGManager:
    def __init__(self, db_path="./rag_db", collection_name="bgp_cases"):
        """
        初始化 Vector RAG 引擎
        :param db_path: 向量数据库持久化路径
        """
        self.client = chromadb.PersistentClient(path=db_path)
        self.collection = self.client.get_or_create_collection(name=collection_name)
        # 使用轻量级嵌入模型 (本地运行)
        self.model = SentenceTransformer("all-MiniLM-L6-v2")

        # 检索参数：先粗召回，再重排，最后动态返回 top-k
        self.recall_k = 15
        self.reject_distance = 0.75
        print(f"INFO:RAGManager:RAG 引擎就绪 | 数据库路径: {db_path}")

    def load_knowledge_base(self, json_path):
        """
        从 JSON/JSONL 文件加载知识库 (自动去重 + 兼容性修复)
        """
        if not os.path.exists(json_path):
            logger.error(f"文件未找到: {json_path}")
            return

        cases = []
        # 1. 读取数据 (兼容 JSON 和 JSONL)
        try:
            if json_path.endswith(".jsonl"):
                with open(json_path, "r", encoding="utf-8") as f:
                    for line in f:
                        if line.strip():
                            cases.append(json.loads(line))
            else:
                with open(json_path, "r", encoding="utf-8") as f:
                    cases = json.load(f)
        except Exception as e:
            logger.error(f"读取文件失败: {e}")
            return

        logger.info(f"正在导入 {len(cases)} 条数据...")

        ids = []
        documents = []
        metadatas = []
        seen_ids = set()

        for case in cases:
            # --- ID 处理 (防止重复) ---
            curr_id = case.get("id", f"auto_{len(ids)}")
            original_id = curr_id
            retry_count = 0
            while curr_id in seen_ids:
                retry_count += 1
                curr_id = f"{original_id}_{retry_count}"
            seen_ids.add(curr_id)

            # --- 文本内容 (Document) ---
            # 优先使用场景描述作为向量化的主体
            doc_text = case.get("scenario_desc", str(case))

            # 1. 兼容 analysis 字段名 (旧数据用 analysis, 新数据用 analysis_logic)
            analysis_text = case.get("analysis") or case.get("analysis_logic") or "N/A"

            # 2. 处理 conclusion (可能是字符串，也可能是字典)
            conclusion_val = case.get("conclusion", "N/A")
            if isinstance(conclusion_val, dict):
                # 如果是字典，转成 JSON 字符串存入 metadata (ChromaDB 不支持嵌套字典)
                conclusion_str = json.dumps(conclusion_val, ensure_ascii=False)
            else:
                conclusion_str = str(conclusion_val)

            evidence = case.get("evidence") or case.get("context") or {}
            prefix = str(evidence.get("prefix", "")).strip()
            as_path = str(evidence.get("as_path", "")).strip()
            detected_origin = self._normalize_asn(evidence.get("detected_origin"))
            expected_origin = self._normalize_asn(evidence.get("expected_origin"))
            prefix_len = self._prefix_len(prefix)
            path_len = len(self._parse_path(as_path))
            origin_mismatch = (
                "1"
                if detected_origin
                and expected_origin
                and detected_origin != expected_origin
                else "0"
            )

            meta = {
                "type": case.get("type", "Unknown"),
                "attack_family": self._map_case_type(case.get("type", "Unknown")),
                "analysis": str(analysis_text),  # 确保是字符串
                "conclusion": conclusion_str,  # 确保是字符串
                "prefix_len": prefix_len,
                "path_len_bucket": self._bucket_path_len(path_len),
                "origin_mismatch": origin_mismatch,
                "full_json": json.dumps(case, ensure_ascii=False),  # 存完整副本
            }

            ids.append(curr_id)
            documents.append(doc_text)
            metadatas.append(meta)

        # 3. 批量写入 ChromaDB 并生成向量
        if ids:
            try:
                embeddings = self.model.encode(documents).tolist()
                self.collection.upsert(
                    ids=ids,
                    documents=documents,
                    embeddings=embeddings,
                    metadatas=metadatas,
                )
                logger.info(f"✅ 知识库导入完成！(共 {len(ids)} 条)")
            except Exception as e:
                logger.error(f"写入数据库失败: {e}")

    @staticmethod
    def _normalize_asn(asn):
        if asn is None:
            return ""
        s = str(asn).strip().upper()
        if s.startswith("AS"):
            s = s[2:]
        digits = "".join(ch for ch in s if ch.isdigit())
        return digits

    @staticmethod
    def _parse_path(as_path):
        if not as_path:
            return []
        return [p.strip() for p in str(as_path).replace(",", " ").split() if p.strip().isdigit()]

    @staticmethod
    def _prefix_len(prefix):
        m = re.search(r"/(\d+)$", str(prefix))
        return int(m.group(1)) if m else -1

    @staticmethod
    def _bucket_path_len(path_len):
        if path_len <= 0:
            return "unknown"
        if path_len <= 2:
            return "short"
        if path_len <= 5:
            return "medium"
        return "long"

    @staticmethod
    def _map_case_type(case_type):
        t = str(case_type or "").lower()
        if "hijack" in t:
            return "hijack"
        if "leak" in t:
            return "leak"
        if "forg" in t:
            return "forgery"
        if "benign" in t or "normal" in t:
            return "benign"
        return "unknown"

    def _infer_query_profile(self, ctx):
        prefix = str(ctx.get("prefix", "")).strip() if isinstance(ctx, dict) else ""
        as_path = str(ctx.get("as_path", "")).strip() if isinstance(ctx, dict) else ""
        detected = self._normalize_asn(ctx.get("detected_origin")) if isinstance(ctx, dict) else ""
        expected = self._normalize_asn(ctx.get("expected_origin")) if isinstance(ctx, dict) else ""
        path = self._parse_path(as_path)
        origin_mismatch = "1" if detected and expected and detected != expected else "0"

        if origin_mismatch == "1":
            attack_family = "hijack"
        elif len(path) >= 3:
            # origin 正常且路径较长时，优先考虑 leak/forgery 类型案例
            attack_family = "leak_or_forgery"
        else:
            attack_family = "unknown"

        return {
            "prefix_len": self._prefix_len(prefix),
            "path_len_bucket": self._bucket_path_len(len(path)),
            "origin_mismatch": origin_mismatch,
            "attack_family": attack_family,
        }

    def _build_where_filter(self, profile):
        fam = profile.get("attack_family")
        if fam == "hijack":
            return {"attack_family": "hijack"}
        if fam == "leak_or_forgery":
            return {"$or": [{"attack_family": "leak"}, {"attack_family": "forgery"}]}
        return None

    def _context_to_query(self, ctx):
        """将单条 context 转为查询文本"""
        if isinstance(ctx, dict):
            return (
                f"BGP anomaly prefix {ctx.get('prefix', '')} path {ctx.get('as_path', '')} "
                f"origin {ctx.get('detected_origin', '')} expected {ctx.get('expected_origin', '')}"
            )
        return str(ctx)

    def _feature_match_score(self, profile, meta):
        score = 0.0
        meta = self._enrich_meta_features(meta)
        try:
            meta_prefix_len = int(meta.get("prefix_len", -1))
        except (TypeError, ValueError):
            meta_prefix_len = -1
        meta_bucket = str(meta.get("path_len_bucket", "unknown"))
        meta_mismatch = str(meta.get("origin_mismatch", ""))
        meta_family = str(meta.get("attack_family", "unknown"))

        if profile["prefix_len"] != -1 and meta_prefix_len == profile["prefix_len"]:
            score += 0.35
        if meta_mismatch and meta_mismatch == profile["origin_mismatch"]:
            score += 0.25
        if meta_bucket == profile["path_len_bucket"]:
            score += 0.20

        if profile["attack_family"] == "hijack" and meta_family == "hijack":
            score += 0.20
        elif profile["attack_family"] == "leak_or_forgery" and meta_family in ("leak", "forgery"):
            score += 0.20

        return min(score, 1.0)

    def _enrich_meta_features(self, meta):
        """
        兼容旧库：若 metadata 缺少结构化字段，尝试从 full_json 回填。
        """
        if not isinstance(meta, dict):
            return {}
        if (
            "attack_family" in meta
            and "prefix_len" in meta
            and "path_len_bucket" in meta
            and "origin_mismatch" in meta
        ):
            return meta

        full_json = meta.get("full_json")
        if not full_json:
            return meta

        try:
            case = json.loads(full_json)
        except Exception:
            return meta

        evidence = case.get("evidence") or case.get("context") or {}
        prefix = str(evidence.get("prefix", "")).strip()
        as_path = str(evidence.get("as_path", "")).strip()
        detected = self._normalize_asn(evidence.get("detected_origin"))
        expected = self._normalize_asn(evidence.get("expected_origin"))

        enriched = dict(meta)
        enriched.setdefault("attack_family", self._map_case_type(case.get("type", meta.get("type", "Unknown"))))
        enriched.setdefault("prefix_len", self._prefix_len(prefix))
        enriched.setdefault("path_len_bucket", self._bucket_path_len(len(self._parse_path(as_path))))
        enriched.setdefault("origin_mismatch", "1" if detected and expected and detected != expected else "0")
        return enriched

    def _query_once(self, query_text, n_results, where_filter=None):
        kwargs = {"query_texts": [query_text], "n_results": n_results}
        if where_filter:
            kwargs["where"] = where_filter
        return self.collection.query(**kwargs)

    def _retrieve_candidates(self, query_context, recall_k=None):
        query_text = self._context_to_query(query_context)
        profile = self._infer_query_profile(query_context if isinstance(query_context, dict) else {})
        where_filter = self._build_where_filter(profile)
        recall_k = recall_k or self.recall_k

        raw_candidates = {}
        # 第 1 阶段：结构化过滤后的粗召回；若结果为空自动回退全库召回
        for filt in (where_filter, None):
            try:
                res = self._query_once(query_text, recall_k, where_filter=filt)
            except Exception as e:
                logger.debug(f"RAG query 失败 (filter={filt}): {e}")
                continue

            docs = (res.get("documents") or [[]])[0]
            metas = (res.get("metadatas") or [[]])[0]
            dists = (res.get("distances") or [[]])[0]
            ids = (res.get("ids") or [[]])[0]
            for i, doc_id in enumerate(ids):
                if not doc_id:
                    continue
                dist = float(dists[i]) if i < len(dists) else 1.0
                meta = metas[i] if i < len(metas) and isinstance(metas[i], dict) else {}
                doc = docs[i] if i < len(docs) else ""

                vec_score = max(0.0, 1.0 - dist)
                feat_score = self._feature_match_score(profile, meta)
                final_score = 0.70 * vec_score + 0.30 * feat_score

                prev = raw_candidates.get(doc_id)
                item = {
                    "id": doc_id,
                    "doc": doc,
                    "meta": meta,
                    "dist": dist,
                    "score": final_score,
                }
                if (prev is None) or (item["score"] > prev["score"]):
                    raw_candidates[doc_id] = item

            if raw_candidates:
                # 过滤召回有结果就不再跑无过滤召回
                break

        if not raw_candidates:
            return []

        # 第 2 阶段：重排
        items = sorted(raw_candidates.values(), key=lambda x: (-x["score"], x["dist"]))
        return items

    def _dynamic_select_topk(self, items, k):
        if not items:
            return []
        best = items[0]
        # 拒答阈值：最优候选仍过远时，避免注入噪声案例
        if best["dist"] > self.reject_distance and best["score"] < 0.45:
            return []

        if len(items) == 1:
            return items[:1]

        second = items[1]
        # 动态 k：当头部候选明显更强时仅给 1 条，避免稀疏查询引入无关案例
        if best["score"] >= 0.78 and (best["score"] - second["score"]) >= 0.12:
            return items[:1]
        return items[: max(1, min(k, 2))]

    def _format_results(self, items):
        """将重排后案例列表格式化为输出字符串"""
        snippets = []
        for i, item in enumerate(items, 1):
            doc = item.get("doc", "")
            meta = item.get("meta", {})
            dist = float(item.get("dist", 1.0))
            conclusion_display = meta.get("conclusion", "N/A")
            try:
                conc_obj = json.loads(conclusion_display)
                conclusion_display = json.dumps(conc_obj, ensure_ascii=False, indent=2)
            except Exception:
                pass
            snippet = f"""
--- [参考案例 #{i} | 相关性: {1-dist:.2f}] ---
【类型】: {meta.get('type', 'Unknown')}
【场景】: {doc}
【分析逻辑】: {meta.get('analysis', 'N/A')}
【结论】: {conclusion_display}
"""
            snippets.append(snippet)
        return "\n".join(snippets)

    def search_similar_cases(self, query_context, k=2):
        """
        RAG 检索接口（单条）：结构化过滤 + 两阶段重排 + 动态 top-k + 阈值拒答
        """
        items = self._retrieve_candidates(query_context, recall_k=max(self.recall_k, k * 5))
        top_items = self._dynamic_select_topk(items, k)
        if not top_items:
            return "（未找到高置信相似案例；RAG已降权）"
        return self._format_results(top_items)

    @staticmethod
    def _signature_of_update(update):
        prefix = str(update.get("prefix", "")).strip()
        detected = str(update.get("detected_origin", "")).strip()
        expected = str(update.get("expected_origin", "")).strip()
        path = [p for p in str(update.get("as_path", "")).replace(",", " ").split() if p.isdigit()]
        tail = " ".join(path[-2:]) if len(path) >= 2 else (" ".join(path) if path else "")
        return (prefix, detected, expected, tail)

    def search_similar_cases_batch(self, updates_list, k=2):
        """
        批量 RAG 检索（签名聚合版）：
        1) 先按更新签名聚合，抑制重复/噪声 updates
        2) 对每个签名粗召回 + 重排
        3) 按签名频次加权后合并去重，最终取 top-k
        """
        if not updates_list:
            return "（未找到相似历史案例）"
        if len(updates_list) == 1:
            return self.search_similar_cases(updates_list[0], k=k)

        # 签名聚合
        grouped = {}
        for u in updates_list:
            sig = self._signature_of_update(u)
            if sig not in grouped:
                grouped[sig] = {"count": 0, "sample": u}
            grouped[sig]["count"] += 1

        merged = {}
        sig_num = max(1, len(grouped))
        per_sig_recall = max(6, min(self.recall_k, self.recall_k // sig_num + 4))

        for g in grouped.values():
            count = g["count"]
            sample = g["sample"]
            items = self._retrieve_candidates(sample, recall_k=per_sig_recall)
            if not items:
                continue

            weight = 1.0 + 0.15 * math.log1p(count)
            for it in items[: max(3, k * 2)]:
                doc_id = it["id"]
                weighted_score = it["score"] * weight
                prev = merged.get(doc_id)
                candidate = dict(it)
                candidate["score"] = weighted_score
                if (prev is None) or (candidate["score"] > prev["score"]):
                    merged[doc_id] = candidate

        if not merged:
            return "（未找到高置信相似案例；RAG已降权）"

        ranked = sorted(merged.values(), key=lambda x: (-x["score"], x["dist"]))
        top_items = self._dynamic_select_topk(ranked, k)
        if not top_items:
            return "（未找到高置信相似案例；RAG已降权）"
        return self._format_results(top_items)


if __name__ == "__main__":
    # 简单自测
    rag = RAGManager()
    # 这里的路径改成你实际的文件路径，用于自测
    # rag.load_knowledge_base("data/forensics_cases.jsonl")
