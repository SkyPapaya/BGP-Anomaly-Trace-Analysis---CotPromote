import json
import os
import shutil
from rag_manager import RAGManager

# 1. 绝对正确的种子数据
CORRECT_DATA = [
    {
        "id": "case_hijack_001",
        "type": "Malicious Hijack",
        "scenario_desc": "Prefix: 104.244.42.0/24 (Twitter), Path: 174 12389, Origin: AS12389 (Russia).",
        "analysis": "Origin AS (AS12389) 与 RPKI 记录的合法拥有者 (AS13414) 不符。且 AS12389 位于俄罗斯，AS13414 位于美国，存在严重的地理位置冲突。",
        "conclusion": "判定为恶意劫持。攻击者利用非法 Origin 劫持流量。"
    },
    {
        "id": "case_leak_001",
        "type": "Route Leak",
        "scenario_desc": "Prefix: 216.58.223.0/24 (Google), Path: 174 37282 15169, Origin: AS15169 (US).",
        "analysis": "Origin AS (AS15169) 是合法的。但是 AS路径中包含了 Tier-1 -> 小型ISP -> Tier-1 的结构，违反了 Valley-Free 原则。",
        "conclusion": "判定为路由泄露。中间 AS 配置错误导致流量穿透。"
    },
    {
        "id": "case_config_001",
        "type": "Private ASN Leak",
        "scenario_desc": "Prefix: 1.2.3.0/24, Path: 3356 64512, Origin: AS64512.",
        "analysis": "AS64512 属于私有 ASN 范围 (64512-65535)。私有 ASN 不应出现在全球公网路由表中。",
        "conclusion": "判定为配置错误。私有 ASN 意外泄露到公网。"
    }
]

def run_fix():
    # 写入 JSON
    json_path = "data/knowledge_base.json"
    os.makedirs(os.path.dirname(json_path), exist_ok=True)
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(CORRECT_DATA, f, indent=4, ensure_ascii=False)
    print("✅ JSON 数据源已准备。")

    # 删除旧库 (为了保险清空一次)
    db_path = "./rag_db"
    if os.path.exists(db_path):
        shutil.rmtree(db_path)
        print(f"✅ 清空数据库目录: {db_path}")

    # 重建
    print("🔄 正在初始化新数据库...")
    rag = RAGManager(db_path=db_path) # 使用新路径
    rag.load_knowledge_base(json_path)
    
    # 验证
    print("\n🔎 最终验证 (Expect: Malicious Hijack)...")
    res = rag.search_similar_cases({
        "prefix": "104.244.42.0/24", 
        "as_path": "174 12389", 
        "detected_origin": "12389"
    })
    print(res)

if __name__ == "__main__":
    run_fix()