import requests
import bz2  # <--- 修改点 1: 换成 bz2
import io
from neo4j import GraphDatabase
import time

# --- 配置 ---
# CAIDA 数据集 (确认这里也是 .bz2 后缀)
CAIDA_URL = "https://publicdata.caida.org/datasets/as-relationships/serial-1/20231201.as-rel.txt.bz2" 
NEO4J_URI = "bolt://localhost:7687"
NEO4J_AUTH = ("neo4j", "whm161122309") 
BATCH_SIZE = 5000

class RealWorldLoader:
    def __init__(self):
        self.driver = GraphDatabase.driver(NEO4J_URI, auth=NEO4J_AUTH)

    def close(self):
        self.driver.close()

    def download_and_parse(self):
        print(f"⬇️ 正在从 CAIDA 下载真实拓扑数据...\n    {CAIDA_URL}")
        response = requests.get(CAIDA_URL, stream=True)
        if response.status_code != 200:
            raise Exception(f"下载失败: HTTP {response.status_code}")
        
        total_rels = 0
        batch_data = []
        
        # <--- 修改点 2: 使用 bz2.open 解压流
        with bz2.open(io.BytesIO(response.content), 'rt') as f:
            for line in f:
                if line.startswith('#'):
                    continue
                
                parts = line.strip().split('|')
                if len(parts) < 3:
                    continue

                asn1, asn2, rel_type = parts[0], parts[1], parts[2]
                
                batch_data.append({
                    "asn1": asn1, 
                    "asn2": asn2, 
                    "type": rel_type
                })

                if len(batch_data) >= BATCH_SIZE:
                    self._batch_insert(batch_data)
                    total_rels += len(batch_data)
                    print(f"\r🚀 已导入关系数: {total_rels}...", end="")
                    batch_data = []

            if batch_data:
                self._batch_insert(batch_data)
                total_rels += len(batch_data)

        print(f"\n\n✅ 导入完成！全球 AS 拓扑图构建完毕。总关系数: {total_rels}")

    def _batch_insert(self, data):
        query = """
        UNWIND $batch AS row
        MERGE (a:AS {asn: row.asn1})
        MERGE (b:AS {asn: row.asn2})
        
        FOREACH (_ IN CASE WHEN row.type = '-1' THEN [1] ELSE [] END |
            MERGE (b)-[:CUSTOMER_OF]->(a)
            MERGE (a)-[:PROVIDER_TO]->(b)
        )
        
        FOREACH (_ IN CASE WHEN row.type = '0' THEN [1] ELSE [] END |
            MERGE (a)-[:PEER_WITH]-(b)
        )
        """
        try:
            with self.driver.session() as session:
                session.run(query, batch=data)
        except Exception as e:
            print(f"\n❌ 批次写入失败: {e}")

    def create_indexes(self):
        print("⚡ 正在为真实数据创建索引...")
        with self.driver.session() as session:
            session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (a:AS) REQUIRE a.asn IS UNIQUE")
        print("✅ 索引创建完毕。")

if __name__ == "__main__":
    loader = RealWorldLoader()
    try:
        loader.create_indexes()
        loader.download_and_parse()
    finally:
        loader.close()