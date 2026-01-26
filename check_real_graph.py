from neo4j import GraphDatabase

# 验证真实数据的威力
driver = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "whm161122309"))

def check_twitter_topology():
    with driver.session() as session:
        # 查询 AS13414 (Twitter) 的所有 Provider
        query = """
        MATCH (twitter:AS {asn: '13414'})-[:CUSTOMER_OF]->(provider)
        RETURN provider.asn
        """
        result = session.run(query)
        providers = [record["provider.asn"] for record in result]
        
        print(f"🌍 [真实拓扑验证] Twitter (AS13414) 的全球供应商: {providers}")
        
        # 验证 AS174 (Cogent) 是否在其中
        if '174' in providers:
            print("✅ 验证通过：Cogent (AS174) 确实是 Twitter 的上游。")
        else:
            print("⚠️ 数据可能有变动，未找到 Cogent。")

check_twitter_topology()