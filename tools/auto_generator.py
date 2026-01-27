import asyncio
import json
import random
import os
import re
from datetime import datetime, timedelta
from openai import AsyncOpenAI
from tqdm.asyncio import tqdm

# --- 1. 配置 ---
API_KEY = "sk-9944c48494394db6b8bc31b40f8a710f" # 你的 DeepSeek Key
BASE_URL = "https://api.deepseek.com"
OUTPUT_FILE = "data/synthetic_cases_hijack.json"
CONCURRENCY = 10  # 并发数 (DeepSeek 官方通常支持较好，可设 10-20)

# --- 2. 真实世界种子数据 (用于抑制幻觉) ---
# 我们提供真实的 ASN 和 IP，让 AI 基于这些事实编故事
REAL_ENTITIES = [
    {"asn": "15169", "name": "Google", "prefixes": ["8.8.8.0/24", "8.8.4.0/24", "35.190.0.0/16"]},
    {"asn": "13414", "name": "Twitter", "prefixes": ["104.244.42.0/24", "199.16.156.0/22"]},
    {"asn": "16509", "name": "Amazon", "prefixes": ["54.239.0.0/16", "52.95.0.0/16"]},
    {"asn": "3356", "name": "Level3 (CenturyLink)", "prefixes": ["4.0.0.0/8"], "is_tier1": True},
    {"asn": "174", "name": "Cogent", "prefixes": ["38.0.0.0/8"], "is_tier1": True},
    {"asn": "12389", "name": "Rostelecom (Russia)", "prefixes": ["188.128.0.0/16"], "is_risky": True},
    {"asn": "4134", "name": "China Telecom", "prefixes": ["202.96.0.0/12"]},
    {"asn": "9009", "name": "M247 Europe", "prefixes": ["45.74.40.0/24"], "is_risky": True},
    {"asn": "17557", "name": "Pakistan Telecom", "prefixes": ["111.119.160.0/20"], "is_risky": True},
    {"asn": "209", "name": "Lumen", "prefixes": ["206.196.160.0/19"], "is_tier1": True}
]

# --- 3. Prompt 模板 (严格约束格式) ---
SYSTEM_PROMPT = """
你是一个 BGP 数据生成引擎。你的任务是根据提供的 ASN 和 IP 信息，生成高质量的 BGP 异常案例数据。
数据将用于 RAG 知识库，因此【Analysis】部分必须包含严谨的逻辑推理（引用 RPKI、商业关系、拓扑距离等概念）。

**绝对规则：**
1. 输出必须是纯 JSON 格式，不要包含 Markdown 标记（如 ```json）。
2. 不要发明不存在的 ASN，严格使用用户提供的 ASN 和 IP。
3. "scenario_desc" 必须像真实的日志描述。
4. "id" 字段保持为空，由代码填充。
"""

class DataGenerator:
    def __init__(self):
        self.client = AsyncOpenAI(api_key=API_KEY, base_url=BASE_URL)
        self.sem = asyncio.Semaphore(CONCURRENCY)

    def _clean_json(self, text):
        """清洗 AI 可能输出的 Markdown 标记"""
        text = re.sub(r'^```json\s*', '', text)
        text = re.sub(r'\s*```$', '', text)
        return text.strip()

    async def generate_case(self, case_type, template_data):
        """
        生成单个案例
        case_type: 'HIJACK' | 'AMBIGUOUS'
        """
        victim = template_data['victim']
        attacker = template_data['attacker']
        prefix = random.choice(victim['prefixes'])
        
        # 构造差异化的 Prompt
        if case_type == "HIJACK":
            user_prompt = f"""
            生成一个【确定的前缀劫持】案例。
            - 受害者: {victim['name']} (AS{victim['asn']})
            - 攻击者: {attacker['name']} (AS{attacker['asn']})
            - 被劫持前缀: {prefix}
            - 场景: 攻击者非法宣告了该前缀，且 RPKI 验证失败 (Invalid)。
            - 要求: 在 analysis 中强调 Origin ASN 不匹配，且攻击者与受害者地理/商业关系不合理。
            """
        else: # AMBIGUOUS (误判/路由泄露/配置错误)
            scenario_subtypes = [
                "Route Leak (违反 Valley-Free 原则)", 
                "MOAS (多源宣告，可能是合法的备用线路)", 
                "Private ASN Leak (配置错误)"
            ]
            subtype = random.choice(scenario_subtypes)
            user_prompt = f"""
            生成一个【容易误判的复杂情况】案例。类型: {subtype}
            - 涉及 AS: {victim['name']} (AS{victim['asn']}) 和 {attacker['name']} (AS{attacker['asn']})
            - 前缀: {prefix}
            - 场景: 看起来像劫持，但实际上可能是配置错误、合法的 Anycast 或者路由泄露。
            - 要求: analysis 需要通过推理（如“虽然 Origin 变了，但 WHOIS 备注了合作关系”或“这是典型的 Tier-1 泄露模式”）来解释为什么这可能不是恶意攻击，或者很难定性。
            """

        prompt = f"{user_prompt}\n\n请返回如下 JSON 结构:\n{{\n  \"type\": \"...\",\n  \"scenario_desc\": \"...\",\n  \"analysis\": \"...\",\n  \"conclusion\": \"...\"\n}}"

        async with self.sem: # 并发控制
            try:
                response = await self.client.chat.completions.create(
                    model="deepseek-chat",
                    messages=[
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": prompt}
                    ],
                    temperature=0.7 # 稍微有些创造性，但不要太发散
                )
                content = self._clean_json(response.choices[0].message.content)
                data = json.loads(content)
                
                # 补充元数据
                data['id'] = f"auto_{case_type.lower()}_{random.randint(10000, 99999)}"
                return data
            except Exception as e:
                # print(f"生成失败: {e}")
                return None

    async def run(self):
        tasks = []
        
        print(f"🚀 开始生成数据 (并发数: {CONCURRENCY})...")
        
        # 1. 生成 300 条经典劫持
        print(">> 正在编排 300 条劫持任务...")
        for _ in range(300):
            # 随机挑选受害者和攻击者 (排除自己攻击自己)
            v = random.choice(REAL_ENTITIES)
            a = random.choice([x for x in REAL_ENTITIES if x['asn'] != v['asn']])
            tasks.append(self.generate_case("HIJACK", {'victim': v, 'attacker': a}))

        # 2. 生成 200 条容易误判的情况
        print(">> 正在编排 200 条误判/复杂任务...")
        for _ in range(200):
            v = random.choice(REAL_ENTITIES)
            a = random.choice([x for x in REAL_ENTITIES if x['asn'] != v['asn']])
            tasks.append(self.generate_case("AMBIGUOUS", {'victim': v, 'attacker': a}))

        # 3. 执行并发
        results = []
        # 使用 tqdm 显示进度条
        for f in tqdm(asyncio.as_completed(tasks), total=len(tasks), desc="AI 生成中"):
            res = await f
            if res:
                results.append(res)
        
        # 4. 保存
        print(f"\n✅ 生成完成！成功: {len(results)}/{len(tasks)}")
        
        # 如果文件已存在，读取并追加；否则新建
        final_data = results
        if os.path.exists(OUTPUT_FILE):
            try:
                with open(OUTPUT_FILE, 'r', encoding='utf-8') as f:
                    old_data = json.load(f)
                    final_data = old_data + results
            except:
                pass # 文件损坏或格式不对则覆盖

        os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
        with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
            json.dump(final_data, f, indent=4, ensure_ascii=False)
        
        print(f"💾 数据已保存至: {OUTPUT_FILE}")

if __name__ == "__main__":
    generator = DataGenerator()
    asyncio.run(generator.run())