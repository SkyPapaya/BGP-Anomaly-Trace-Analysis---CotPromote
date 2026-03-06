import asyncio
import json
import random
import os
import sys
from openai import AsyncOpenAI
from tqdm.asyncio import tqdm
import aiofiles

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tools.config_loader import get_entities
from tools.project_paths import FORENSICS_CASES_FILE

# --- 配置 ---
API_KEY = os.getenv("DEEPSEEK_API_KEY") or os.getenv("OPENAI_API_KEY", "")
BASE_URL = "https://api.deepseek.com"
OUTPUT_FILE = str(FORENSICS_CASES_FILE)
CONCURRENCY = 10

SYSTEM_PROMPT = """
你是一个 BGP 安全取证专家的数据生成器。
任务：构造一份 BGP 劫持或泄露的溯源分析档案。

**必须包含的核心逻辑 (模仿 Google May 2005 Outage 报告):**
1. **正常状态 (Baseline)**: 说明该前缀合法的 Origin 是谁 (例如 Google AS15169)。
2. **异常 Update**: 提供一条具体的异常 AS_PATH (例如 "701 174")。
3. **溯源推理**: 
   - 观察到 AS_PATH 的最右侧 (Origin) 变成了 AS174。
   - 确认 AS174 不是合法 Owner，且没有代播授权。
   - 结论：AS174 是攻击者 (Attacker)。

**输出格式 (JSON):**
{
    "id": "auto_forensics_xxxx",
    "type": "Origin Hijack" 或 "Route Leak",
    "scenario_desc": "一段详细的案情描述，包含时间点、受害者、以及异常 Update 消息的内容...",
    "evidence": {
        "prefix": "...", 
        "expected_origin": "...",
        "suspicious_path": "..." 
    },
    "analysis_logic": "详细的思维链：如何通过路径末端锁定攻击者...",
    "conclusion": {
        "attacker_as": "...",
        "confidence": "High"
    }
}
"""

class ForensicsGenerator:
    def __init__(self):
        if not API_KEY:
            raise ValueError("缺少 API Key，请设置环境变量 DEEPSEEK_API_KEY 或 OPENAI_API_KEY。")
        self.client = AsyncOpenAI(api_key=API_KEY, base_url=BASE_URL)
        self.sem = asyncio.Semaphore(CONCURRENCY)

    async def generate_case(self):
        entities = get_entities()
        legacy = entities.get("LEGACY", [])
        victims = [x for x in legacy if not x.get("is_attacker_candidate")]
        if not victims:
            victims = entities.get("VICTIMS", [])
        all_entities = legacy if legacy else (entities["VICTIMS"] + entities["ATTACKERS"])
        victim = random.choice(victims) if victims else {"asn": "15169", "name": "Google", "prefixes": ["64.233.161.0/24"]}
        candidates = [x for x in all_entities if x.get("asn") != victim.get("asn")]
        attacker = random.choice(candidates) if candidates else random.choice(all_entities) if all_entities else {"asn": "12389", "name": "Rostelecom"}
        prefix = victim.get("prefixes", [victim.get("prefix", "1.2.3.0/24")])[0]
        
        # 构造 path (让 attacker 出现在末尾，模拟 Origin Hijack)
        # 例如: Transit -> Attacker
        transit = "3356" if attacker['asn'] != "3356" else "174"
        suspicious_path = f"{transit} {attacker['asn']}"

        prompt = f"""
        生成一个溯源案例：
        - 受害者: {victim['name']} (AS{victim['asn']})
        - 攻击者: {attacker['name']} (AS{attacker['asn']})
        - 异常路径: "{suspicious_path}" (注意：攻击者把自己放在了 Origin 位置)
        - 前缀: {prefix}
        
        请模仿 Google 2005 报告的语气，描述这次 Origin Hijack 事件。
        """

        async with self.sem:
            try:
                response = await self.client.chat.completions.create(
                    model="deepseek-chat",
                    messages=[
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": prompt}
                    ],
                    temperature=0.7,
                    response_format={'type': 'json_object'}
                )
                return json.loads(response.choices[0].message.content)
            except Exception:
                return None

    async def run(self, count=50):
        tasks = [self.generate_case() for _ in range(count)]
        
        print(f"🚀 开始生成 {count} 条溯源案例...")
        os.makedirs("data", exist_ok=True)
        
        valid_count = 0
        async with aiofiles.open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
            for future in tqdm(asyncio.as_completed(tasks), total=count):
                res = await future
                if res:
                    # 补充 ID
                    res['id'] = f"forensics_{random.randint(100000,999999)}"
                    await f.write(json.dumps(res, ensure_ascii=False) + "\n")
                    valid_count += 1
        
        print(f"✅ 生成完成！存入: {OUTPUT_FILE}")

if __name__ == "__main__":
    gen = ForensicsGenerator()
    asyncio.run(gen.run(count=200)) # 生成 200 条高质量案例
